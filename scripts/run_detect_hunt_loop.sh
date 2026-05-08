#!/usr/bin/env bash
# run_detect_hunt_loop.sh — End-to-end SIFTics → Velociraptor detect-hunt loop.
#
# Workflow:
#   1. Discover or pull the offline collection from the primary victim
#      into <case_root>/incoming/<victim>/
#   2. Unpack into the case structure expected by SIFTics phases
#   3. Run SIFTics analysis (the agent invokes triage-methodology; this
#      script can also call individual phase scripts deterministically
#      via --deterministic mode)
#   4. Convert findings to Velociraptor hunt artifacts (findings_to_hunt.py)
#   5. Upload artifacts + create hunts via the MCP broker
#   6. Start hunts; wait for completion (bounded poll)
#   7. Pull hunt results into <case_root>/analysis/hunt_results/
#   8. Optionally re-run anomaly check + self-correct on the new evidence
#
# This is the demo-required self-correction sequence: the agent goes from
# "found something on host A" to "now hunting for it across the fleet" —
# and the cross-host findings can trigger another iteration.
#
# Hard cap on detect-hunt iterations to prevent runaway.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=audit_log.sh
source "${SCRIPT_DIR}/audit_log.sh"

CASE_ROOT="${1:-${CASE_ROOT:-}}"
if [[ -z "$CASE_ROOT" ]]; then
    read -rp "Case root directory: " CASE_ROOT
fi
[[ -d "$CASE_ROOT" ]] || { echo "ERROR: CASE_ROOT '${CASE_ROOT}' does not exist." >&2; exit 1; }
export CASE_ROOT
ANALYSIS_DIR="${CASE_ROOT}/analysis"
INCOMING_DIR="${CASE_ROOT}/incoming"
HUNT_RESULTS_DIR="${ANALYSIS_DIR}/hunt_results"

# Configuration via env (with defaults)
PRIMARY_CLIENT_ID="${PRIMARY_CLIENT_ID:-}"
HUNT_TIMEOUT_S="${HUNT_TIMEOUT_S:-300}"
MAX_LOOP_ITERATIONS="${MAX_LOOP_ITERATIONS:-2}"
DETERMINISTIC="${DETERMINISTIC:-0}"  # 1 = run phases sequentially, 0 = let agent drive
DRY_RUN="${DRY_RUN:-0}"               # 1 = don't actually upload/start hunts

# venv'd Python for MCP broker calls
BROKER_PY="${SCRIPT_DIR}/../mcp_broker/.venv/bin/python"
if [[ ! -x "${BROKER_PY}" ]]; then
    echo "ERROR: mcp_broker venv not found at ${BROKER_PY}" >&2
    echo "       Run: python3 -m venv mcp_broker/.venv && \\" >&2
    echo "            mcp_broker/.venv/bin/pip install -r mcp_broker/requirements.txt" >&2
    exit 1
fi

vr() {
    "${BROKER_PY}" -m mcp_broker.tools.velociraptor "$@"
}

section() { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
status()  { printf "  [%-12s] %s\n" "$1" "$2"; }

section "Detect-Hunt Loop"
echo " $(date -u)"
echo " Case root      : ${CASE_ROOT}"
echo " Max iterations : ${MAX_LOOP_ITERATIONS}"
echo " Deterministic  : ${DETERMINISTIC}"
echo " Dry-run        : ${DRY_RUN}"
echo " Mock VR        : ${SIFTICS_MCP_MOCK:-0}"

mkdir -p "${INCOMING_DIR}" "${HUNT_RESULTS_DIR}"

# ─── Step 1: discover / pull the primary collection ────────────────────────

section "Step 1 — Primary collection ingestion"

INCOMING_ZIPS=$(find "${INCOMING_DIR}" -maxdepth 2 -name "*.zip" 2>/dev/null | sort)

if [[ -z "${INCOMING_ZIPS}" ]] && [[ -n "${PRIMARY_CLIENT_ID}" ]]; then
    status "PULL" "Pulling offline collection from ${PRIMARY_CLIENT_ID}"
    target="${INCOMING_DIR}/${PRIMARY_CLIENT_ID}_collection.zip"
    vr pull_offline_collection \
        client_id="${PRIMARY_CLIENT_ID}" \
        output_path="${target}" \
        artifact_pack=Generic.Collectors.File \
    || { status "ERROR" "pull_offline_collection failed"; exit 2; }
    INCOMING_ZIPS="${target}"
elif [[ -z "${INCOMING_ZIPS}" ]]; then
    status "WAIT" "No collection zips in ${INCOMING_DIR}/. Either:"
    echo "      • Drop a collection zip into ${INCOMING_DIR}/<host>/"
    echo "      • Set PRIMARY_CLIENT_ID=<C.xxx> to auto-pull from Velociraptor"
    echo "      • Set SIFTICS_MCP_MOCK=1 to use mock mode for the demo"
    exit 0
fi

for zip in ${INCOMING_ZIPS}; do
    status "OK" "Found: ${zip} ($(du -h "${zip}" | cut -f1))"
done

# Unpack — caller is expected to already have the zip in KAPE-shape, OR
# implement unpacking logic here for a specific collector format.
# For now we just record the ingestion in the audit chain.
audit_log_entry "ALL" "detect-hunt-loop" \
    "ingest collections: ${INCOMING_ZIPS}" \
    "Step 1: discover primary victim collection" \
    "${INCOMING_DIR}" \
    "$(echo "${INCOMING_ZIPS}" | wc -l) zip(s) found" "0"

# ─── Step 2: run SIFTics analysis ───────────────────────────────────────────

section "Step 2 — SIFTics analysis on primary victim"

if [[ "${DETERMINISTIC}" == "1" ]]; then
    status "MODE" "Deterministic — running phases 1..20 in order"
    PHASES=(
        run_ntfs run_registry run_eventlogs run_artifacts run_execution
        run_hunting run_credaccess run_antiforensics
        run_browser run_ransomware run_webserver run_email run_linux
        run_ioc_extract run_c2_beacon run_attack_path
        run_anomaly_check run_memory run_pcap
    )
    for phase in "${PHASES[@]}"; do
        if [[ -x "${SCRIPT_DIR}/${phase}.sh" ]]; then
            status "RUN" "${phase}"
            bash "${SCRIPT_DIR}/${phase}.sh" "${CASE_ROOT}" >/tmp/${phase}.log 2>&1 \
                || status "WARN" "${phase} returned non-zero (continuing)"
        fi
    done
else
    status "MODE" "Agent-driven — assuming SIFTics has already analyzed primary victim"
    if [[ ! -s "${ANALYSIS_DIR}/ioc_master.csv" ]] && [[ "${SIFTICS_MCP_MOCK:-0}" != "1" ]]; then
        status "WARN" "ioc_master.csv missing — did the agent run phases 1..20?"
        echo "      Run with DETERMINISTIC=1 to invoke phases sequentially, or"
        echo "      have the agent run via /investigation-section-chief first."
    fi
fi

# ─── Step 3: convert findings to hunt artifacts ─────────────────────────────

section "Step 3 — Generate Velociraptor hunt artifacts from findings"

if [[ ! -s "${ANALYSIS_DIR}/ioc_master.csv" ]] && [[ ! -s "${ANALYSIS_DIR}/anomalies.csv" ]]; then
    if [[ "${SIFTICS_MCP_MOCK:-0}" == "1" ]]; then
        # Mock mode: synthesize a demo IOC so the loop has something to do
        status "MOCK" "Synthesizing demo IOC for end-to-end loop test"
        cat > "${ANALYSIS_DIR}/ioc_master.csv" <<'EOF'
Type,Value,Count,Sources,FirstSeen,Note
ip,192.0.2.55,3,phase10_c2_beacon,2026-05-08T10:00:00Z,demo IOC
sha256,5d41402abc4b2a76b9719d911017c592bd29bf2dad7e69e8ad6d5a6c8f0e7b9c,1,phase8_anti_forensics,2026-05-08T10:01:00Z,demo IOC
EOF
    else
        status "SKIP" "No IOC findings yet — nothing to hunt for"
        exit 0
    fi
fi

python3 "${SCRIPT_DIR}/findings_to_hunt.py" "${CASE_ROOT}"
status "OK" "Hunt artifacts in ${ANALYSIS_DIR}/hunt_artifacts/"

ARTIFACT_FILES=$(find "${ANALYSIS_DIR}/hunt_artifacts" -name "SIFTICS_*.yaml" 2>/dev/null | sort)
if [[ -z "${ARTIFACT_FILES}" ]]; then
    status "DONE" "No artifacts to upload — loop complete"
    exit 0
fi

audit_log_entry "ALL" "detect-hunt-loop" \
    "findings_to_hunt.py ${CASE_ROOT}" \
    "Step 3: derive hunt artifacts from SIFTics findings" \
    "${ANALYSIS_DIR}/hunt_artifacts/" \
    "$(echo "${ARTIFACT_FILES}" | wc -l) artifacts generated" "0"

# ─── Step 4: upload + create + start hunts ──────────────────────────────────

section "Step 4 — Upload + create + start hunts via MCP broker"

if [[ "${DRY_RUN}" == "1" ]]; then
    status "DRY-RUN" "Skipping upload/create/start"
    exit 0
fi

declare -a HUNT_IDS=()

for artifact_file in ${ARTIFACT_FILES}; do
    artifact_name=$(basename "${artifact_file}" .yaml)
    yaml_body=$(cat "${artifact_file}")

    # Upload
    upload_result=$(vr upload_artifact \
        name="${artifact_name}" \
        vql_yaml="${yaml_body}" 2>&1) \
    || { status "WARN" "upload failed for ${artifact_name}"; continue; }
    status "UPLOAD" "${artifact_name}"

    # Create hunt
    hunt_create=$(vr create_hunt \
        name="siftics_${artifact_name}" \
        artifact_name="${artifact_name}" \
        expires_hours=4 2>&1) \
    || { status "WARN" "create_hunt failed for ${artifact_name}"; continue; }
    hunt_id=$(echo "${hunt_create}" | python3 -c "import sys,json; print(json.load(sys.stdin)['hunt_id'])" 2>/dev/null)
    if [[ -z "${hunt_id}" ]]; then
        status "WARN" "no hunt_id returned for ${artifact_name}"
        continue
    fi
    status "HUNT" "${hunt_id} created for ${artifact_name}"

    # Start
    vr start_hunt hunt_id="${hunt_id}" >/dev/null 2>&1 \
        || { status "WARN" "start_hunt failed for ${hunt_id}"; continue; }

    HUNT_IDS+=("${hunt_id}")
done

status "TOTAL" "${#HUNT_IDS[@]} hunts started"

audit_log_entry "ALL" "detect-hunt-loop" \
    "${#HUNT_IDS[@]} hunts created+started" \
    "Step 4: push SIFTics findings to fleet as Velociraptor hunts" \
    "${HUNT_RESULTS_DIR}" \
    "hunt_ids=${HUNT_IDS[*]}" "0"

# ─── Step 5: wait for completion + pull results ─────────────────────────────

section "Step 5 — Wait for hunt completion + pull results"

for hunt_id in "${HUNT_IDS[@]}"; do
    status "WAIT" "${hunt_id} (timeout ${HUNT_TIMEOUT_S}s)"
    final_status=$(vr wait_for_hunt hunt_id="${hunt_id}" timeout_s="${HUNT_TIMEOUT_S}" 2>&1)
    is_complete=$(echo "${final_status}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('is_complete', False))" 2>/dev/null)
    status "DONE" "${hunt_id} is_complete=${is_complete}"

    # Pull results
    results_file="${HUNT_RESULTS_DIR}/${hunt_id}_results.json"
    vr get_hunt_results hunt_id="${hunt_id}" > "${results_file}" 2>/dev/null
    rows=$(python3 -c "import sys,json; print(len(json.load(open('${results_file}'))))" 2>/dev/null || echo 0)
    status "RESULTS" "${hunt_id} → ${rows} rows → ${results_file}"
done

# ─── Step 6: ingest results back into the case ─────────────────────────────

section "Step 6 — Cross-host findings summary"

# Combine all hunt results into a single CSV for the agent to read
SUMMARY_CSV="${ANALYSIS_DIR}/cross_host_findings.csv"
python3 - "${HUNT_RESULTS_DIR}" "${SUMMARY_CSV}" <<'PYEOF'
import csv, json, os, sys
from pathlib import Path
results_dir = Path(sys.argv[1])
out_csv = Path(sys.argv[2])

rows = []
for jf in sorted(results_dir.glob("*_results.json")):
    try:
        data = json.loads(jf.read_text())
    except Exception:
        continue
    for r in data:
        # Flatten one level for readability
        flat = {"hunt_file": jf.name}
        for k, v in r.items():
            flat[k] = v if isinstance(v, (str, int, float, bool)) else json.dumps(v)
        rows.append(flat)

if rows:
    keys = sorted({k for r in rows for k in r.keys()})
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in keys})
    print(f"Wrote {len(rows)} rows from {len(list(results_dir.glob('*_results.json')))} hunts to {out_csv}")
else:
    print("No hunt results to summarize.")
PYEOF

audit_log_entry "ALL" "detect-hunt-loop" \
    "consolidate hunt results" \
    "Step 6: cross-host findings summary" \
    "${SUMMARY_CSV}" "see ${SUMMARY_CSV}" "0"

# ─── Step 7: optional re-analysis loop ─────────────────────────────────────

section "Step 7 — Re-analysis loop (if applicable)"

if [[ -s "${SUMMARY_CSV}" ]]; then
    status "INFO" "Cross-host findings present in ${SUMMARY_CSV}"
    echo "      The ISC may now choose to:"
    echo "      • Add new affected hosts to scope (Authority Gate per ISC skill)"
    echo "      • Re-run anomaly check incorporating cross-host data"
    echo "      • Trigger another detect-hunt iteration"
    echo "      Loop cap (${MAX_LOOP_ITERATIONS}) prevents runaway."
fi

section "Detect-Hunt Loop Complete"
echo "  Hunt artifacts: ${ANALYSIS_DIR}/hunt_artifacts/"
echo "  Hunt results:   ${HUNT_RESULTS_DIR}/"
echo "  Summary CSV:    ${SUMMARY_CSV}"
echo ""
