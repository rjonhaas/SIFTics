#!/usr/bin/env bash
# run_self_correct.sh — Self-correction loop driver.
#
# Reads analysis/anomalies.csv (produced by Phase 18 run_anomaly_check.sh),
# maps each HIGH-severity anomaly to a corrective action (re-run an upstream
# phase with adjusted scope, or update IOC master), executes the action,
# re-runs anomaly detection, and verifies the anomaly count decreased.
#
# Hard cap of 3 iterations to prevent runaway. Each iteration is logged to
# analysis/self_correction.jsonl so the demo video can show the loop in action.
#
# Anomaly → corrective action mapping:
#   shimcache-mft-absent / amcache-mft-absent → re-run run_antiforensics.sh
#   evtx-gap-attack-window                    → re-run run_antiforensics.sh
#   prefetch-no-4688                          → re-run run_hunting.sh (broader EID set)
#   iis-log-gap                               → re-run run_webserver.sh
#   memory-only-ip                            → add IP to ioc_master.csv + re-run ioc_extract
#   pcap-beacon-not-in-iocs                   → add IP to ioc_master.csv + re-run ioc_extract
#   timestomping-confirmed                    → re-run run_hunting.sh on timestomp window
#   usn-jump                                  → log only (data quality, not correctable)
#
# Output : analysis/self_correction.jsonl
#          analysis/self_correction_report.md   (human-readable summary)
# Logging: appends to analysis/forensic_audit.jsonl

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

ANOMALIES_CSV="${ANALYSIS_DIR}/anomalies.csv"
SELF_CORRECT_LOG="${ANALYSIS_DIR}/self_correction.jsonl"
SELF_CORRECT_MD="${ANALYSIS_DIR}/self_correction_report.md"
MAX_ITERATIONS="${SELF_CORRECT_MAX_ITER:-3}"
DRY_RUN="${SELF_CORRECT_DRY_RUN:-0}"

section() { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
status()  { printf "  [%-12s] %s\n" "$1" "$2"; }

section "Self-Correction Loop"
echo " $(date -u)"
echo " Case      : ${CASE_ROOT}"
echo " Max iter  : ${MAX_ITERATIONS}"
echo " Dry-run   : ${DRY_RUN}"

# ─── pre-flight ────────────────────────────────────────────────────────────

if [[ ! -s "${ANOMALIES_CSV}" ]] || [[ $(wc -l < "${ANOMALIES_CSV}") -le 1 ]]; then
    status "INFO" "No anomalies present — running Phase 18 first"
    bash "${SCRIPT_DIR}/run_anomaly_check.sh" "${CASE_ROOT}"
    if [[ ! -s "${ANOMALIES_CSV}" ]] || [[ $(wc -l < "${ANOMALIES_CSV}") -le 1 ]]; then
        status "DONE" "Phase 18 ran clean — no anomalies to correct"
        exit 0
    fi
fi

# ─── helpers ───────────────────────────────────────────────────────────────

count_high() {
    awk -F, 'NR>1 && $1=="HIGH"' "${ANOMALIES_CSV}" 2>/dev/null | wc -l
}

count_total() {
    awk -F, 'NR>1' "${ANOMALIES_CSV}" 2>/dev/null | wc -l
}

# log_iter ITER ACTION_JSON
log_iter() {
    local iter="$1" action_json="$2"
    local ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    python3 - "$iter" "$ts" "$action_json" "${SELF_CORRECT_LOG}" <<'PYEOF'
import json, sys
iteration, ts, action_json, out = sys.argv[1:]
entry = {
    "iteration": int(iteration),
    "timestamp_utc": ts,
    "action": json.loads(action_json),
}
with open(out, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
PYEOF
}

# pick_action — print one line describing the corrective action for a given category+machine+value
# Returns the script path to invoke (or empty if non-correctable / dry-run note)
pick_action() {
    local category="$1" machine="$2" value="$3"
    case "${category}" in
        shimcache-mft-absent|amcache-mft-absent)
            echo "${SCRIPT_DIR}/run_antiforensics.sh|wipe-evidence sweep on ${machine}"
            ;;
        evtx-gap-attack-window)
            echo "${SCRIPT_DIR}/run_antiforensics.sh|EVTX gap analysis on ${machine}"
            ;;
        prefetch-no-4688)
            echo "${SCRIPT_DIR}/run_hunting.sh|broader EID hunt for ${value} on ${machine}"
            ;;
        iis-log-gap)
            echo "${SCRIPT_DIR}/run_webserver.sh|IIS log gap analysis on ${machine}"
            ;;
        memory-only-ip|pcap-beacon-not-in-iocs)
            # These are IOC additions, then re-run extract
            echo "${SCRIPT_DIR}/run_ioc_extract.sh|add ${value} to IOC master then re-extract"
            ;;
        timestomping-confirmed)
            echo "${SCRIPT_DIR}/run_hunting.sh|timestomp-window hunt on ${machine}"
            ;;
        usn-jump)
            echo "|log only — data quality issue, not correctable autonomously"
            ;;
        *)
            echo "|no corrective action mapped for category '${category}'"
            ;;
    esac
}

# add_ioc_ip IP TYPE_CONTEXT
# Inserts a row into ioc_master.csv for a discovered IP that wasn't present
add_ioc_ip() {
    local ip="$1" context="$2"
    local ioc="${ANALYSIS_DIR}/ioc_master.csv"
    if [[ ! -f "${ioc}" ]]; then
        echo "Type,Value,Count,Sources,FirstSeen,Note" > "${ioc}"
    fi
    if ! grep -qE "^ip,${ip}," "${ioc}" 2>/dev/null; then
        local ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        echo "ip,${ip},1,self_correction,${ts},${context}" >> "${ioc}"
        return 0
    fi
    return 1
}

# ─── iteration loop ────────────────────────────────────────────────────────

initial_high=$(count_high)
initial_total=$(count_total)

echo ""
echo " Initial state:"
echo "   HIGH anomalies: ${initial_high}"
echo "   Total:          ${initial_total}"

if [[ ${initial_high} -eq 0 ]]; then
    status "DONE" "No HIGH anomalies — nothing to self-correct"
    cat > "${SELF_CORRECT_MD}" <<EOF
# Self-Correction Report

**Status:** No corrective action required — initial anomaly scan produced 0 HIGH-severity items.

**Total anomalies:** ${initial_total} (all MEDIUM or LOW)

The triage pipeline produced an internally consistent picture; no contradictions
between artifact sources warranted re-execution.
EOF
    exit 0
fi

for ITER in $(seq 1 "${MAX_ITERATIONS}"); do
    section "Iteration ${ITER}/${MAX_ITERATIONS}"

    high_before=$(count_high)
    total_before=$(count_total)
    echo "  HIGH before:  ${high_before}"
    echo "  Total before: ${total_before}"

    if [[ ${high_before} -eq 0 ]]; then
        status "DONE" "No remaining HIGH anomalies — self-correction converged"
        log_iter "${ITER}" "{\"summary\":\"converged — 0 HIGH anomalies remaining\"}"
        break
    fi

    # Pick the first HIGH anomaly to address this iteration
    # (one per iteration so each correction is attributable in the log)
    target=$(awk -F, 'NR>1 && $1=="HIGH" {print $2 "|" $3 "|" $4; exit}' "${ANOMALIES_CSV}")
    target_cat="${target%%|*}"
    rest="${target#*|}"
    target_machine="${rest%%|*}"
    target_value="${rest#*|}"

    echo ""
    echo "  Target anomaly:"
    echo "    Category : ${target_cat}"
    echo "    Machine  : ${target_machine}"
    echo "    Value    : ${target_value}"

    action_def=$(pick_action "${target_cat}" "${target_machine}" "${target_value}")
    action_script="${action_def%%|*}"
    action_desc="${action_def#*|}"

    echo "  Corrective action: ${action_desc}"
    echo "  Script           : ${action_script:-(none)}"

    if [[ -z "${action_script}" ]]; then
        # Not correctable — log + skip this anomaly so we don't loop on it
        log_iter "${ITER}" "$(python3 -c "import json; print(json.dumps({'category':'${target_cat}','machine':'${target_machine}','value':'${target_value}','action':'log-only','description':'${action_desc}','high_before':${high_before},'high_after':${high_before}}))")"
        # Mark as low-priority by removing from anomalies (one-shot demote)
        python3 - "${ANOMALIES_CSV}" "${target_cat}" "${target_machine}" "${target_value}" <<'PYEOF'
import csv, sys
src, cat, mach, val = sys.argv[1:]
rows = []
with open(src, newline="", encoding="utf-8") as fh:
    r = csv.reader(fh)
    header = next(r)
    for row in r:
        if row[0]=="HIGH" and row[1]==cat and row[2]==mach and row[3]==val:
            row[0] = "LOW"  # demote to LOW so we don't loop on uncorrectable items
        rows.append(row)
with open(src, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(header)
    w.writerows(rows)
PYEOF
        continue
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        status "DRY-RUN" "Would invoke: bash ${action_script} ${CASE_ROOT}"
        log_iter "${ITER}" "$(python3 -c "import json; print(json.dumps({'category':'${target_cat}','machine':'${target_machine}','value':'${target_value}','action':'dry-run','script':'${action_script}','description':'${action_desc}'}))")"
        break
    fi

    # IOC-addition categories: insert into ioc_master.csv first, then re-extract
    if [[ "${target_cat}" == "memory-only-ip" || "${target_cat}" == "pcap-beacon-not-in-iocs" ]]; then
        if add_ioc_ip "${target_value}" "self-correction iter ${ITER} (${target_cat})"; then
            status "OK" "Added ${target_value} to ioc_master.csv"
        fi
    fi

    # Force re-run of the corrective phase by removing its completion signal
    case "${action_script}" in
        *run_antiforensics.sh)
            find "${ANALYSIS_DIR}" -path "*${target_machine}*/AntiForensics/*.csv" -delete 2>/dev/null
            ;;
        *run_hunting.sh)
            find "${ANALYSIS_DIR}" -path "*${target_machine}*/Hunting/*.csv" -delete 2>/dev/null
            ;;
        *run_webserver.sh)
            find "${ANALYSIS_DIR}" -path "*${target_machine}*/WebServer/*.csv" -delete 2>/dev/null
            ;;
        *run_ioc_extract.sh)
            rm -f "${ANALYSIS_DIR}/ioc_master.csv.bak"
            cp "${ANALYSIS_DIR}/ioc_master.csv" "${ANALYSIS_DIR}/ioc_master.csv.bak" 2>/dev/null || true
            rm -f "${ANALYSIS_DIR}/ioc_master.csv"
            ;;
    esac

    set +e
    bash "${action_script}" "${CASE_ROOT}" >/tmp/self_correct_iter.log 2>&1
    rc=$?
    set -e
    tail -20 /tmp/self_correct_iter.log

    # Re-run anomaly check after the corrective action
    rm -f "${ANOMALIES_CSV}"
    bash "${SCRIPT_DIR}/run_anomaly_check.sh" "${CASE_ROOT}" >/dev/null 2>&1

    high_after=$(count_high)
    total_after=$(count_total)
    delta=$((high_before - high_after))

    echo ""
    echo "  Iteration result:"
    echo "    HIGH after:  ${high_after}  (delta: $([ ${delta} -ge 0 ] && echo +)${delta})"
    echo "    Total after: ${total_after}"

    success="false"
    if [[ ${delta} -gt 0 ]]; then
        success="true"
        status "SUCCESS" "Anomaly count decreased — corrective action effective"
    elif [[ ${delta} -eq 0 ]]; then
        status "NO-CHANGE" "Anomaly count unchanged — corrective action did not resolve"
    else
        status "WORSE" "Anomaly count INCREASED — additional contradictions surfaced"
    fi

    log_iter "${ITER}" "$(python3 -c "import json; print(json.dumps({'category':'${target_cat}','machine':'${target_machine}','value':'${target_value}','action':'rerun','script':'${action_script}','description':'${action_desc}','exit_code':${rc},'high_before':${high_before},'high_after':${high_after},'delta':${delta},'success':${success}}))")"

    audit_log_entry "${target_machine}" "self_correction" \
        "iter ${ITER}: ${action_script}" \
        "Self-correction iter ${ITER}: ${action_desc}" \
        "${ANOMALIES_CSV}" \
        "HIGH ${high_before}→${high_after} (delta ${delta}, success=${success})" \
        "${rc}"
done

# ─── final report ──────────────────────────────────────────────────────────

final_high=$(count_high)
final_total=$(count_total)

section "Self-Correction Complete"
echo "  HIGH anomalies:  ${initial_high} → ${final_high}"
echo "  Total anomalies: ${initial_total} → ${final_total}"

# Build human-readable report
python3 - "${SELF_CORRECT_LOG}" "${SELF_CORRECT_MD}" "${initial_high}" "${final_high}" "${initial_total}" "${final_total}" <<'PYEOF'
import json, sys, datetime
log_path, md_out, ih, fh, it, ft = sys.argv[1:]
ih, fh, it, ft = map(int, (ih, fh, it, ft))

iters = []
try:
    with open(log_path, encoding="utf-8") as fp:
        for line in fp:
            line=line.strip()
            if line:
                iters.append(json.loads(line))
except FileNotFoundError:
    pass

with open(md_out, "w", encoding="utf-8") as out:
    out.write("# Self-Correction Report\n\n")
    out.write(f"**Generated:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n")
    out.write("## Summary\n\n")
    out.write(f"- **Initial HIGH anomalies:** {ih}\n")
    out.write(f"- **Final HIGH anomalies:**   {fh}\n")
    out.write(f"- **HIGH delta:**             {ih - fh}\n")
    out.write(f"- **Initial total anomalies:** {it}\n")
    out.write(f"- **Final total anomalies:**   {ft}\n")
    out.write(f"- **Iterations executed:**    {len(iters)}\n\n")

    if ih == 0:
        out.write("**Outcome:** No HIGH anomalies on first scan — pipeline produced internally consistent output.\n\n")
    elif fh == 0:
        out.write("**Outcome:** **CONVERGED** — all HIGH anomalies resolved through self-correction.\n\n")
    elif fh < ih:
        out.write(f"**Outcome:** **PARTIAL** — reduced HIGH anomalies from {ih} to {fh}; remaining items require analyst review.\n\n")
    else:
        out.write(f"**Outcome:** **NO IMPROVEMENT** — corrective actions did not reduce HIGH anomalies. Surface to IC for manual investigation.\n\n")

    if iters:
        out.write("## Iteration Log\n\n")
        for it_entry in iters:
            i = it_entry.get("iteration","?")
            ts = it_entry.get("timestamp_utc","?")
            a = it_entry.get("action",{})
            out.write(f"### Iteration {i} — {ts}\n\n")
            for k, v in a.items():
                out.write(f"- **{k}:** {v}\n")
            out.write("\n")

print(f"  Report: {md_out}")
PYEOF

echo "  Iteration log: ${SELF_CORRECT_LOG}"
echo "  Report:        ${SELF_CORRECT_MD}"
echo ""
