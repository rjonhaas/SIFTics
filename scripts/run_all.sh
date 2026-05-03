#!/usr/bin/env bash
# run_all.sh — Master orchestrator for jackofallhacks triage.
#
# Before invoking each phase script the orchestrator checks per-machine output
# directories for CSV files that exist and contain data rows (not just a header).
# A phase is skipped entirely if every machine already has parsed output.
# If any machine is incomplete the phase script runs — it performs the same CSV
# check internally and skips individual machines/artifacts that are already done.
#
# Phase 1 — run_ntfs.sh        $MFT $Boot $LogFile $J
# Phase 2 — run_registry.sh    System/User hives, Amcache, ShimCache, ShellBags, RegBack
# Phase 3 — run_eventlogs.sh   All .evtx (EvtxECmd + Maps)
# Phase 4 — run_artifacts.sh   LNK, Jump Lists, Recycle Bin, Windows Timeline, Prefetch
# Phase 5 — run_execution.sh   IIS logs, HTTPERR, PS history, Scheduled Tasks
# Phase 6 — run_hunting.sh     PrivEsc / Lateral Movement hunting over evtx CSVs
# Phase 7 — run_credaccess.sh   Credential access & persistence (DCSync/LSASS/Kerberoasting/WMI/Timestomping)
# Phase 8 — run_antiforensics.sh Log clearing, VSS deletion, Defender tampering, anti-forensic tools
# Phase 9 — run_ioc_extract.sh   IOC extraction (IPs/URLs/hashes/paths) across all analysis CSVs
# Phase 10— run_c2_beacon.sh     C2 beacon detection via IIS log interval analysis
# Phase 11— run_browser.sh       Zone.Identifier/MotW, Chrome/Edge/Firefox history, IE legacy
# Phase 12— run_ransomware.sh    Ransom notes, suspicious extensions, archive staging
# Phase 13— run_webserver.sh     IIS log injection detection, LOLBIN downloads, operator sessions, webshell inventory
# Phase 14— run_email.sh         PST/OST email parsing (readpst → mbox → IOC extraction, attachment hashing)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Resolve CASE_ROOT: $1 argument → inherited env var → interactive prompt
CASE_ROOT="${1:-${CASE_ROOT:-}}"
if [[ -z "$CASE_ROOT" ]]; then
    read -rp "Case root directory (e.g. /cases/jack2): " CASE_ROOT
fi
[[ -d "$CASE_ROOT" ]] || { echo "ERROR: CASE_ROOT '${CASE_ROOT}' does not exist." >&2; exit 1; }
export CASE_ROOT
ANALYSIS_DIR="${CASE_ROOT}/analysis"
COMMAND_LOG="${SCRIPT_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")
RUN_LOG="${SCRIPT_DIR}/run_$(date -u +%Y%m%d_%H%M%S).log"

# Tee all output (stdout + stderr) to a timestamped run log
exec > >(tee -a "${RUN_LOG}") 2>&1
echo "Run log: ${RUN_LOG}"

# ─── discover machines (anchored by $MFT) ───────────────────────────────────

mapfile -t DRIVE_ROOTS < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name '$MFT' -print \
    | sort | xargs -I{} dirname {}
)

MACHINE_COUNT="${#DRIVE_ROOTS[@]}"

# ─── helpers ─────────────────────────────────────────────────────────────────

divider()  { echo ""; echo "████████████████████████████████████████████████████"; }
log_phase() {
    local label="$1" script="$2" status="$3" runtime="$4"
    cat >> "${COMMAND_LOG}" <<EOF

[${TIMESTAMP}] ALL | run_all.sh orchestrator
  bash ${script}
  > Purpose  : ${label}
  > Output   : see phase section in commands.txt
  > Result   : ${status} — runtime ${runtime}

--------------------------------------------------------------------------------
EOF
}

# csv_has_data DIR [PATTERN]
# Returns 0 if at least one CSV matching PATTERN under DIR has >1 line (header+data).
csv_has_data() {
    local dir="$1" pattern="${2:-*.csv}"
    [[ -d "${dir}" ]] || return 1
    while IFS= read -r f; do
        [[ $(wc -l < "${f}" 2>/dev/null) -gt 1 ]] && return 0
    done < <(find "${dir}" -maxdepth 4 -name "${pattern}" -size +100c 2>/dev/null)
    return 1
}

# phase_status SUBDIR PATTERN
# Prints "N done / M total" and returns the count of machines still needing work.
phase_status() {
    local subdir="$1" pattern="${2:-*.csv}"
    local done=0 remaining=0 machine drive
    for drive_root in "${DRIVE_ROOTS[@]}"; do
        machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
        if csv_has_data "${ANALYSIS_DIR}/${machine}/${subdir}" "${pattern}"; then
            (( done++ ))    || true
        else
            (( remaining++ )) || true
        fi
    done
    echo "${done} / ${MACHINE_COUNT} machines already parsed"
    return "${remaining}"
}

# ─── phase definitions ───────────────────────────────────────────────────────
# Format: "Label|script|output_subdir|csv_pattern"
#   output_subdir — relative to analysis/<MACHINE>/; checked per machine
#   csv_pattern   — glob passed to csv_has_data

PHASES=(
    "Phase 1 — NTFS Artifacts|${SCRIPT_DIR}/run_ntfs.sh|.|*_MFT.csv"
    "Phase 2 — Registry      |${SCRIPT_DIR}/run_registry.sh|Registry|*.csv"
    "Phase 3 — Event Logs    |${SCRIPT_DIR}/run_eventlogs.sh|EventLogs|*.csv"
    "Phase 4 — Artifacts     |${SCRIPT_DIR}/run_artifacts.sh|Artifacts|*.csv"
    "Phase 5 — Execution Evd |${SCRIPT_DIR}/run_execution.sh|Execution|*.csv"
    "Phase 6 — Hunting       |${SCRIPT_DIR}/run_hunting.sh|Hunting|*.csv"
    "Phase 7 — Cred Access   |${SCRIPT_DIR}/run_credaccess.sh|CredAccess|*.csv"
    "Phase 8 — Anti-Forensics|${SCRIPT_DIR}/run_antiforensics.sh|AntiForensics|*.csv"
    "Phase 9 — IOC Extract   |${SCRIPT_DIR}/run_ioc_extract.sh|.|ioc_master.csv"
    "Phase 10— C2 Beacon     |${SCRIPT_DIR}/run_c2_beacon.sh|Execution/IIS|c2_beacon.csv"
    "Phase 11— Browser       |${SCRIPT_DIR}/run_browser.sh|Browser|*.csv"
    "Phase 12— Ransomware    |${SCRIPT_DIR}/run_ransomware.sh|Ransomware|*.csv"
    "Phase 13— Web Server   |${SCRIPT_DIR}/run_webserver.sh|WebServer|injection_attempts.csv"
    "Phase 14— Email        |${SCRIPT_DIR}/run_email.sh|Email|*_E_*_Email_Messages.csv"
)

# ─── main loop ───────────────────────────────────────────────────────────────

declare -A PHASE_STATUS
declare -A PHASE_ELAPSED

echo "████████████████████████████████████████████████████"
echo " jackofallhacks — Full Triage Orchestrator"
echo " $(date -u)"
echo " Machines : ${MACHINE_COUNT}"
echo "████████████████████████████████████████████████████"

# ─── pre-flight tool check ───────────────────────────────────────────────────
divider
echo " PRE-FLIGHT: Checking required tools"
echo "████████████████████████████████████████████████████"
echo ""

INSTALL_SCRIPT="${SCRIPT_DIR}/install_tools.sh"
if [[ -f "${INSTALL_SCRIPT}" ]]; then
    set +e
    bash "${INSTALL_SCRIPT}" --check-only
    tool_rc=$?
    set -e
    if [[ ${tool_rc} -ne 0 ]]; then
        echo ""
        echo "  One or more required tools are missing."
        echo "  Run the following to install them, then re-run this script:"
        echo ""
        echo "    bash ${INSTALL_SCRIPT}"
        echo ""
        echo "  Continuing — phases with missing tools will report clearly and skip."
        echo ""
    fi
else
    echo "  install_tools.sh not found — skipping pre-flight check."
fi

for phase_def in "${PHASES[@]}"; do
    IFS='|' read -r label script subdir pattern <<< "${phase_def}"

    divider
    echo " ${label}"
    echo " Script : ${script}"
    echo ""

    # ── pre-flight CSV check ─────────────────────────────────────────────────
    set +e
    summary=$(phase_status "${subdir}" "${pattern}")
    remaining=$?
    set -e

    echo "  Pre-flight : ${summary}"

    if [[ ${remaining} -eq 0 ]]; then
        echo "  [SKIP] All machines have parsed output — no tools will run."
        PHASE_STATUS["${label}"]="SKIP (all done)"
        PHASE_ELAPSED["${label}"]="0m 0s"
        continue
    fi

    echo "  [RUN ] ${remaining} machine(s) need processing."
    echo ""

    if [[ ! -f "${script}" ]]; then
        echo "  [ERROR] Script not found: ${script}"
        PHASE_STATUS["${label}"]="MISSING SCRIPT"
        PHASE_ELAPSED["${label}"]="-"
        continue
    fi

    start_ts=$(date +%s)
    set +e
    bash "${script}"
    exit_code=$?
    set -e
    elapsed=$(( $(date +%s) - start_ts ))
    elapsed_fmt=$(printf "%dm %ds" $(( elapsed / 60 )) $(( elapsed % 60 )))

    if [[ ${exit_code} -eq 0 ]]; then
        PHASE_STATUS["${label}"]="OK"
    else
        PHASE_STATUS["${label}"]="ERROR (exit ${exit_code})"
    fi
    PHASE_ELAPSED["${label}"]="${elapsed_fmt}"

    log_phase "${label}" "${script}" "${PHASE_STATUS["${label}"]}" "${elapsed_fmt}"
done

# ─── summary ─────────────────────────────────────────────────────────────────

divider
echo " TRIAGE COMPLETE — $(date -u)"
echo "████████████████████████████████████████████████████"
echo ""
printf "  %-30s  %-24s  %s\n" "Phase" "Status" "Runtime"
echo "  ──────────────────────────────────────────────────────────"
for phase_def in "${PHASES[@]}"; do
    IFS='|' read -r label script subdir pattern <<< "${phase_def}"
    printf "  %-30s  %-24s  %s\n" \
        "${label}" \
        "${PHASE_STATUS["${label}"]:-NOT RUN}" \
        "${PHASE_ELAPSED["${label}"]:-}"
done
echo ""
echo "  Output root: ${SCRIPT_DIR}"
echo ""
