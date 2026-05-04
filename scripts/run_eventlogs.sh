#!/usr/bin/env bash
# DAEDALUS:HANDLES win_evtx
# run_eventlogs.sh — Phase 3: Parse Windows event logs for every machine under
# the case root using EvtxECmd with the full Maps library.
#
# Sections:
#   A. Bulk evtx parse  — EvtxECmd (-d) on entire Logs directory per machine
#
# Output : analysis/<MACHINE>/EventLogs/<MACHINE>_<DRIVE>_evtx_*.csv
# Logging: appends to analysis/commands.txt

set -euo pipefail

# Resolve CASE_ROOT: $1 argument → inherited env var → interactive prompt
CASE_ROOT="${1:-${CASE_ROOT:-}}"
if [[ -z "$CASE_ROOT" ]]; then
    read -rp "Case root directory (e.g. /cases/jack2): " CASE_ROOT
fi
[[ -d "$CASE_ROOT" ]] || { echo "ERROR: CASE_ROOT '${CASE_ROOT}' does not exist." >&2; exit 1; }
export CASE_ROOT
ANALYSIS_DIR="${CASE_ROOT}/analysis"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")

EVTXECMD="dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"
MAPS_DIR="/opt/zimmermantools/EvtxeCmd/Maps"

# ─── helpers ────────────────────────────────────────────────────────────────

log_cmd() {
    local machine="$1" tool="$2" cmd="$3" purpose="$4" output="$5" result="$6"
    cat >> "${COMMAND_LOG}" <<EOF

[${TIMESTAMP}] ${machine} | ${tool} | EZ Tools
  ${cmd}
  > Purpose  : ${purpose}
  > Output   : ${output}
  > Result   : ${result}

--------------------------------------------------------------------------------
EOF
}

run_tool() {
    set +e; out=$(eval "$1" 2>&1); rc=$?; set -e
    echo "${out}"; return ${rc}
}

# csv_has_data DIR [PATTERN] — true if any matching CSV under DIR has >1 line
csv_has_data() {
    local dir="$1" pattern="${2:-*.csv}"
    [[ -d "${dir}" ]] || return 1
    while IFS= read -r f; do
        [[ $(wc -l < "${f}" 2>/dev/null) -gt 1 ]] && return 0
    done < <(find "${dir}" -maxdepth 2 -name "${pattern}" -size +100c 2>/dev/null)
    return 1
}

section()        { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
machine_header() { echo ""; echo "  ── $* ──"; }
status()         { printf "  [%-10s] %s\n" "$1" "$2"; }

mapfile -t DRIVE_ROOTS < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name '$MFT' -print \
    | sort | xargs -I{} dirname {}
)

echo "════════════════════════════════════════════════════"
echo " Event Log Batch Runner — jackofallhacks"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ════════════════════════════════════════════════════════════════════════════
section "A. Event Logs — EvtxECmd (all .evtx per machine)"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    logs_dir="${drive_root}/Windows/System32/winevt/Logs"
    out_dir="${ANALYSIS_DIR}/${machine}/EventLogs"
    csv_prefix="${machine}_${drive}_evtx"

    machine_header "${machine} (drive ${drive}:)"

    if [[ ! -d "${logs_dir}" ]]; then
        status "MISSING" "${logs_dir}"; continue
    fi

    evtx_count=$(find "${logs_dir}" -name "*.evtx" | wc -l)
    if [[ ${evtx_count} -eq 0 ]]; then
        status "EMPTY" "No .evtx files found in ${logs_dir}"; continue
    fi

    if csv_has_data "${out_dir}" "${csv_prefix}*.csv"; then
        status "SKIP" "CSV(s) with data already exist"; continue
    fi

    mkdir -p "${out_dir}"
    cmd="${EVTXECMD} -d '${logs_dir}' --maps '${MAPS_DIR}' --csv '${out_dir}' --csvf '${csv_prefix}.csv'"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "EvtxECmd exited ${rc}"; echo "${tool_out}" | sed 's/^/    /'; continue
    fi

    csv_count=$(find "${out_dir}" -maxdepth 1 -name "${csv_prefix}*.csv" 2>/dev/null | wc -l)
    events=$(cat "${out_dir}"/${csv_prefix}*.csv 2>/dev/null | grep -c "^" || echo "?")
    status "OK" "${evtx_count} logs → ${csv_count} CSV(s), ~${events} events"
    log_cmd "${machine}" "EvtxECmd (all event logs, drive ${drive}:)" \
        "${cmd}" \
        "Parse all Windows event logs with full Maps library — Security/System/Application/PowerShell/TaskScheduler/WMI/RDP/Defender/etc." \
        "${out_dir}/${csv_prefix}_*.csv (${csv_count} files)" \
        "${evtx_count} evtx files processed, ~${events} events"
done

echo ""
echo "════════════════════════════════════════════════════"
echo " Done. EventLog output:"
find "${ANALYSIS_DIR}" -path "*/EventLogs/*.csv" | sort | awk '{print "  "$0}'
echo "════════════════════════════════════════════════════"
