#!/usr/bin/env bash
# run_artifacts.sh — Phase 4: Parse user activity artifacts for every machine
# under the case root.
#
# Sections:
#   A. LNK files        — LECmd   (Recent, Desktop, taskbar shortcuts)
#   B. Jump Lists       — JLECmd  (AutomaticDestinations + CustomDestinations)
#   C. Recycle Bin      — RBCmd   ($Recycle.Bin $I* metadata records)
#   D. Windows Timeline — WxTCmd  (ActivitiesCache.db per user)
#   E. Prefetch         — PECmd   (Windows\Prefetch\*.pf — run count + load order)
#
# Output : analysis/<MACHINE>/Artifacts/{LNK,JumpLists,RecycleBin,Timeline,Prefetch}/
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

LECMD="dotnet /opt/zimmermantools/LECmd.dll"
JLECMD="dotnet /opt/zimmermantools/JLECmd.dll"
RBCMD="dotnet /opt/zimmermantools/RBCmd.dll"
WXTCMD="dotnet /opt/zimmermantools/WxTCmd.dll"
PECMD="dotnet /opt/zimmermantools/PECmd.dll"
INSTALL_SCRIPT="$(dirname "$0")/install_tools.sh"

SKIP_USERS="Default|LocalService|NetworkService"

# require_tool DISPLAY_NAME DLL_PATH
# Warns and returns 1 if the tool DLL is missing, so calling sections can skip.
require_tool() {
    local name="$1" dll="$2"
    if [[ ! -f "${dll}" ]]; then
        echo ""
        echo "  ╔══════════════════════════════════════════════════════╗"
        echo "  ║  MISSING TOOL: ${name}"
        printf "  ║  Expected    : %s\n" "${dll}"
        echo "  ║"
        echo "  ║  To install, run:"
        echo "  ║    bash ${INSTALL_SCRIPT}"
        echo "  ║"
        echo "  ║  Or manually:"
        echo "  ║    curl -L 'https://download.ericzimmermanstools.com/net9/${name}.zip' \\"
        echo "  ║         -o /tmp/${name}.zip"
        echo "  ║    sudo unzip -o /tmp/${name}.zip -d /opt/zimmermantools/"
        echo "  ╚══════════════════════════════════════════════════════╝"
        echo ""
        return 1
    fi
    return 0
}

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
echo " Artifact Batch Runner — jackofallhacks"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ════════════════════════════════════════════════════════════════════════════
section "A. LNK Files — LECmd"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    out_dir="${ANALYSIS_DIR}/${machine}/Artifacts/LNK"
    csv_prefix="${machine}_${drive}_LNK"

    machine_header "${machine} (drive ${drive}:)"

    lnk_count=$(find "${drive_root}/Users" -name "*.lnk" ! -path "*/ServiceProfiles/*" 2>/dev/null | wc -l)
    if [[ ${lnk_count} -eq 0 ]]; then
        status "MISSING" "No .lnk files found under ${drive_root}/Users"; continue
    fi
    if csv_has_data "${out_dir}" "${csv_prefix}.csv"; then
        status "SKIP" "CSV with data already exists"; continue
    fi

    mkdir -p "${out_dir}"
    cmd="${LECMD} -d '${drive_root}/Users' -q --csv '${out_dir}' --csvf '${csv_prefix}'"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "LECmd exited ${rc}"; echo "${tool_out}" | sed 's/^/    /'; continue
    fi

    csv_size=$(du -h "${out_dir}/${csv_prefix}.csv" 2>/dev/null | cut -f1 || echo "?")
    entries=$(grep -c "^" "${out_dir}/${csv_prefix}.csv" 2>/dev/null || echo "?")
    status "OK" "${lnk_count} .lnk files → ${entries} rows (${csv_size})"
    log_cmd "${machine}" "LECmd (LNK files, drive ${drive}:)" \
        "${cmd}" \
        "Parse all LNK shortcut files for target path, timestamps, volume serial, machine name" \
        "${out_dir}/${csv_prefix}.csv (${csv_size})" \
        "${lnk_count} files parsed, ${entries} rows"
done

# ════════════════════════════════════════════════════════════════════════════
section "B. Jump Lists — JLECmd"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    out_dir="${ANALYSIS_DIR}/${machine}/Artifacts/JumpLists"
    csv_prefix="${machine}_${drive}_JumpLists"

    machine_header "${machine} (drive ${drive}:)"

    jl_count=$(find "${drive_root}/Users" \( -name "*.automaticDestinations-ms" -o -name "*.customDestinations-ms" \) \
               ! -path "*/ServiceProfiles/*" 2>/dev/null | wc -l)
    if [[ ${jl_count} -eq 0 ]]; then
        status "MISSING" "No jump list files found"; continue
    fi
    if csv_has_data "${out_dir}" "${csv_prefix}*.csv"; then
        status "SKIP" "CSV(s) with data already exist"; continue
    fi

    mkdir -p "${out_dir}"
    cmd="${JLECMD} -d '${drive_root}/Users' -q --csv '${out_dir}' --csvf '${csv_prefix}'"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "JLECmd exited ${rc}"; echo "${tool_out}" | sed 's/^/    /'; continue
    fi

    csv_count=$(find "${out_dir}" -maxdepth 1 -name "${csv_prefix}*.csv" 2>/dev/null | wc -l)
    status "OK" "${jl_count} jump list files → ${csv_count} CSV(s)"
    log_cmd "${machine}" "JLECmd (Jump Lists, drive ${drive}:)" \
        "${cmd}" \
        "Parse AutomaticDestinations and CustomDestinations jump lists for recently accessed files per application" \
        "${out_dir}/${csv_prefix}_*.csv (${csv_count} files)" \
        "${jl_count} jump list files parsed"
done

# ════════════════════════════════════════════════════════════════════════════
section "C. Recycle Bin — RBCmd"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    recycle_dir="${drive_root}/\$Recycle.Bin"
    out_dir="${ANALYSIS_DIR}/${machine}/Artifacts/RecycleBin"
    csv_name="${machine}_${drive}_RecycleBin.csv"

    machine_header "${machine} (drive ${drive}:)"

    if [[ ! -d "${recycle_dir}" ]]; then
        status "MISSING" "${recycle_dir}"; continue
    fi

    record_count=$(find "${recycle_dir}" -name "\$I*" 2>/dev/null | wc -l)
    if [[ ${record_count} -eq 0 ]]; then
        status "EMPTY" "No \$I records in Recycle Bin"; continue
    fi
    if csv_has_data "${out_dir}" "${csv_name}"; then
        status "SKIP" "CSV with data already exists"; continue
    fi

    mkdir -p "${out_dir}"
    cmd="${RBCMD} -d '${recycle_dir}' --csv '${out_dir}' --csvf '${csv_name}'"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "RBCmd exited ${rc}"; echo "${tool_out}" | sed 's/^/    /'; continue
    fi

    entries=$(grep -c "^" "${out_dir}/${csv_name}" 2>/dev/null || echo "?")
    status "OK" "${record_count} \$I records → ${entries} rows"
    log_cmd "${machine}" "RBCmd (Recycle Bin, drive ${drive}:)" \
        "${cmd}" \
        "Parse Recycle Bin \$I records for deleted file original path, size, and deletion timestamp by SID" \
        "${out_dir}/${csv_name}" \
        "${record_count} records parsed, ${entries} rows"
done

# ════════════════════════════════════════════════════════════════════════════
section "D. Windows Timeline — WxTCmd (ActivitiesCache.db per user)"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')

    machine_header "${machine} (drive ${drive}:)"

    while IFS= read -r db_path; do
        username=$(echo "${db_path}" | grep -oP '(?<=/Users/)[^/]+')

        if echo "${username}" | grep -qP "^(${SKIP_USERS})$"; then
            status "SKIP" "${username} (service/default account)"; continue
        fi

        out_dir="${ANALYSIS_DIR}/${machine}/Artifacts/Timeline/${username}"
        safe_user=$(echo "${username}" | tr ' ' '_')
        csv_prefix="${machine}_${drive}_${safe_user}_Timeline"

        if csv_has_data "${out_dir}" "${csv_prefix}*.csv"; then
            status "SKIP" "${username} timeline — CSV(s) with data already exist"; continue
        fi

        mkdir -p "${out_dir}"
        cmd="${WXTCMD} -f '${db_path}' --csv '${out_dir}' --csvf '${csv_prefix}'"

        tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
        if [[ ${rc} -ne 0 ]]; then
            status "ERROR" "${username} — WxTCmd exited ${rc}"; continue
        fi

        csv_count=$(find "${out_dir}" -maxdepth 1 -name "${csv_prefix}*.csv" 2>/dev/null | wc -l)
        entries=$(cat "${out_dir}"/${csv_prefix}*.csv 2>/dev/null | grep -c "^" || echo "?")
        status "OK" "${username} → ${csv_count} CSV(s), ~${entries} activity entries"
        log_cmd "${machine}" "WxTCmd (Windows Timeline — ${username}, drive ${drive}:)" \
            "${cmd}" \
            "Parse Windows 10 Timeline ActivitiesCache.db for application usage and file access history for ${username}" \
            "${out_dir}/${csv_prefix}_*.csv (${csv_count} files)" \
            "~${entries} activity entries"

    done < <(find "${drive_root}/Users" -name "ActivitiesCache.db" \
                ! -path "*/ServiceProfiles/*" 2>/dev/null | sort)
done

# ════════════════════════════════════════════════════════════════════════════
section "E. Prefetch — PECmd"
# ════════════════════════════════════════════════════════════════════════════

if ! require_tool "PECmd" "/opt/zimmermantools/PECmd.dll"; then
    echo "  Prefetch files located (will parse once PECmd is installed):"
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -ipath "*/prefetch/*.pf" -print \
        2>/dev/null | awk -F'/' '{print "    "$0}' | head -10
    pf_total=$(find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -ipath "*/prefetch/*.pf" -print 2>/dev/null | wc -l)
    echo "    ... ${pf_total} total .pf files across all machines"
else
    for drive_root in "${DRIVE_ROOTS[@]}"; do
        machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
        drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
        prefetch_dir="${drive_root}/Windows/prefetch"
        out_dir="${ANALYSIS_DIR}/${machine}/Artifacts/Prefetch"
        csv_prefix="${machine}_${drive}_Prefetch"

        machine_header "${machine} (drive ${drive}:)"

        # Prefetch is disabled by default on Windows Server — skip gracefully
        if [[ ! -d "${prefetch_dir}" ]]; then
            status "MISSING" "No prefetch directory (likely server with prefetch disabled)"
            continue
        fi

        pf_count=$(find "${prefetch_dir}" -iname "*.pf" 2>/dev/null | wc -l)
        if [[ ${pf_count} -eq 0 ]]; then
            status "EMPTY" "Prefetch directory exists but contains no .pf files"
            continue
        fi

        if csv_has_data "${out_dir}" "${csv_prefix}*.csv"; then
            status "SKIP" "CSV(s) with data already exist"
            continue
        fi

        mkdir -p "${out_dir}"
        cmd="${PECMD} -d '${prefetch_dir}' --csv '${out_dir}' --csvf '${csv_prefix}' -q"

        tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
        if [[ ${rc} -ne 0 ]]; then
            status "ERROR" "PECmd exited ${rc}"; echo "${tool_out}" | sed 's/^/    /'; continue
        fi

        csv_count=$(find "${out_dir}" -maxdepth 1 -name "${csv_prefix}*.csv" 2>/dev/null | wc -l)
        entries=$(cat "${out_dir}"/${csv_prefix}*.csv 2>/dev/null | grep -c "^" || echo "?")
        status "OK" "${pf_count} .pf files → ${csv_count} CSV(s), ~${entries} entries"
        log_cmd "${machine}" "PECmd (Prefetch, drive ${drive}:)" \
            "${cmd}" \
            "Parse Windows Prefetch files for execution evidence: last run time, run count, files loaded at execution" \
            "${out_dir}/${csv_prefix}_*.csv (${csv_count} files)" \
            "${pf_count} .pf files parsed, ~${entries} entries"
    done
fi

echo ""
echo "════════════════════════════════════════════════════"
echo " Done. Artifact output:"
find "${ANALYSIS_DIR}" -path "*/Artifacts/*" -name "*.csv" | sort | awk '{print "  "$0}'
echo "════════════════════════════════════════════════════"
