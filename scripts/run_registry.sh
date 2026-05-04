#!/usr/bin/env bash
# DAEDALUS:HANDLES win_registry win_shimcache win_amcache win_userassist win_shellbags
# DAEDALUS:DOMAIN windows_registry
# run_registry.sh — Phase 2 registry parsing for all machines under the case root.
#
# Sections (run in order):
#   A. System hives  — RECmd + Kroll_Batch.reb  (SAM/SECURITY/SOFTWARE/SYSTEM/DEFAULT)
#   B. User hives    — RECmd + Kroll_Batch.reb  (NTUSER.DAT per real user account)
#   C. User classes  — RECmd + Kroll_Batch.reb  (UsrClass.dat per real user account)
#   D. Amcache       — AmcacheParser             (Amcache.hve)
#   E. ShimCache     — AppCompatCacheParser      (SYSTEM hive)
#   F. SRUM          — SrumECmd                  [NOT INSTALLED — skipped]
#   G. Shell Bags    — SBECmd                    (UsrClass.dat — folder traversal history)
#   H. RegBack hives — RECmd + Kroll_Batch.reb  (config/RegBack snapshot, where present)
#
# Outputs: analysis/<MACHINE>/Registry/{System,Users/<user>,Amcache,ShimCache,ShellBags,RegBack}/
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

RECMD="dotnet /opt/zimmermantools/RECmd/RECmd.dll"
KROLL_BATCH="/opt/zimmermantools/RECmd/BatchExamples/Kroll_Batch.reb"
AMCACHE="dotnet /opt/zimmermantools/AmcacheParser.dll"
SHIMCACHE="dotnet /opt/zimmermantools/AppCompatCacheParser.dll"
SBECMD="dotnet /opt/zimmermantools/SBECmd.dll"

# Service/default accounts to exclude from user hive processing
SKIP_USERS="Default|LocalService|NetworkService"

# ─── helpers ────────────────────────────────────────────────────────────────

# csv_has_data DIR [PATTERN] — true if any matching CSV under DIR has >1 line
csv_has_data() {
    local dir="$1" pattern="${2:-*.csv}"
    [[ -d "${dir}" ]] || return 1
    while IFS= read -r f; do
        [[ $(wc -l < "${f}" 2>/dev/null) -gt 1 ]] && return 0
    done < <(find "${dir}" -maxdepth 3 -name "${pattern}" -size +100c 2>/dev/null)
    return 1
}

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
    local cmd="$1"
    set +e
    out=$(eval "${cmd}" 2>&1)
    rc=$?
    set -e
    echo "${out}"
    return ${rc}
}

section() { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
machine_header() { echo ""; echo "  ── $* ──"; }
status() { printf "  [%-10s] %s\n" "$1" "$2"; }

# ─── find all drive roots (anchored by $MFT presence) ───────────────────────

mapfile -t DRIVE_ROOTS < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name '$MFT' -print \
    | sort | xargs -I{} dirname {}
)

echo "════════════════════════════════════════════════════"
echo " Registry Artifact Batch Runner — jackofallhacks"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ════════════════════════════════════════════════════════════════════════════
section "A. System Hives — RECmd + Kroll_Batch.reb"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    config_dir="${drive_root}/Windows/System32/config"
    out_dir="${ANALYSIS_DIR}/${machine}/Registry/System"

    machine_header "${machine} (drive ${drive}:)"

    if [[ ! -d "${config_dir}" ]]; then
        status "MISSING" "${config_dir}"; continue
    fi
    if csv_has_data "${out_dir}" "${machine}_${drive}_System*.csv"; then
        status "SKIP" "CSV(s) with data already exist"; continue
    fi

    mkdir -p "${out_dir}"
    cmd="${RECMD} --bn '${KROLL_BATCH}' -d '${config_dir}' --csv '${out_dir}' --csvf '${machine}_${drive}_System' --nl"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "RECmd exited ${rc}"; echo "${tool_out}" | sed 's/^/    /'; continue
    fi

    csv_count=$(find "${out_dir}" -maxdepth 1 -name "${machine}_${drive}_System*.csv" 2>/dev/null | wc -l)
    status "OK" "${csv_count} CSV(s) → ${out_dir}"
    log_cmd "${machine}" "RECmd + Kroll_Batch.reb (System hives, drive ${drive}:)" \
        "${cmd}" \
        "Parse system hives (SAM/SECURITY/SOFTWARE/SYSTEM/DEFAULT) with all Kroll plugins" \
        "${out_dir}/${machine}_${drive}_System_*.csv (${csv_count} files)" \
        "${csv_count} batch CSVs written"
done

# ════════════════════════════════════════════════════════════════════════════
section "B. User Hives — NTUSER.DAT — RECmd + Kroll_Batch.reb"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    users_dir="${drive_root}/Users"

    machine_header "${machine} (drive ${drive}:)"

    if [[ ! -d "${users_dir}" ]]; then
        status "MISSING" "${users_dir}"; continue
    fi

    while IFS= read -r ntuser; do
        username=$(echo "${ntuser}" | grep -oP '(?<=/Users/)[^/]+')

        # Skip service accounts and Default profile
        if echo "${username}" | grep -qP "^(${SKIP_USERS})$"; then
            status "SKIP" "${username} (service/default account)"
            continue
        fi

        out_dir="${ANALYSIS_DIR}/${machine}/Registry/Users/${username}"
        safe_user=$(echo "${username}" | tr ' ' '_')
        csv_prefix="${machine}_${drive}_${safe_user}_NTUSER"

        if csv_has_data "${out_dir}" "${csv_prefix}*.csv"; then
            status "SKIP" "${username} NTUSER — CSV(s) with data already exist"; continue
        fi

        mkdir -p "${out_dir}"
        cmd="${RECMD} --bn '${KROLL_BATCH}' -f '${ntuser}' --csv '${out_dir}' --csvf '${csv_prefix}' --nl"

        tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
        if [[ ${rc} -ne 0 ]]; then
            status "ERROR" "${username} — RECmd exited ${rc}"; continue
        fi

        csv_count=$(find "${out_dir}" -maxdepth 1 -name "${csv_prefix}*.csv" 2>/dev/null | wc -l)
        status "OK" "${username} → ${csv_count} CSV(s)"
        log_cmd "${machine}" "RECmd + Kroll_Batch.reb (NTUSER.DAT — ${username})" \
            "${cmd}" \
            "Parse user hive for ${username}: UserAssist, TypedURLs, RecentDocs, RunMRU, FeatureUsage/AppSwitched, MRUs, etc." \
            "${out_dir}/${csv_prefix}_*.csv (${csv_count} files)" \
            "${csv_count} batch CSVs written"

    done < <(find "${users_dir}" -maxdepth 2 -name "NTUSER.DAT" \
                ! -path "*/ServiceProfiles/*" | sort)
done

# ════════════════════════════════════════════════════════════════════════════
section "C. User Class Hives — UsrClass.dat — RECmd + Kroll_Batch.reb"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    users_dir="${drive_root}/Users"

    machine_header "${machine} (drive ${drive}:)"

    if [[ ! -d "${users_dir}" ]]; then
        status "MISSING" "${users_dir}"; continue
    fi

    while IFS= read -r usrcls; do
        username=$(echo "${usrcls}" | grep -oP '(?<=/Users/)[^/]+')

        if echo "${username}" | grep -qP "^(${SKIP_USERS})$"; then
            status "SKIP" "${username} (service/default account)"
            continue
        fi

        out_dir="${ANALYSIS_DIR}/${machine}/Registry/Users/${username}"
        safe_user=$(echo "${username}" | tr ' ' '_')
        csv_prefix="${machine}_${drive}_${safe_user}_UsrClass"

        if csv_has_data "${out_dir}" "${csv_prefix}*.csv"; then
            status "SKIP" "${username} UsrClass — CSV(s) with data already exist"; continue
        fi

        mkdir -p "${out_dir}"
        cmd="${RECMD} --bn '${KROLL_BATCH}' -f '${usrcls}' --csv '${out_dir}' --csvf '${csv_prefix}' --nl"

        tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
        if [[ ${rc} -ne 0 ]]; then
            status "ERROR" "${username} UsrClass — RECmd exited ${rc}"; continue
        fi

        csv_count=$(find "${out_dir}" -maxdepth 1 -name "${csv_prefix}*.csv" 2>/dev/null | wc -l)
        status "OK" "${username} UsrClass → ${csv_count} CSV(s)"
        log_cmd "${machine}" "RECmd + Kroll_Batch.reb (UsrClass.dat — ${username})" \
            "${cmd}" \
            "Parse UsrClass hive for ${username}: shell bag entries, COM class registrations" \
            "${out_dir}/${csv_prefix}_*.csv (${csv_count} files)" \
            "${csv_count} batch CSVs written"

    done < <(find "${users_dir}" -name "UsrClass.dat" \
                ! -path "*/ServiceProfiles/*" | sort)
done

# ════════════════════════════════════════════════════════════════════════════
section "D. Amcache — AmcacheParser"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')

    # Case-insensitive search for Amcache.hve
    amcache_path=$(find "${drive_root}/Windows" -iname "Amcache.hve" 2>/dev/null | head -1)
    out_dir="${ANALYSIS_DIR}/${machine}/Registry/Amcache"

    machine_header "${machine} (drive ${drive}:)"

    if [[ -z "${amcache_path}" ]]; then
        status "MISSING" "Amcache.hve not found under ${drive_root}/Windows"; continue
    fi
    if csv_has_data "${out_dir}" "${machine}_${drive}_Amcache*.csv"; then
        status "SKIP" "CSV(s) with data already exist"; continue
    fi

    mkdir -p "${out_dir}"
    cmd="${AMCACHE} -f '${amcache_path}' --csv '${out_dir}' --csvf '${machine}_${drive}_Amcache' --nl"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "AmcacheParser exited ${rc}"; echo "${tool_out}" | sed 's/^/    /'; continue
    fi

    csv_count=$(find "${out_dir}" -maxdepth 1 -name "${machine}_${drive}_Amcache*.csv" 2>/dev/null | wc -l)
    status "OK" "${csv_count} CSV(s) → ${out_dir}"
    log_cmd "${machine}" "AmcacheParser (Amcache.hve, drive ${drive}:)" \
        "${cmd}" \
        "Parse Amcache for program execution history, SHA-1 hashes, install timestamps" \
        "${out_dir}/${machine}_${drive}_Amcache_*.csv (${csv_count} files)" \
        "${csv_count} CSVs written"
done

# ════════════════════════════════════════════════════════════════════════════
section "E. ShimCache — AppCompatCacheParser"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    system_hive="${drive_root}/Windows/System32/config/SYSTEM"
    out_dir="${ANALYSIS_DIR}/${machine}/Registry/ShimCache"
    csv_name="${machine}_${drive}_ShimCache.csv"

    machine_header "${machine} (drive ${drive}:)"

    if [[ ! -f "${system_hive}" ]]; then
        status "MISSING" "${system_hive}"; continue
    fi
    if csv_has_data "${out_dir}" "${csv_name}"; then
        status "SKIP" "CSV with data already exists"; continue
    fi

    mkdir -p "${out_dir}"
    cmd="${SHIMCACHE} -f '${system_hive}' --csv '${out_dir}' --csvf '${csv_name}' --nl"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "AppCompatCacheParser exited ${rc}"; echo "${tool_out}" | sed 's/^/    /'; continue
    fi

    csv_size=$(du -h "${out_dir}/${csv_name}" 2>/dev/null | cut -f1 || echo "?")
    entries=$(grep -c "^" "${out_dir}/${csv_name}" 2>/dev/null || echo "?")
    status "OK" "${csv_name} (${csv_size}, ~${entries} rows)"
    log_cmd "${machine}" "AppCompatCacheParser (ShimCache, drive ${drive}:)" \
        "${cmd}" \
        "Parse ShimCache (AppCompatCache) for program path and last modified timestamps" \
        "${out_dir}/${csv_name} (${csv_size})" \
        "~${entries} entries"
done

# ════════════════════════════════════════════════════════════════════════════
section "F. SRUM — SrumECmd [NOT INSTALLED]"
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "  SrumECmd is not present in /opt/zimmermantools."
echo "  SRUDB.dat files are available at:"
find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name "SRUDB.dat" -print \
    | sort | sed 's/^/    /'
echo ""
echo "  To process: install SrumECmd then run:"
echo "    dotnet /opt/zimmermantools/SrumECmd.dll -f <SRUDB.dat> --csv <out_dir>"

# ════════════════════════════════════════════════════════════════════════════
section "G. Shell Bags — SBECmd"
# ════════════════════════════════════════════════════════════════════════════
# SBECmd reconstructs full folder path traversal history from UsrClass.dat.
# It goes deeper than the Kroll batch shell bag plugin and produces a single
# deduplicated timeline of every directory the user opened in Explorer.

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    users_dir="${drive_root}/Users"

    machine_header "${machine} (drive ${drive}:)"

    if [[ ! -d "${users_dir}" ]]; then
        status "MISSING" "${users_dir}"; continue
    fi

    while IFS= read -r usrcls; do
        username=$(echo "${usrcls}" | grep -oP '(?<=/Users/)[^/]+')

        if echo "${username}" | grep -qP "^(${SKIP_USERS})$"; then
            status "SKIP" "${username} (service/default account)"
            continue
        fi

        out_dir="${ANALYSIS_DIR}/${machine}/Registry/ShellBags/${username}"
        safe_user=$(echo "${username}" | tr ' ' '_')
        csv_prefix="${machine}_${drive}_${safe_user}_ShellBags"

        if csv_has_data "${out_dir}" "${csv_prefix}*.csv"; then
            status "SKIP" "${username} shell bags — CSV(s) with data already exist"; continue
        fi

        mkdir -p "${out_dir}"
        cmd="${SBECMD} -f '${usrcls}' --csv '${out_dir}' --csvf '${csv_prefix}' --nl"

        tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
        if [[ ${rc} -ne 0 ]]; then
            status "ERROR" "${username} — SBECmd exited ${rc}"; continue
        fi

        csv_count=$(find "${out_dir}" -maxdepth 1 -name "${csv_prefix}*.csv" 2>/dev/null | wc -l)
        entries=$(cat "${out_dir}"/${csv_prefix}*.csv 2>/dev/null | grep -c "^" || echo "?")
        status "OK" "${username} → ${csv_count} CSV(s), ~${entries} bag entries"
        log_cmd "${machine}" "SBECmd (Shell Bags — ${username}, drive ${drive}:)" \
            "${cmd}" \
            "Parse shell bags for ${username}: full folder traversal path history with timestamps" \
            "${out_dir}/${csv_prefix}_*.csv (${csv_count} files)" \
            "~${entries} shell bag entries"

    done < <(find "${users_dir}" -name "UsrClass.dat" \
                ! -path "*/ServiceProfiles/*" | sort)
done

# ════════════════════════════════════════════════════════════════════════════
section "H. RegBack Hives — RECmd + Kroll_Batch.reb (snapshot comparison)"
# ════════════════════════════════════════════════════════════════════════════
# RegBack contains Windows-managed backup copies of system hives. Processing
# them alongside live hives lets you spot persistence added or removed between
# the backup timestamp and collection time. Only present on server-class machines
# here (DC01, DC02, IIS, SVR01) — WS01/WS02 are Win10 which stopped auto-populating RegBack.

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    regback_dir="${drive_root}/Windows/System32/config/RegBack"
    out_dir="${ANALYSIS_DIR}/${machine}/Registry/RegBack"

    machine_header "${machine} (drive ${drive}:)"

    if [[ ! -d "${regback_dir}" ]]; then
        status "MISSING" "${regback_dir}"; continue
    fi

    populated=$(find "${regback_dir}" -maxdepth 1 -type f -size +0c 2>/dev/null | wc -l)
    if [[ ${populated} -eq 0 ]]; then
        status "EMPTY" "RegBack present but all hives are zero-byte (Win10 behaviour)"; continue
    fi

    if csv_has_data "${out_dir}" "${machine}_${drive}_RegBack*.csv"; then
        status "SKIP" "CSV(s) with data already exist"; continue
    fi

    mkdir -p "${out_dir}"
    cmd="${RECMD} --bn '${KROLL_BATCH}' -d '${regback_dir}' --csv '${out_dir}' --csvf '${machine}_${drive}_RegBack' --nl"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "RECmd exited ${rc}"; echo "${tool_out}" | sed 's/^/    /'; continue
    fi

    csv_count=$(find "${out_dir}" -maxdepth 1 -name "${machine}_${drive}_RegBack*.csv" 2>/dev/null | wc -l)
    status "OK" "${csv_count} CSV(s) → ${out_dir}  [${populated} hive(s) in RegBack]"
    log_cmd "${machine}" "RECmd + Kroll_Batch.reb (RegBack snapshot, drive ${drive}:)" \
        "${cmd}" \
        "Parse RegBack hive snapshot for comparison against live hives — surface persistence added/removed between backup and collection" \
        "${out_dir}/${machine}_${drive}_RegBack_*.csv (${csv_count} files)" \
        "${csv_count} batch CSVs from ${populated} RegBack hive(s)"
done

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════"
echo " Done. Registry output tree:"
find "${ANALYSIS_DIR}" -path "*/Registry/*" -name "*.csv" \
    | sort | awk -F/ '{print "  "$0}' | head -80
echo "════════════════════════════════════════════════════"
