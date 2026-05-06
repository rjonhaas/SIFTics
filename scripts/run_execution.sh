#!/usr/bin/env bash
# DAEDALUS:HANDLES win_sched_tasks win_ps_history
# DAEDALUS:DOMAIN windows_execution
# run_execution.sh — Phase 5: Server & execution-focused artifacts.
# Supplements Phase 2 (Amcache/ShimCache/BAM) for machines where prefetch
# is disabled (servers) and collects high-value execution evidence across
# all machines regardless of role.
#
# Sections:
#   A. IIS Access Logs   — iisGeolocate (auto-detected per machine)
#   B. HTTPERR Logs      — raw copy + line count (IIS machines only)
#   C. PowerShell History— ConsoleHost_history.txt collected per user
#   D. Scheduled Tasks   — XML inventory + suspicious task flagging (all machines)
#
# Output : analysis/<MACHINE>/Execution/{IIS,PowerShell,Tasks}/
# Logging: appends to analysis/commands.txt

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=audit_log.sh
source "${SCRIPT_DIR}/audit_log.sh"

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

IISGEO="dotnet /opt/zimmermantools/iisGeolocate/iisGeolocate.dll"
SKIP_USERS="Default|LocalService|NetworkService"

# ─── helpers ─────────────────────────────────────────────────────────────────

# log_cmd() provided by audit_log.sh

run_tool() {
    set +e; out=$(eval "$1" 2>&1); rc=$?; set -e
    echo "${out}"; return ${rc}
}

csv_has_data() {
    local dir="$1" pattern="${2:-*.csv}"
    [[ -d "${dir}" ]] || return 1
    while IFS= read -r f; do
        [[ $(wc -l < "${f}" 2>/dev/null) -gt 1 ]] && return 0
    done < <(find "${dir}" -maxdepth 3 -name "${pattern}" -size +100c 2>/dev/null)
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
echo " Execution Evidence Runner — jackofallhacks"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ════════════════════════════════════════════════════════════════════════════
section "A. IIS Access Logs — iisGeolocate"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')

    machine_header "${machine} (drive ${drive}:)"

    # Recursively find IIS log directories
    iis_log_dir=$(find "${drive_root}" -type d -ipath "*/LogFiles/W3SVC*" 2>/dev/null | head -1)

    if [[ -z "${iis_log_dir}" ]]; then
        status "SKIP" "No W3SVC log directory found — not an IIS machine or logs not collected"
        continue
    fi

    log_count=$(find "${iis_log_dir}" -name "*.log" 2>/dev/null | wc -l)
    if [[ ${log_count} -eq 0 ]]; then
        status "EMPTY" "W3SVC directory exists but contains no .log files"
        continue
    fi

    out_dir="${ANALYSIS_DIR}/${machine}/Execution/IIS"

    if csv_has_data "${out_dir}"; then
        status "SKIP" "CSV(s) with data already exist (${log_count} source logs)"
        continue
    fi

    mkdir -p "${out_dir}"
    cmd="${IISGEO} -d '${iis_log_dir}' --csv '${out_dir}'"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "iisGeolocate exited ${rc}"
        echo "${tool_out}" | sed 's/^/    /'
        continue
    fi

    csv_count=$(find "${out_dir}" -maxdepth 1 -name "*.csv" 2>/dev/null | wc -l)
    total_rows=$(find "${out_dir}" -maxdepth 1 -name "*.csv" -exec wc -l {} + 2>/dev/null \
                 | tail -1 | awk '{print $1}' || echo "?")
    status "OK" "${log_count} log file(s) → ${csv_count} CSV(s), ~${total_rows} request rows"
    log_cmd "${machine}" "iisGeolocate v2.2.0 (IIS access logs, drive ${drive}:)" \
        "${cmd}" \
        "Parse IIS W3C access logs with IP geolocation — HTTP method, URI, status, client IP, user-agent, geo country/city" \
        "${out_dir}/*.csv (${csv_count} files)" \
        "${log_count} log files, ~${total_rows} request rows"
done

# ════════════════════════════════════════════════════════════════════════════
section "B. HTTPERR Logs — raw copy"
# ════════════════════════════════════════════════════════════════════════════
# HTTPERR logs capture requests rejected at the HTTP.sys level before they
# reach IIS — exploit attempts that return 400/503 often only appear here.

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')

    machine_header "${machine} (drive ${drive}:)"

    httperr_dir="${drive_root}/Windows/System32/LogFiles/HTTPERR"
    out_dir="${ANALYSIS_DIR}/${machine}/Execution/IIS"

    if [[ ! -d "${httperr_dir}" ]]; then
        status "SKIP" "No HTTPERR directory"
        continue
    fi

    err_count=$(find "${httperr_dir}" -name "httperr*.log" 2>/dev/null | wc -l)
    if [[ ${err_count} -eq 0 ]]; then
        status "EMPTY" "HTTPERR directory exists but no logs found"
        continue
    fi

    if [[ -f "${out_dir}/httperr_collected" ]]; then
        status "SKIP" "Already collected"
        continue
    fi

    mkdir -p "${out_dir}"
    find "${httperr_dir}" -name "httperr*.log" -exec cp {} "${out_dir}/" \; 2>/dev/null
    touch "${out_dir}/httperr_collected"

    total_lines=$(cat "${out_dir}"/httperr*.log 2>/dev/null | grep -vc "^#" || echo "?")
    status "OK" "${err_count} HTTPERR log(s) copied → ${total_lines} request lines"
    log_cmd "${machine}" "HTTPERR log copy (drive ${drive}:)" \
        "cp ${httperr_dir}/httperr*.log ${out_dir}/" \
        "Collect HTTP.sys error logs for requests rejected before reaching IIS (exploit attempts, malformed requests)" \
        "${out_dir}/httperr*.log" \
        "${err_count} files, ${total_lines} request lines"
done

# ════════════════════════════════════════════════════════════════════════════
section "C. PowerShell History — ConsoleHost_history.txt"
# ════════════════════════════════════════════════════════════════════════════
# PSReadLine history captures every interactive command typed at a PS prompt.
# Not affected by transcription or script block logging policy — always present
# if the user ran PowerShell interactively, even once.

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    out_dir="${ANALYSIS_DIR}/${machine}/Execution/PowerShell"

    machine_header "${machine} (drive ${drive}:)"

    while IFS= read -r hist_file; do
        username=$(echo "${hist_file}" | grep -oP '(?<=/Users/)[^/]+')

        if echo "${username}" | grep -qP "^(${SKIP_USERS})$"; then
            continue
        fi

        dest="${out_dir}/${username}_ConsoleHost_history.txt"

        if [[ -f "${dest}" ]]; then
            status "SKIP" "${username} — already collected"
            continue
        fi

        mkdir -p "${out_dir}"
        cp "${hist_file}" "${dest}"
        line_count=$(wc -l < "${dest}" 2>/dev/null || echo "?")
        status "OK" "${username} — ${line_count} commands"
        log_cmd "${machine}" "PowerShell ConsoleHost history (${username}, drive ${drive}:)" \
            "cp '${hist_file}' '${dest}'" \
            "Collect interactive PowerShell command history for ${username} (PSReadLine — not affected by logging policy)" \
            "${dest}" \
            "${line_count} commands"

    done < <(find "${drive_root}/Users" -name "ConsoleHost_history.txt" \
                ! -path "*/ServiceProfiles/*" 2>/dev/null | sort)

    # Report if nothing found
    hist_count=$(find "${drive_root}/Users" -name "ConsoleHost_history.txt" \
                    ! -path "*/ServiceProfiles/*" 2>/dev/null | wc -l)
    if [[ ${hist_count} -eq 0 ]]; then
        status "NONE" "No ConsoleHost_history.txt files found"
    fi
done

# ════════════════════════════════════════════════════════════════════════════
section "D. Scheduled Tasks — XML inventory + suspicious task flagging"
# ════════════════════════════════════════════════════════════════════════════
# Task XML files are the ground truth for what a task will execute — the
# registry TaskCache only stores a subset. Non-Microsoft tasks and tasks
# referencing temp/appdata paths or LOLBins are flagged automatically.

TASK_PARSER=$(mktemp /tmp/parse_tasks_XXXXXX.py)
trap 'rm -f "${TASK_PARSER}"' EXIT

cat > "${TASK_PARSER}" << 'PYEOF'
import os, csv, sys, xml.etree.ElementTree as ET

NS = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}

SUSPICIOUS_EXES = {
    'powershell','powershell_ise','pwsh','cmd','wscript','cscript','mshta',
    'rundll32','regsvr32','certutil','bitsadmin','msiexec','regasm',
    'installutil','msbuild','cmstp','wmic','forfiles','schtasks','at',
    'pcalua','bash','curl','wget','ftp','tftp','nc','ncat','netcat'
}
SUSPICIOUS_PATHS = {
    '\\temp\\','\\tmp\\','\\appdata\\roaming\\','\\appdata\\local\\temp',
    '\\programdata\\','\\users\\public\\','%temp%','%tmp%','%appdata%',
    '%public%','%programdata%'
}

tasks_dir, out_all, out_flagged, machine = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
FIELDS = ['Machine','URI','TaskPath','Author','RegDate','Description',
          'Command','Arguments','Triggers','RunAs','RunLevel',
          'IsMicrosoft','Flags']

rows = []
for root_dir, dirs, files in os.walk(tasks_dir):
    for fname in files:
        fpath = os.path.join(root_dir, fname)
        rel   = '\\' + os.path.relpath(fpath, tasks_dir).replace('/', '\\')
        row   = dict.fromkeys(FIELDS, '')
        row.update({'Machine': machine, 'TaskPath': fpath, 'URI': rel})

        try:
            for enc in ('utf-16', 'utf-8-sig', 'utf-8'):
                try:
                    with open(fpath, 'r', encoding=enc) as f:
                        content = f.read()
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue
            else:
                raise ValueError("Could not decode file")

            tree = ET.fromstring(content)
            get  = lambda path: (tree.findtext(path, namespaces=NS) or '').strip()

            row['URI']         = get('t:RegistrationInfo/t:URI') or rel
            row['Author']      = get('t:RegistrationInfo/t:Author')
            row['RegDate']     = get('t:RegistrationInfo/t:Date')
            row['Description'] = get('t:RegistrationInfo/t:Description')
            row['Command']     = get('.//t:Exec/t:Command')
            row['Arguments']   = get('.//t:Exec/t:Arguments')
            row['RunAs']       = get('.//t:Principal/t:UserId')
            row['RunLevel']    = get('.//t:Principal/t:RunLevel')

            triggers = [t.tag.split('}')[-1]
                        for t in tree.findall('.//t:Triggers/*', NS)]
            row['Triggers'] = ','.join(triggers)

            is_ms = '\\Microsoft\\' in row['URI']
            row['IsMicrosoft'] = str(is_ms)

            flags = []
            if not is_ms:
                flags.append('NON-MICROSOFT')

            cmd_lower = (row['Command'] + ' ' + row['Arguments']).lower()
            exe = os.path.basename(row['Command']).lower().replace('.exe','')
            if exe in SUSPICIOUS_EXES:
                flags.append(f'LOLBIN:{exe}')
            if any(p in cmd_lower for p in SUSPICIOUS_PATHS):
                flags.append('SUSPICIOUS-PATH')
            if row['RunLevel'] == 'HighestAvailable' and not is_ms:
                flags.append('ELEVATED')
            if any(t in row['Triggers'] for t in ('LogonTrigger','RegistrationTrigger')):
                if not is_ms:
                    flags.append('PERSISTENCE-TRIGGER')

            row['Flags'] = '|'.join(flags)

        except Exception as e:
            row['Flags'] = f'PARSE-ERROR:{e}'

        rows.append(row)

def write_csv(path, data):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(data)

write_csv(out_all, rows)
flagged = [r for r in rows if r['Flags'] and 'PARSE-ERROR' not in r['Flags']]
write_csv(out_flagged, flagged)
print(f"{len(rows)} tasks parsed, {len(flagged)} flagged")
PYEOF

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    tasks_dir="${drive_root}/Windows/System32/Tasks"
    out_dir="${ANALYSIS_DIR}/${machine}/Execution/Tasks"
    csv_all="${out_dir}/${machine}_${drive}_Tasks_All.csv"
    csv_flagged="${out_dir}/${machine}_${drive}_Tasks_Flagged.csv"

    machine_header "${machine} (drive ${drive}:)"

    if [[ ! -d "${tasks_dir}" ]]; then
        status "MISSING" "${tasks_dir}"
        continue
    fi

    task_count=$(find "${tasks_dir}" -type f 2>/dev/null | wc -l)

    if csv_has_data "${out_dir}" "${machine}_${drive}_Tasks_All.csv"; then
        status "SKIP" "CSV with data already exists (${task_count} source tasks)"
        continue
    fi

    mkdir -p "${out_dir}"
    cmd="python3 ${TASK_PARSER} '${tasks_dir}' '${csv_all}' '${csv_flagged}' '${machine}'"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "Task parser exited ${rc}"
        echo "${tool_out}" | sed 's/^/    /'
        continue
    fi

    flagged_count=$(grep -c "^" "${csv_flagged}" 2>/dev/null || echo "?")
    flagged_count=$(( flagged_count - 1 ))   # subtract header
    status "OK" "${tool_out} | flagged → ${csv_flagged##*/}"
    log_cmd "${machine}" "Scheduled Task XML parser (drive ${drive}:)" \
        "${cmd}" \
        "Inventory all scheduled task XML files; flag non-Microsoft tasks, LOLBin commands, suspicious paths, persistence triggers" \
        "${csv_all} + ${csv_flagged}" \
        "${tool_out}"

    # Print flagged task summary to console
    if [[ ${flagged_count} -gt 0 ]] && [[ -f "${csv_flagged}" ]]; then
        echo ""
        echo "  ┌─ FLAGGED TASKS (${machine}) ─────────────────────────────────"
        python3 - "${csv_flagged}" << 'PYEOF'
import csv, sys
with open(sys.argv[1], encoding='utf-8') as f:
    for row in csv.DictReader(f):
        print(f"  │  [{row['Flags']}]")
        print(f"  │    URI     : {row['URI']}")
        print(f"  │    Command : {row['Command']} {row['Arguments']}")
        print(f"  │    RunAs   : {row['RunAs']}  Triggers: {row['Triggers']}")
        print(f"  │")
PYEOF
        echo "  └────────────────────────────────────────────────────────────"
    fi
done

echo ""
echo "════════════════════════════════════════════════════"
echo " Done. Execution output:"
find "${ANALYSIS_DIR}" -path "*/Execution/*" \( -name "*.csv" -o -name "*.txt" \) \
    | sort | awk '{print "  "$0}'
echo "════════════════════════════════════════════════════"
