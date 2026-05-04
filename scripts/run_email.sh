#!/usr/bin/env bash
# DAEDALUS:HANDLES email_ost email_pst email_mbox
# run_email.sh — Phase 14: Email Artifact Parsing (PST/OST via readpst)
#
# Sections:
#   E. PST/OST → mbox (readpst) → Python message & attachment parser
#
# Output : analysis/<MACHINE>/Email/
# Logging: appends to analysis/commands.txt

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CASE_ROOT="${1:-${CASE_ROOT:-}}"
if [[ -z "$CASE_ROOT" ]]; then
    read -rp "Case root directory (e.g. /cases/jack2): " CASE_ROOT
fi
[[ -d "$CASE_ROOT" ]] || { echo "ERROR: CASE_ROOT '${CASE_ROOT}' does not exist." >&2; exit 1; }
export CASE_ROOT
ANALYSIS_DIR="${CASE_ROOT}/analysis"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")

READPST="/usr/bin/readpst"
PARSE_EMAIL="${SCRIPT_DIR}/parse_email.py"

SKIP_USERS="Default|LocalService|NetworkService|DefaultAccount|WDAGUtilityAccount"

# ─── helpers ────────────────────────────────────────────────────────────────

log_cmd() {
    local machine="$1" tool="$2" cmd="$3" purpose="$4" output="$5" result="$6"
    cat >> "${COMMAND_LOG}" <<EOF

[${TIMESTAMP}] ${machine} | ${tool} | Email
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

# ─── discover drive roots ────────────────────────────────────────────────────

mapfile -t DRIVE_ROOTS < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name '$MFT' -print \
    | sort | xargs -I{} dirname {}
)

echo "════════════════════════════════════════════════════"
echo " Email Artifact Parsing — Phase 14"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ─── pre-flight ──────────────────────────────────────────────────────────────

if [[ ! -x "${READPST}" ]]; then
    echo "  ERROR: readpst not found at ${READPST} — install libpst and retry"
    exit 1
fi

if [[ ! -f "${PARSE_EMAIL}" ]]; then
    echo "  ERROR: parse_email.py not found at ${PARSE_EMAIL}"
    exit 1
fi

# ════════════════════════════════════════════════════════════════════════════
section "E. PST/OST Email Parsing"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    out_dir="${ANALYSIS_DIR}/${machine}/Email"

    machine_header "${machine} (drive ${drive}:)"

    # Find all OST and PST files under this drive root
    mapfile -t pst_files < <(
        find "${drive_root}" \( -iname "*.ost" -o -iname "*.pst" \) 2>/dev/null | sort
    )

    if [[ ${#pst_files[@]} -eq 0 ]]; then
        status "MISSING" "No .ost / .pst files found under ${drive_root}"
        continue
    fi

    status "INFO" "${#pst_files[@]} PST/OST file(s) found"

    for pst_path in "${pst_files[@]}"; do
        # Extract username from path (component after /Users/)
        if echo "${pst_path}" | grep -q "/Users/"; then
            username=$(echo "${pst_path}" | sed "s|${drive_root}/Users/||" | cut -d'/' -f1)
        else
            username=$(basename "${pst_path}" | sed 's/\.[^.]*$//')
        fi

        # Skip system accounts
        if echo "${username}" | grep -qE "^(${SKIP_USERS})$"; then
            status "SKIP" "${username} (system account)"
            continue
        fi

        pst_basename=$(basename "${pst_path}")
        msg_csv="${out_dir}/${machine}_E_${username}_Email_Messages.csv"
        att_csv="${out_dir}/${machine}_E_${username}_Email_Attachments.csv"
        mbox_dir="${out_dir}/${username}/mbox"
        attach_dir="${out_dir}/${username}/attachments"

        # Skip if output already exists with data
        if [[ -f "${msg_csv}" ]] && [[ $(wc -l < "${msg_csv}" 2>/dev/null) -gt 1 ]]; then
            rows=$(( $(wc -l < "${msg_csv}") - 1 ))
            status "SKIP" "${username}/${pst_basename} already parsed (${rows} message rows)"
            continue
        fi

        mkdir -p "${mbox_dir}" "${attach_dir}"

        # Run readpst: -D includes deleted items, -w overwrites existing, -q suppresses progress
        readpst_cmd="${READPST} -D -w -q -o '${mbox_dir}' '${pst_path}'"
        readpst_out=$(run_tool "${readpst_cmd}") && rp_rc=0 || rp_rc=$?

        mbox_count=$(find "${mbox_dir}" -name "*.mbox" 2>/dev/null | wc -l)

        if [[ ${rp_rc} -ne 0 ]] || [[ ${mbox_count} -eq 0 ]]; then
            status "ERROR" "readpst failed (rc=${rp_rc}) or produced no .mbox files"
            [[ -n "${readpst_out}" ]] && echo "${readpst_out}" | head -5 | sed 's/^/    /'
            continue
        fi

        status "OK" "readpst: ${mbox_count} folder(s) from ${pst_basename}"

        log_cmd "${machine}" "readpst (libpst)" \
            "${readpst_cmd}" \
            "Convert ${pst_basename} PST/OST to mbox format (deleted items included)" \
            "${mbox_dir}/" \
            "rc=${rp_rc}, ${mbox_count} .mbox files"

        # Parse mbox files with Python
        parse_cmd="python3 '${PARSE_EMAIL}' '${mbox_dir}' '${machine}' '${username}' '${msg_csv}' '${att_csv}' '${attach_dir}'"
        parse_out=$(run_tool "${parse_cmd}") && py_rc=0 || py_rc=$?

        if [[ ${py_rc} -ne 0 ]]; then
            status "ERROR" "parse_email.py exited ${py_rc}"
            echo "${parse_out}" | sed 's/^/    /'
            continue
        fi

        # Output line is "msg_rows,att_rows"
        result_line=$(echo "${parse_out}" | tail -1)
        msg_rows=$(echo "${result_line}" | cut -d',' -f1)
        att_rows=$(echo "${result_line}" | cut -d',' -f2)

        [[ "${msg_rows}" == "0" ]] && rm -f "${msg_csv}"
        [[ "${att_rows}" == "0" ]] && rm -f "${att_csv}"

        status "OK" "${username}: ${msg_rows} messages, ${att_rows} attachments"

        log_cmd "${machine}" "parse_email.py" \
            "${parse_cmd}" \
            "Parse mbox messages, extract IOCs (URLs/IPs/coords/base64), hash attachments" \
            "${msg_csv}, ${att_csv}, ${attach_dir}/" \
            "${msg_rows} messages, ${att_rows} attachments"

        # Highlight high-value findings inline
        if [[ -f "${msg_csv}" ]]; then
            b64_hits=$(awk -F',' 'NR>1 && $14!=""' "${msg_csv}" 2>/dev/null | wc -l || echo 0)
            coord_hits=$(awk -F',' 'NR>1 && $13!=""' "${msg_csv}" 2>/dev/null | wc -l || echo 0)
            [[ "${b64_hits}" -gt 0 ]]   && status "ALERT" "${b64_hits} message(s) contain decoded base64 strings"
            [[ "${coord_hits}" -gt 0 ]] && status "ALERT" "${coord_hits} message(s) contain geographic coordinates"
        fi
    done
done

# ════════════════════════════════════════════════════════════════════════════
section "Summary"
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "Email output:"

total_msg=0
total_att=0

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    email_dir="${ANALYSIS_DIR}/${machine}/Email"
    [[ -d "${email_dir}" ]] || continue

    while IFS= read -r f; do
        [[ -f "${f}" ]] || continue
        r=$(( $(wc -l < "${f}") - 1 ))
        printf "  %-6s  Messages (%d rows):  %s\n" "${machine}" "${r}" "${f}"
        total_msg=$(( total_msg + r ))
    done < <(find "${email_dir}" -maxdepth 1 -name "*_E_*_Email_Messages.csv" 2>/dev/null | sort)

    while IFS= read -r f; do
        [[ -f "${f}" ]] || continue
        r=$(( $(wc -l < "${f}") - 1 ))
        printf "  %-6s  Attachments (%d rows):  %s\n" "${machine}" "${r}" "${f}"
        total_att=$(( total_att + r ))
    done < <(find "${email_dir}" -maxdepth 1 -name "*_E_*_Email_Attachments.csv" 2>/dev/null | sort)
done

echo ""
echo "  Totals:"
echo "    Email message rows  : ${total_msg}"
echo "    Attachment rows     : ${total_att}"
echo ""
echo " Phase 14 complete — $(date -u)"
