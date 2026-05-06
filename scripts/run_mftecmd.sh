#!/usr/bin/env bash
# DAEDALUS:HANDLES win_mft
# DAEDALUS:DOMAIN windows_filesystem
# run_mftecmd.sh — Parse NTFS artifacts ($MFT, $Boot, $LogFile, $J) for every
# machine under the case root. Outputs one CSV per artifact per machine to
# analysis/<MACHINE>/. Skips artifacts that are absent or already processed.

set -euo pipefail

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
MFTECMD="dotnet /opt/zimmermantools/MFTECmd.dll"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")

# Artifact definitions: <relative-path-from-drive-root>|<label>|<purpose>
ARTIFACTS=(
    "\$MFT|MFT|Parse Master File Table for full filesystem record and timestamps"
    "\$Boot|Boot|Parse boot sector for volume serial number and partition geometry"
    "\$LogFile|LogFile|Parse NTFS transaction log for recent metadata operations"
    "\$Extend/\$J|J|Parse USN Change Journal for file create/delete/rename history"
)

# log_command — wrapper preserving artifact-in-tool-name format; delegates to audit_log.sh
log_command() {
    audit_log_entry "$1" "MFTECmd v1.3.0.0 ($2) | EZ Tools" "$3" "$4" "$5" "$6" "0"
}

echo "========================================"
echo " MFTECmd NTFS Artifact Batch Runner"
echo " Case: jackofallhacks"
echo " $(date -u)"
echo "========================================"
echo ""

# Iterate over drive roots located by finding $MFT files
while IFS= read -r mft_path; do

    drive_root=$(dirname "${mft_path}")
    machine=$(echo "${mft_path}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${mft_path}"   | grep -oP '(?<=/)[A-Z](?=/\$MFT)')
    out_dir="${ANALYSIS_DIR}/${machine}"

    echo "----------------------------------------"
    echo " Machine: ${machine}  Drive: ${drive}:"
    echo " Root   : ${drive_root}"
    echo "----------------------------------------"

    mkdir -p "${out_dir}"

    for artifact_def in "${ARTIFACTS[@]}"; do
        rel_path=$(echo "${artifact_def}" | cut -d'|' -f1)
        label=$(echo "${artifact_def}"    | cut -d'|' -f2)
        purpose=$(echo "${artifact_def}"  | cut -d'|' -f3)

        src="${drive_root}/${rel_path}"
        csv_name="${machine}_${drive}_${label}.csv"
        csv_path="${out_dir}/${csv_name}"

        printf "  [%-7s] " "${label}"

        if [[ ! -f "${src}" ]]; then
            echo "MISSING — ${src}"
            continue
        fi

        if [[ -f "${csv_path}" ]]; then
            echo "SKIP    — CSV exists: ${csv_name}"
            continue
        fi

        cmd="${MFTECMD} -f '${src}' --csv '${out_dir}' --csvf '${csv_name}'"

        set +e
        tool_out=$(eval "${cmd}" 2>&1)
        exit_code=$?
        set -e

        if [[ ${exit_code} -ne 0 ]]; then
            echo "ERROR   — MFTECmd exited ${exit_code}"
            echo "${tool_out}" | sed 's/^/             /'
            continue
        fi

        csv_size=$(du -h "${csv_path}" 2>/dev/null | cut -f1 || echo "?")
        stats=$(echo "${tool_out}" | grep -oP '(FILE records found|Entries found): [\d,]+[^\n]*' \
                || echo "OK")

        echo "OK      — ${csv_name} (${csv_size})  ${stats}"

        log_command \
            "${machine}" \
            "${label} (drive ${drive}:)" \
            "${cmd}" \
            "${purpose} (drive ${drive}:)" \
            "${csv_path} (${csv_size})" \
            "${stats}"
    done

    echo ""

done < <(find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name '$MFT' -print | sort)

echo "========================================"
echo " Done. Output summary:"
ls -lh "${ANALYSIS_DIR}"/*/*.csv 2>/dev/null || true
echo "========================================"
