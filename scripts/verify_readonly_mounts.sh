#!/usr/bin/env bash
# verify_readonly_mounts.sh — SIFTics pre-flight check
# Verifies that all evidence-related mounts are read-only before analysis tools run.
#
# Usage:
#   bash verify_readonly_mounts.sh <CASE_ROOT>
#   CASE_ROOT=/cases/mycase bash verify_readonly_mounts.sh
#
# Exit codes:
#   0 — all evidence mounts are read-only (or no mounts found)
#   1 — one or more evidence mounts are read-write (VIOLATION)
#   2 — usage error

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve CASE_ROOT
# ---------------------------------------------------------------------------
if [[ $# -ge 1 ]]; then
    CASE_ROOT="$1"
elif [[ -n "${CASE_ROOT:-}" ]]; then
    : # already set in environment
else
    echo "ERROR: CASE_ROOT not provided." >&2
    echo "Usage: bash verify_readonly_mounts.sh <CASE_ROOT>" >&2
    exit 2
fi

# Strip trailing slash for consistent prefix matching
CASE_ROOT="${CASE_ROOT%/}"

# ---------------------------------------------------------------------------
# Baseline evidence prefixes (always checked)
# ---------------------------------------------------------------------------
BASELINE_PREFIXES=( "/mnt/" "/media/" "/cases/" )

# ---------------------------------------------------------------------------
# Parse CLAUDE.md evidence inventory for additional paths
# ---------------------------------------------------------------------------
CLAUDE_MD="${CASE_ROOT}/CLAUDE.md"
declare -a EXTRA_PREFIXES=()

if [[ -f "${CLAUDE_MD}" ]]; then
    # Extract absolute paths from markdown table rows.
    # Match lines that contain a cell with a path starting with /
    # Handles formats like:  | label | /cases/foo/img.E01 | ...
    # or                     | /cases/foo/img.E01 | label | ...
    while IFS= read -r line; do
        # Extract every pipe-delimited cell and look for paths starting with /
        # Replace | with newlines, then grep for cells that look like paths
        while IFS= read -r cell; do
            # Trim leading/trailing whitespace
            cell="$(echo "${cell}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            # Accept if cell starts with / and contains no spaces after the path
            # (paths may have spaces but we accept them; we just need the leading /)
            if [[ "${cell}" =~ ^(/[^[:space:]|]+) ]]; then
                extracted_path="${BASH_REMATCH[1]}"
                # Only keep if it looks like an absolute path (at least one component)
                if [[ "${extracted_path}" =~ ^/[a-zA-Z0-9._/-] ]]; then
                    EXTRA_PREFIXES+=( "${extracted_path}" )
                fi
            fi
        done < <(echo "${line}" | tr '|' '\n')
    done < <(grep -E '^\s*\|' "${CLAUDE_MD}" || true)

    if [[ ${#EXTRA_PREFIXES[@]} -gt 0 ]]; then
        echo "INFO: Extracted ${#EXTRA_PREFIXES[@]} evidence path(s) from ${CLAUDE_MD}"
    else
        echo "INFO: No evidence paths found in ${CLAUDE_MD}; using baseline prefixes only."
    fi
else
    echo "INFO: ${CLAUDE_MD} not found; using baseline prefixes only."
fi

# ---------------------------------------------------------------------------
# Helper: check whether a mount point is covered by our evidence prefixes
# ---------------------------------------------------------------------------
is_evidence_mount() {
    local mp="$1"
    # Normalise: ensure trailing slash so prefix matching is exact
    local mp_slash="${mp%/}/"

    # Check baseline prefixes
    for prefix in "${BASELINE_PREFIXES[@]}"; do
        if [[ "${mp_slash}" == "${prefix}"* || "${mp}" == "${prefix%/}" ]]; then
            return 0
        fi
    done

    # Check paths from CLAUDE.md: the mount point either equals the path or
    # the path lives under the mount point (mount point is a prefix of path)
    # — and also the reverse: path is a prefix of mount point.
    for epath in "${EXTRA_PREFIXES[@]}"; do
        local epath_slash="${epath%/}/"
        # Mount point is the evidence path or a parent of it
        if [[ "${epath_slash}" == "${mp_slash}"* ]]; then
            return 0
        fi
        # Mount point equals the evidence path (exact)
        if [[ "${mp}" == "${epath}" ]]; then
            return 0
        fi
        # Evidence path is under this mount point
        if [[ "${epath_slash}" == "${mp_slash}"* ]]; then
            return 0
        fi
    done

    return 1
}

# ---------------------------------------------------------------------------
# Helper: check whether "rw" appears as a standalone mount option
# ---------------------------------------------------------------------------
has_rw_option() {
    local options="$1"
    # Split on commas and check for exact "rw" token
    IFS=',' read -ra opts <<< "${options}"
    for opt in "${opts[@]}"; do
        if [[ "${opt}" == "rw" ]]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Parse /proc/mounts and evaluate each mount point
# ---------------------------------------------------------------------------
MOUNTS_CHECKED=0
VIOLATIONS=0
declare -a VIOLATION_LIST=()

while IFS=' ' read -r device mountpoint fstype options _rest; do
    # Skip comment lines or malformed lines
    [[ "${device}" == \#* ]] && continue
    [[ -z "${mountpoint}" ]] && continue

    if is_evidence_mount "${mountpoint}"; then
        MOUNTS_CHECKED=$(( MOUNTS_CHECKED + 1 ))

        if has_rw_option "${options}"; then
            echo "ERROR: READ-WRITE MOUNT DETECTED — ${mountpoint} (options: ${options})"
            VIOLATIONS=$(( VIOLATIONS + 1 ))
            VIOLATION_LIST+=( "${mountpoint}" )
        else
            echo "OK:    ${mountpoint} is read-only (options: ${options})"
        fi
    fi
done < /proc/mounts

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "--- Mount Verification Summary ---"

if [[ ${MOUNTS_CHECKED} -eq 0 ]]; then
    echo "WARNING: No evidence-related mounts found under checked prefixes."
    echo "         Evidence may not be mounted yet. Proceeding without enforcement."
    exit 0
fi

if [[ ${VIOLATIONS} -eq 0 ]]; then
    echo "PASS: ${MOUNTS_CHECKED} mount(s) checked — all read-only."
    exit 0
else
    echo "FAIL: ${MOUNTS_CHECKED} mount(s) checked — ${VIOLATIONS} mount(s) are READ-WRITE (VIOLATION):"
    for v in "${VIOLATION_LIST[@]}"; do
        echo "      - ${v}"
    done
    exit 1
fi
