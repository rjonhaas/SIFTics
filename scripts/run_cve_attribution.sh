#!/usr/bin/env bash
# DAEDALUS:HANDLES cve_attribution
# DAEDALUS:DOMAIN intel_cve
# run_cve_attribution.sh — Phase 16 (Intel ICS): CVE Attribution
#
# Reads investigation_report.md + cop.md, calls the claude CLI with a
# focused CVE attribution system prompt, and writes cve_attribution.md.
#
# Prerequisites:
#   - investigation_report.md must exist in <CASE_ROOT>/reports/
#   - cop.md must exist in <CASE_ROOT>/analysis/
#   - claude CLI must be in PATH (or set CLAUDE_BIN)
#
# Usage:
#   bash run_cve_attribution.sh /cases/my-case
#   CASE_ROOT=/cases/my-case bash run_cve_attribution.sh
#
# After completion, re-run the investigation-report skill to integrate
# cve_attribution.md as Section 3B of the investigation report.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=audit_log.sh
source "${SCRIPT_DIR}/audit_log.sh"

# ── Resolve CASE_ROOT ────────────────────────────────────────────────────────
SKIP_VALIDATION=0
for arg in "$@"; do
    [[ "$arg" == "--skip-validation" ]] && SKIP_VALIDATION=1
done

CASE_ROOT="${1:-${CASE_ROOT:-}}"
# Strip --skip-validation from positional args
set -- "${@/--skip-validation/}"
if [[ -z "$CASE_ROOT" ]]; then
    read -rp "Case root directory (e.g. /cases/my-case): " CASE_ROOT
fi
[[ -d "$CASE_ROOT" ]] || { echo "ERROR: CASE_ROOT '${CASE_ROOT}' does not exist." >&2; exit 1; }
export CASE_ROOT

ANALYSIS_DIR="${CASE_ROOT}/analysis"
REPORT_DIR="${CASE_ROOT}/reports"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
MODEL="${CVE_MODEL:-claude-sonnet-4-6}"

mkdir -p "${ANALYSIS_DIR}"

# ── Locate inputs ────────────────────────────────────────────────────────────
REPORT_MD=""
if [[ -f "${REPORT_DIR}/investigation_report.md" ]]; then
    REPORT_MD="${REPORT_DIR}/investigation_report.md"
else
    REPORT_MD=$(find "${REPORT_DIR}" -name "investigation_report*.md" 2>/dev/null | sort | tail -1 || true)
fi

COP_MD="${ANALYSIS_DIR}/cop.md"
OUTPUT_MD="${ANALYSIS_DIR}/cve_attribution.md"

echo "========================================"
echo " CVE Attribution — Phase 16 (Intel ICS)"
echo " Case: $(basename "${CASE_ROOT}")"
echo " $(date -u)"
echo "========================================"
echo ""

# ── Preflight checks ─────────────────────────────────────────────────────────
if [[ -z "$REPORT_MD" ]] || [[ ! -f "$REPORT_MD" ]]; then
    echo "ERROR: investigation_report.md not found in ${REPORT_DIR}" >&2
    echo "       Run the investigation-report skill first." >&2
    exit 1
fi

if [[ ! -f "$COP_MD" ]]; then
    echo "ERROR: cop.md not found at ${COP_MD}" >&2
    exit 1
fi

if ! command -v "$CLAUDE_BIN" &>/dev/null; then
    echo "ERROR: claude CLI not found. Add to PATH or set CLAUDE_BIN=/path/to/claude" >&2
    exit 1
fi

# ── Skip guard ───────────────────────────────────────────────────────────────
if [[ -f "$OUTPUT_MD" ]] && [[ $(wc -l < "$OUTPUT_MD") -gt 10 ]]; then
    CVE_COUNT=$(grep -c "^#### CVE-" "$OUTPUT_MD" 2>/dev/null || echo "?")
    echo "SKIP — ${OUTPUT_MD} already exists (${CVE_COUNT} CVE(s))"
    echo "       Delete it to re-run: rm ${OUTPUT_MD}"
    exit 0
fi

# ── System prompt ────────────────────────────────────────────────────────────
read -r -d '' SYSTEM_PROMPT << 'SYSTEM_END' || true
You are the CVE Attribution Analyst in the Intel ICS function of a DFIR workflow. You receive a completed DFIR investigation report and Common Operating Picture (COP) produced by the SIFTics forensic triage pipeline.

Your job is to identify any CVEs that were likely exploited based on the evidence documented in the report. You work from the evidence record only — do not hallucinate findings that are not present in the documents.

INSTRUCTIONS:

1. Read the entire report and COP carefully.

2. Look for exploitation indicators including but not limited to:
   - Software names and version numbers: installer filenames, browser notifier URLs (e.g. notifier.win-rar.com/?version=611), LNK targets, process command lines, KAPE collection paths with version directories
   - Process tree anomalies: archive handlers (WinRAR, 7z) spawning cmd/wscript/powershell; web servers spawning shells; office apps spawning interpreters; browsers spawning cmd
   - File creation patterns: folder names with trailing spaces inside archives, double extensions (file.pdf .cmd), DLLs in spool paths, webshells in wwwroot, executables in temp paths with random names
   - Network patterns: JNDI strings, default framework ports (4444, 50050), template injection in URLs
   - Registry and scheduled task patterns associated with known exploit chains

3. For each CVE you identify, provide the structured output below.

4. IMPORTANT GUIDELINES:
   - Do NOT filter by CVSS score — low-severity CVEs chained with other activity are still worth attributing.
   - Do NOT limit to well-known CVEs. If evidence matches a lesser-known vulnerability, include it.
   - If behaviour is consistent with a class of vulnerabilities but you cannot identify a specific CVE, state the CWE class instead. Example: "Consistent with CWE-78 (OS Command Injection) in the HTTP file server; specific CVE cannot be determined without exact version."
   - If a CVE affects a specific version range and the report documents the version, explicitly state whether the observed version falls within the affected range.
   - If the report already names a CVE, confirm it and add supporting evidence.
   - Check for MULTIPLE CVEs — an attack chain may exploit more than one vulnerability.
   - Confidence is High ONLY when: (a) software version is confirmed in the evidence AND (b) the exploitation mechanism matches the CVE. Use Moderate when version is not confirmed. Use Low when the pattern is suggestive but circumstantial.

5. Respond ONLY with the structured markdown output below. No preamble, no trailing commentary.

OUTPUT FORMAT — use this exact structure:

---

## CVE Attribution Analysis (Intel ICS)

**Analyst:** CVE Attribution Skill (Intel ICS)
**Input:** investigation_report.md, cop.md
**Generated:** [current UTC timestamp — use real date/time]
**Case:** [case name extracted from the report's h1 heading]

### Attributed CVEs

#### CVE-YYYY-NNNNN — [Title]

| Field | Value |
|-------|-------|
| CVE ID | CVE-YYYY-NNNNN |
| Affected Software | [software name] [version observed in evidence] |
| Affected Version Range | [from CVE advisory] |
| CVSS Score | [base score or "Not determined"] |
| Confidence | High / Moderate / Low |
| MITRE ATT&CK | T####.### — [technique name] |

**Evidence from report:**
- [Specific finding with section reference]
- [Additional supporting evidence with section reference]

**Attribution rationale:**
[2–3 sentences: why this CVE matches the observed behaviour, what the exploitation mechanism was, how it maps to the CVE description]

**Confirming evidence needed:**
[What additional artifact would raise confidence, or "Version confirmed in evidence — no additional evidence required" for High]

---

[Repeat block for each attributed CVE]

### CVE-Adjacent Observations

[Findings consistent with exploitation but not tied to a specific CVE. State CWE class if identifiable. If none: "No additional CVE-adjacent observations."]

---
SYSTEM_END

# ── Build user prompt ────────────────────────────────────────────────────────
PROMPT_FILE=$(mktemp /tmp/cve_attr_XXXXXX.txt)
trap 'rm -f "$PROMPT_FILE"' EXIT

{
    echo "The following are the investigation report and COP for the case you must analyse."
    echo ""
    echo "=== INVESTIGATION REPORT ==="
    echo ""
    cat "$REPORT_MD"
    echo ""
    echo "=== COMMON OPERATING PICTURE ==="
    echo ""
    cat "$COP_MD"
} > "$PROMPT_FILE"

PROMPT_BYTES=$(wc -c < "$PROMPT_FILE")
REPORT_LINES=$(wc -l < "$REPORT_MD")
COP_LINES=$(wc -l < "$COP_MD")

echo "  Report:       ${REPORT_MD} (${REPORT_LINES} lines)"
echo "  COP:          ${COP_MD} (${COP_LINES} lines)"
echo "  Prompt size:  ${PROMPT_BYTES} bytes"
echo "  Model:        ${MODEL}"
echo ""
echo "  Running CVE attribution (this may take 30–90 seconds)..."

# ── Invoke claude ─────────────────────────────────────────────────────────────
START_TIME=$(date +%s)

set +e
"$CLAUDE_BIN" --print \
    --tools "" \
    --system-prompt "$SYSTEM_PROMPT" \
    --model "$MODEL" \
    --output-format text \
    "$(cat "$PROMPT_FILE")" \
    > "$OUTPUT_MD" \
    2>/tmp/cve_attr_stderr_$$.txt
CLAUDE_EXIT=$?
set -e

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))

if [[ $CLAUDE_EXIT -ne 0 ]]; then
    echo ""
    echo "ERROR — claude exited ${CLAUDE_EXIT} after ${ELAPSED}s"
    sed 's/^/         /' /tmp/cve_attr_stderr_$$.txt >&2
    rm -f "$OUTPUT_MD" "/tmp/cve_attr_stderr_$$.txt"
    exit 1
fi
rm -f "/tmp/cve_attr_stderr_$$.txt"

# ── Validate output ───────────────────────────────────────────────────────────
OUTPUT_LINES=$(wc -l < "$OUTPUT_MD" 2>/dev/null || echo 0)
CVE_COUNT=$(grep -c "^#### CVE-" "$OUTPUT_MD" 2>/dev/null || echo 0)
CVE_LIST=$(grep "^#### CVE-" "$OUTPUT_MD" 2>/dev/null | sed 's/^#### //' | paste -sd ', ' || echo "none")

if [[ "$OUTPUT_LINES" -lt 5 ]]; then
    echo "WARNING — output is unexpectedly short (${OUTPUT_LINES} lines). Check ${OUTPUT_MD}"
fi

echo ""
echo "  Done (${ELAPSED}s)"
echo "  Output:       ${OUTPUT_MD} (${OUTPUT_LINES} lines)"
echo "  CVEs found:   ${CVE_COUNT} — ${CVE_LIST}"

# ── CVE ID validation against MITRE API ──────────────────────────────────────
if [[ ${SKIP_VALIDATION} -eq 1 ]]; then
    echo ""
    echo "  Validation:   SKIPPED (--skip-validation)"
else
    echo ""
    echo "  Validating CVE IDs against MITRE CVE API..."
    VALIDATION_OK=1
    NETWORK_OK=1

    # Test network reachability first
    set +e
    curl -s --max-time 5 "https://cveawg.mitre.org/api/cve/CVE-2021-44228" -o /dev/null 2>/dev/null
    NET_RC=$?
    set -e

    if [[ ${NET_RC} -ne 0 ]]; then
        NETWORK_OK=0
        echo ""
        echo "> ⚠ NOTE: CVE validation against MITRE API was not possible (network unavailable). All CVE IDs should be manually verified." >> "${OUTPUT_MD}"
        echo "  [WARN] MITRE API unreachable — validation note appended to output"
    else
        # Extract unique CVE IDs from output
        mapfile -t CVE_IDS < <(grep -oP 'CVE-[0-9]{4}-[0-9]+' "${OUTPUT_MD}" | sort -u || true)
        for cve_id in "${CVE_IDS[@]}"; do
            set +e
            HTTP_CODE=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
                "https://cveawg.mitre.org/api/cve/${cve_id}" 2>/dev/null)
            set -e
            if [[ "${HTTP_CODE}" == "404" ]]; then
                echo "" >> "${OUTPUT_MD}"
                echo "> ⚠ WARNING: ${cve_id} could not be verified against MITRE CVE database. This CVE ID may be hallucinated. Manual verification required before including in deliverable." >> "${OUTPUT_MD}"
                echo "  [WARN] ${cve_id} — 404 from MITRE API (not found)"
                VALIDATION_OK=0
            elif [[ "${HTTP_CODE}" == "200" ]]; then
                echo "  [OK  ] ${cve_id} — verified"
            else
                echo "  [WARN] ${cve_id} — unexpected HTTP ${HTTP_CODE}"
            fi
        done
        if [[ ${VALIDATION_OK} -eq 1 ]]; then
            echo "  All CVE IDs verified against MITRE database"
        fi
    fi
fi

# ── Log to audit log ─────────────────────────────────────────────────────────
log_cmd "ALL" "CVE Attribution (Intel ICS) — claude --print --tools \"\"" \
    "claude --print --tools \"\" --model ${MODEL} (prompt: ${PROMPT_BYTES} bytes)" \
    "Attribute observed exploitation patterns to known CVEs; validate CVE IDs against MITRE API" \
    "${OUTPUT_MD}" \
    "${CVE_COUNT} CVE(s) attributed — ${CVE_LIST} (${ELAPSED}s)"

echo ""
echo "========================================"
echo " Phase 16 complete — ${CVE_COUNT} CVE(s) attributed"
echo ""
echo " Next step: re-run investigation-report skill to integrate"
echo " cve_attribution.md as Section 3B of the report."
echo "========================================"
