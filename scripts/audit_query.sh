#!/usr/bin/env bash
# audit_query.sh — Search SIFTics forensic_audit.jsonl by keyword or finding ID
#
# Usage:
#   bash audit_query.sh /cases/<case_name> <query>
#
# Query may be:
#   - A finding ID  : FND-3
#   - A machine name: DESKTOP-ABC123
#   - A tool name   : LECmd
#   - Any keyword   : powershell, webshell, 192.168.1.1, ...
#
# Searches fields: purpose, command, result, machine, tool
# Prints matching entries with line number, timestamp, machine, tool, command.
#
# Exit codes:
#   0 — one or more matches found
#   1 — no matches (or usage/file error)

set -euo pipefail

CASE_ROOT="${1:-}"
QUERY="${2:-}"

if [[ -z "${CASE_ROOT}" || -z "${QUERY}" ]]; then
    echo "Usage: bash audit_query.sh /cases/<case_name> <query>" >&2
    exit 1
fi

JSONL_FILE="${CASE_ROOT}/analysis/forensic_audit.jsonl"

if [[ ! -f "${JSONL_FILE}" ]]; then
    echo "ERROR: Audit log not found: ${JSONL_FILE}" >&2
    exit 1
fi

python3 - "${JSONL_FILE}" "${QUERY}" <<'PYEOF'
import sys
import json

jsonl_file = sys.argv[1]
query      = sys.argv[2].lower()

SEARCH_FIELDS = ("purpose", "command", "result", "machine", "tool")

matches     = []
total_lines = 0

with open(jsonl_file, "r", encoding="utf-8") as fh:
    for lineno, raw in enumerate(fh, 1):
        raw = raw.strip()
        if not raw:
            continue
        total_lines += 1
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue

        # Check each searchable field for a case-insensitive substring match
        hit = False
        for field in SEARCH_FIELDS:
            val = entry.get(field, "")
            if isinstance(val, str) and query in val.lower():
                hit = True
                break
            if isinstance(val, int) and query == str(val):
                hit = True
                break

        if hit:
            matches.append((lineno, entry))

# ── Print results ───────────────────────────────────────────────────────────
if not matches:
    print(f"No matches for '{query}' in {total_lines} entries.")
    sys.exit(1)

divider = "─" * 72
print(f"Found {len(matches)} match(es) for '{query}' "
      f"(searched {total_lines} entries in {jsonl_file})")
print(divider)

for lineno, e in matches:
    ts      = e.get("timestamp_utc", "?")
    machine = e.get("machine", "?")
    tool    = e.get("tool", "?")
    cmd     = e.get("command", "?")
    purpose = e.get("purpose", "?")
    output  = e.get("output", "?")
    result  = e.get("result", "?")
    ec      = e.get("exit_code", "?")
    eh      = e.get("entry_hash", "?")

    print(f"  Line      : {lineno}")
    print(f"  Timestamp : {ts}")
    print(f"  Machine   : {machine}")
    print(f"  Tool      : {tool}")
    print(f"  Command   : {cmd}")
    print(f"  Purpose   : {purpose}")
    print(f"  Output    : {output}")
    print(f"  Result    : {result}")
    print(f"  ExitCode  : {ec}")
    print(f"  EntryHash : {eh}")
    print(divider)

sys.exit(0)
PYEOF
