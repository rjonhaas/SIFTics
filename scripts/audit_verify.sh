#!/usr/bin/env bash
# audit_verify.sh — Verify the hash chain of a SIFTics forensic_audit.jsonl
#
# Usage:
#   bash audit_verify.sh /cases/<case_name>
#
# Exit codes:
#   0 — chain intact (all hashes match)
#   1 — one or more verification failures

set -euo pipefail

CASE_ROOT="${1:-}"
if [[ -z "${CASE_ROOT}" ]]; then
    echo "Usage: bash audit_verify.sh /cases/<case_name>" >&2
    exit 1
fi

JSONL_FILE="${CASE_ROOT}/analysis/forensic_audit.jsonl"

if [[ ! -f "${JSONL_FILE}" ]]; then
    echo "ERROR: Audit log not found: ${JSONL_FILE}" >&2
    exit 1
fi

python3 - "${JSONL_FILE}" <<'PYEOF'
import sys
import json
import hashlib

jsonl_file = sys.argv[1]

errors      = []
prev_hash   = None   # None = we haven't seen any line yet
entry_count = 0

with open(jsonl_file, "r", encoding="utf-8") as fh:
    for lineno, raw in enumerate(fh, 1):
        raw = raw.strip()
        if not raw:
            continue

        # ── Parse JSON ──────────────────────────────────────────────────────
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"  LINE {lineno}: JSON parse error — {exc}")
            continue

        entry_count += 1
        stored_hash = entry.get("entry_hash", "")
        stored_prev = entry.get("prev_hash", "")

        # ── Reconstruct canonical object (same fixed field order as audit_log.sh) ──
        canonical = {
            "timestamp_utc": entry.get("timestamp_utc", ""),
            "machine":       entry.get("machine", ""),
            "tool":          entry.get("tool", ""),
            "command":       entry.get("command", ""),
            "purpose":       entry.get("purpose", ""),
            "output":        entry.get("output", ""),
            "result":        entry.get("result", ""),
            "exit_code":     entry.get("exit_code", 0),
            "prev_hash":     stored_prev,
        }
        canonical_json  = json.dumps(canonical, ensure_ascii=False, separators=(", ", ": "))
        expected_hash   = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        # ── Verify entry_hash ───────────────────────────────────────────────
        if expected_hash != stored_hash:
            errors.append(
                f"  LINE {lineno}: entry_hash MISMATCH\n"
                f"    stored  : {stored_hash}\n"
                f"    expected: {expected_hash}"
            )

        # ── Verify prev_hash chain ──────────────────────────────────────────
        if prev_hash is None:
            # First entry — must claim GENESIS
            if stored_prev != "GENESIS":
                errors.append(
                    f"  LINE {lineno}: first entry prev_hash should be 'GENESIS'"
                    f", got '{stored_prev}'"
                )
        else:
            if stored_prev != prev_hash:
                errors.append(
                    f"  LINE {lineno}: prev_hash MISMATCH\n"
                    f"    stored  : {stored_prev}\n"
                    f"    expected: {prev_hash}"
                )

        # Advance chain using the stored entry_hash so subsequent lines
        # are checked against what was actually written (not our recompute).
        prev_hash = stored_hash

# ── Report ──────────────────────────────────────────────────────────────────
if not errors:
    print(f"PASS ({entry_count} entries, chain intact)")
    sys.exit(0)
else:
    print(f"FAIL ({entry_count} entries checked, {len(errors)} error(s))")
    for msg in errors:
        print(msg)
    sys.exit(1)
PYEOF
