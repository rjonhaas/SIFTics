#!/usr/bin/env bash
# audit_log.sh — Hash-chained JSONL forensic audit log for SIFTics
#
# Source this file at the top of every run_*.sh script:
#   source "$(dirname "$0")/audit_log.sh"
#
# Provides:
#   audit_log_entry()        — Append one hash-chained JSONL entry
#   log_cmd()                — Backwards-compat wrapper (exit_code=0)
#   audit_jsonl_to_commands() — Regenerate commands.txt from JSONL

[[ -n "${_SIFTICS_AUDIT_LOG_LOADED:-}" ]] && return 0
_SIFTICS_AUDIT_LOG_LOADED=1

# ---------------------------------------------------------------------------
# audit_log_entry()
#
# Params (positional):
#   $1  machine       — hostname or machine label
#   $2  tool          — tool name / category
#   $3  command       — full command string executed
#   $4  purpose       — human description of why this command was run
#   $5  output_path   — path(s) to output file(s)
#   $6  result        — outcome summary string
#   $7  exit_code     — numeric exit code from the tool
#
# Writes one JSONL line to  $ANALYSIS_DIR/forensic_audit.jsonl
# Also appends a human-readable block to $ANALYSIS_DIR/commands.txt
# ---------------------------------------------------------------------------
audit_log_entry() {
    local machine="$1"
    local tool="$2"
    local command="$3"
    local purpose="$4"
    local output_path="$5"
    local result="$6"
    local exit_code="$7"

    # ANALYSIS_DIR must be set by the calling script
    local jsonl_file="${ANALYSIS_DIR}/forensic_audit.jsonl"
    local cmd_file="${ANALYSIS_DIR}/commands.txt"

    # Delegate all JSON encoding, hashing, and atomic append to Python3
    # to avoid bash quoting fragility with arbitrary string values.
    python3 - \
        "${machine}" \
        "${tool}" \
        "${command}" \
        "${purpose}" \
        "${output_path}" \
        "${result}" \
        "${exit_code}" \
        "${jsonl_file}" \
        "${cmd_file}" \
        <<'PYEOF'
import sys
import json
import hashlib
import datetime

machine      = sys.argv[1]
tool         = sys.argv[2]
command      = sys.argv[3]
purpose      = sys.argv[4]
output_path  = sys.argv[5]
result       = sys.argv[6]
exit_code    = int(sys.argv[7])
jsonl_file   = sys.argv[8]
cmd_file     = sys.argv[9]

timestamp_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Read prev_hash from last line of JSONL ──────────────────────────────────
prev_hash = "GENESIS"
try:
    with open(jsonl_file, "r", encoding="utf-8") as fh:
        last_line = ""
        for line in fh:
            stripped = line.strip()
            if stripped:
                last_line = stripped
        if last_line:
            last_obj = json.loads(last_line)
            prev_hash = last_obj.get("entry_hash", "GENESIS")
except FileNotFoundError:
    pass

# ── Build canonical object (without entry_hash) for hashing ────────────────
# Field order is fixed — must match audit_verify.sh exactly.
canonical = {
    "timestamp_utc": timestamp_utc,
    "machine":       machine,
    "tool":          tool,
    "command":       command,
    "purpose":       purpose,
    "output":        output_path,
    "result":        result,
    "exit_code":     exit_code,
    "prev_hash":     prev_hash,
}

# Canonical JSON: sorted=False (we rely on insertion order, Python 3.7+),
# separators=(', ', ': ') to be explicit, no trailing newline inside hash input.
canonical_json = json.dumps(canonical, ensure_ascii=False, separators=(", ", ": "))
entry_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

# ── Final object with entry_hash appended ──────────────────────────────────
final_obj = dict(canonical)
final_obj["entry_hash"] = entry_hash
final_line = json.dumps(final_obj, ensure_ascii=False, separators=(", ", ": "))

# ── Atomic append to JSONL ──────────────────────────────────────────────────
with open(jsonl_file, "a", encoding="utf-8") as fh:
    fh.write(final_line + "\n")

# ── Backwards-compat: append human-readable block to commands.txt ──────────
ts_display = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
block = (
    f"\n[{ts_display}] {machine} | {tool}\n"
    f"  {command}\n"
    f"  > Purpose  : {purpose}\n"
    f"  > Output   : {output_path}\n"
    f"  > Result   : {result}\n"
    f"  > ExitCode : {exit_code}\n"
    f"  > Hash     : {entry_hash[:16]}...\n"
    f"\n"
    "--------------------------------------------------------------------------------\n"
)
with open(cmd_file, "a", encoding="utf-8") as fh:
    fh.write(block)
PYEOF
}

# ---------------------------------------------------------------------------
# log_cmd() — backwards-compatible wrapper used by existing run_*.sh scripts
#
# Params (positional):
#   $1  machine
#   $2  tool
#   $3  command
#   $4  purpose
#   $5  output_path
#   $6  result
# ---------------------------------------------------------------------------
log_cmd() {
    audit_log_entry "$1" "$2" "$3" "$4" "$5" "$6" "0"
}

# ---------------------------------------------------------------------------
# audit_jsonl_to_commands()
#
# Regenerates a human-readable commands.txt from forensic_audit.jsonl.
# Usage:  audit_jsonl_to_commands [/path/to/forensic_audit.jsonl] [output.txt]
#         Defaults: $ANALYSIS_DIR/forensic_audit.jsonl → stdout
# ---------------------------------------------------------------------------
audit_jsonl_to_commands() {
    local jsonl_in="${1:-${ANALYSIS_DIR}/forensic_audit.jsonl}"
    local txt_out="${2:-}"

    python3 - "${jsonl_in}" "${txt_out}" <<'PYEOF'
import sys
import json

jsonl_in = sys.argv[1]
txt_out  = sys.argv[2] if len(sys.argv) > 2 else ""

lines_out = []
try:
    with open(jsonl_in, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                e = json.loads(raw)
            except json.JSONDecodeError as exc:
                lines_out.append(f"[LINE {lineno}] JSON parse error: {exc}\n")
                continue
            ts  = e.get("timestamp_utc", "?")
            m   = e.get("machine", "?")
            t   = e.get("tool", "?")
            cmd = e.get("command", "?")
            pur = e.get("purpose", "?")
            out = e.get("output", "?")
            res = e.get("result", "?")
            ec  = e.get("exit_code", "?")
            eh  = e.get("entry_hash", "?")[:16] + "..."
            block = (
                f"\n[{ts}] {m} | {t}\n"
                f"  {cmd}\n"
                f"  > Purpose  : {pur}\n"
                f"  > Output   : {out}\n"
                f"  > Result   : {res}\n"
                f"  > ExitCode : {ec}\n"
                f"  > Hash     : {eh}\n"
                f"\n"
                "--------------------------------------------------------------------------------\n"
            )
            lines_out.append(block)
except FileNotFoundError:
    sys.stderr.write(f"ERROR: {jsonl_in} not found\n")
    sys.exit(1)

content = "".join(lines_out)
if txt_out:
    with open(txt_out, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"Written {len(lines_out)} entries to {txt_out}")
else:
    sys.stdout.write(content)
PYEOF
}
