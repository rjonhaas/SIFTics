"""Hash-chained, append-only audit log.

Each event line is a single JSON object containing:
    seq               sequence number (monotonic, starts at 1)
    ts                ISO-8601 UTC timestamp
    type              event type string (e.g. "asr_appended")
    actor             "agent" | "ic" | "mcp_server"
    payload           event-specific dict
    prev_line_hash    SHA-256 hex of the previous line's full canonical bytes
    line_hash         SHA-256 hex of THIS line's canonical bytes (excluding line_hash itself)

Verification = recompute line_hash for every row and confirm prev_line_hash chain.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

_DEFAULT_FILENAME = "forensic_audit.jsonl"


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def case_dir() -> Path:
    raw = os.environ.get("SIFTICS_CASE_DIR")
    if not raw:
        raise RuntimeError(
            "SIFTICS_CASE_DIR env var is required (path to the case directory)."
        )
    return Path(raw).expanduser().resolve()


def audit_path() -> Path:
    return case_dir() / _DEFAULT_FILENAME


def _last_state(path: Path) -> tuple[int, str]:
    """Return (last_seq, last_line_hash). Returns (0, '<genesis>') for empty/missing log."""
    if not path.exists():
        return 0, "<genesis>"
    last: dict[str, Any] | None = None
    with path.open("rb") as fh:
        # Tail-read: walk backward to find last non-empty line.
        # For small files (a few MB) this is fine without seek optimisation.
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                continue
    if last is None:
        return 0, "<genesis>"
    return int(last.get("seq", 0)), str(last.get("line_hash", "<genesis>"))


def append_event(event_type: str, payload: dict[str, Any], actor: str = "mcp_server") -> dict[str, Any]:
    """Append a new event to the hash-chained audit log. Returns the written row."""
    path = audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    last_seq, last_hash = _last_state(path)
    row = {
        "seq": last_seq + 1,
        "ts": _now_iso(),
        "type": event_type,
        "actor": actor,
        "payload": payload,
        "prev_line_hash": last_hash,
    }
    row["line_hash"] = hashlib.sha256(_canonical(row)).hexdigest()

    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    return row


def iter_events(limit: int | None = None):
    """Yield events in insertion order. If limit is set, yield the last N events only."""
    path = audit_path()
    if not path.exists():
        return
    lines: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                lines.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if limit is not None:
        lines = lines[-limit:]
    yield from lines


def verify_chain() -> tuple[bool, list[str]]:
    """Recompute hashes; return (ok, errors). Used by /audit/verify and audit_verify.sh."""
    path = audit_path()
    errors: list[str] = []
    if not path.exists():
        return True, []

    prev_hash = "<genesis>"
    expected_seq = 1
    with path.open("r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"line {n}: JSON parse error ({e})")
                return False, errors

            if row.get("seq") != expected_seq:
                errors.append(f"line {n}: seq mismatch (expected {expected_seq}, got {row.get('seq')})")
            if row.get("prev_line_hash") != prev_hash:
                errors.append(f"line {n}: prev_line_hash chain broken")

            stored = row.pop("line_hash", None)
            recomputed = hashlib.sha256(_canonical(row)).hexdigest()
            if stored != recomputed:
                errors.append(f"line {n}: line_hash mismatch (tampering or bug)")

            prev_hash = stored or "<missing>"
            expected_seq += 1

    return len(errors) == 0, errors
