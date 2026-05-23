"""Cryptographic IC Authority Gate (HMAC-SHA256 over PBKDF2-derived key).

See docs/design/ic_approval_mcp_design.md for the full rationale and threat
model. This module implements only the cryptographic + state-tracking core; the
human-facing CLI (`sift-approve`) and the Flask UI (`/gates/sign`) both call
into this.

Architectural guarantee: the MCP server process never reads the IC's HMAC key
unless the operator deliberately sets SIFTICS_SINGLE_USER_MODE=1 (development
shorthand). In production deployment, `ic_key.hmac` is mode 0600 owned by the
analyst user, and the MCP server reads `ic_verifier.hmac` (same bytes in v1,
mode 0640) — moving to Ed25519 in v2 gives true public/private separation.
"""
from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from pathlib import Path
from typing import Any, Literal

from .audit import append_event, case_dir
from .case_state import _now_iso  # noqa: WPS450 (intentional reuse)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 200_000
PBKDF2_KEY_LEN = 32
PBKDF2_HASH = "sha256"
SIGNATURE_ALG = "HMAC-SHA256"
DEFAULT_TTL_SECONDS = 3600

_PENDING = "approvals/pending"
_SIGNED = "approvals/signed"
_CONSUMED = "approvals/consumed"

_IC_KEY_FILE = "ic_key.hmac"
_IC_VERIFIER_FILE = "ic_verifier.hmac"
_IC_SALT_FILE = "ic_key.salt"
_IC_META_FILE = "ic_key.meta.json"


class ApprovalInvalidError(Exception):
    """Raised when an action MCP function is called with a bad approval."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signed_payload(approval: dict[str, Any]) -> bytes:
    """The bytes that are HMAC'd — must match exactly between sign and verify."""
    return _canonical({k: approval[k] for k in
                       ("request_id", "gate", "decision",
                        "decided_at", "agent_context_hash")})


def _ic_key_path(role: Literal["signer", "verifier"]) -> Path:
    if role == "signer":
        return case_dir() / _IC_KEY_FILE
    return case_dir() / _IC_VERIFIER_FILE


def _read_meta() -> dict[str, Any]:
    p = case_dir() / _IC_META_FILE
    if not p.exists():
        raise RuntimeError("IC key not initialised — run `sift-case-init`")
    return json.loads(p.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Key setup (called once by sift-case-init)
# ---------------------------------------------------------------------------


def derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(PBKDF2_HASH, passphrase.encode("utf-8"),
                               salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LEN)


def init_ic_key(passphrase: str, ic_name: str) -> dict[str, Any]:
    """Create ic_key.hmac, ic_verifier.hmac, ic_key.salt, ic_key.meta.json."""
    cd = case_dir()
    cd.mkdir(parents=True, exist_ok=True)
    if (cd / _IC_KEY_FILE).exists():
        raise FileExistsError("IC key material already present")

    salt = secrets.token_bytes(16)
    key = derive_key(passphrase, salt)
    fp = hashlib.sha256(key).hexdigest()

    (cd / _IC_SALT_FILE).write_bytes(salt)
    os.chmod(cd / _IC_SALT_FILE, 0o600)

    (cd / _IC_KEY_FILE).write_bytes(key)
    os.chmod(cd / _IC_KEY_FILE, 0o600)

    # v1: verifier is the same bytes; in multi-user mode this would be group-readable
    # by the mcpsift user. In single-user mode, the file mode is the only separator.
    (cd / _IC_VERIFIER_FILE).write_bytes(key)
    os.chmod(cd / _IC_VERIFIER_FILE, 0o640)

    meta = {
        "ic_name": ic_name,
        "alg": SIGNATURE_ALG,
        "kdf": "PBKDF2",
        "hash": PBKDF2_HASH,
        "iterations": PBKDF2_ITERATIONS,
        "key_len": PBKDF2_KEY_LEN,
        "salt_b64": salt.hex(),
        "key_fingerprint_sha256": fp,
        "created_at": _now_iso(),
        "ttl_seconds": DEFAULT_TTL_SECONDS,
    }
    (cd / _IC_META_FILE).write_text(json.dumps(meta, indent=2, sort_keys=True),
                                    encoding="utf-8")
    append_event("ic_key_initialised",
                 {"ic_name": ic_name, "key_fingerprint": fp,
                  "iterations": PBKDF2_ITERATIONS},
                 actor="case-init")
    return meta


# ---------------------------------------------------------------------------
# Agent → request approval
# ---------------------------------------------------------------------------


def request_approval(gate: str, summary: str, action: dict[str, Any],
                     proposed_by: str = "investigation-section-chief") -> dict[str, Any]:
    """Open an Authority Gate. Writes pending/<id>.json + audit event."""
    request_id = uuid.uuid4().hex
    request = {
        "request_id": request_id,
        "gate": gate,
        "summary": summary,
        "action": action,
        "agent_context_hash": _current_context_hash(),
        "requested_at": _now_iso(),
        "proposed_by": proposed_by,
    }
    p = case_dir() / _PENDING / f"{request_id}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(request, indent=2, sort_keys=True), encoding="utf-8")
    append_event("ic_request_approval",
                 {"request_id": request_id, "gate": gate,
                  "summary_first_120": summary[:120]},
                 actor=proposed_by)
    return request


# Event types that count toward COP state for the agent-context-drift check.
# The IC approval flow itself (ic_request_approval, ic_approval_signed) is
# explicitly excluded so the act of signing doesn't appear as "drift".
_COP_EVENT_TYPES = frozenset({
    "asr_appended", "asr_updated",
    "cet_appended", "cet_updated",
    "itq_answered", "itq_updated",
    "briefing_posted",
    "case_header_updated",
})


def _current_context_hash() -> str:
    """SHA-256 over recent COP-changing audit events. Binds approval to the
    investigation state at request time; later signing / verifier reads don't
    perturb the hash, but actual case-state updates do.
    """
    from .audit import iter_events
    h = hashlib.sha256()
    cop_events = [ev for ev in iter_events() if ev.get("type") in _COP_EVENT_TYPES]
    for ev in cop_events[-50:]:
        h.update(ev.get("line_hash", "").encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# IC → sign approval
# ---------------------------------------------------------------------------


def sign_approval(request_id: str, passphrase: str,
                  decision: Literal["approved", "denied"]) -> dict[str, Any]:
    """Called by the IC's signing surface (CLI or Flask /gates/sign).

    The passphrase is used to derive the HMAC key on the fly; the key is held in
    memory only as long as needed to compute the signature. We never log it.
    """
    pending_p = case_dir() / _PENDING / f"{request_id}.json"
    if not pending_p.exists():
        raise FileNotFoundError(f"no pending request {request_id}")
    request = json.loads(pending_p.read_text(encoding="utf-8"))

    meta = _read_meta()
    salt = bytes.fromhex(meta["salt_b64"])
    key = derive_key(passphrase, salt)

    # Optional sanity: check that the derived key matches what was stored at init.
    expected_fp = meta["key_fingerprint_sha256"]
    if not hmac.compare_digest(hashlib.sha256(key).hexdigest(), expected_fp):
        raise ApprovalInvalidError("bad passphrase (derived key fingerprint mismatch)")

    approval = {
        "request_id": request_id,
        "gate": request["gate"],
        "decision": decision,
        "decided_at": _now_iso(),
        "agent_context_hash": request["agent_context_hash"],
        "ic_name": meta["ic_name"],
        "signature_alg": SIGNATURE_ALG,
    }
    approval["signature"] = hmac.new(key, _signed_payload(approval),
                                     hashlib.sha256).hexdigest()
    # Best-effort scrub
    key = b"\x00" * len(key)
    del key

    signed_p = case_dir() / _SIGNED / f"{request_id}.json"
    signed_p.parent.mkdir(parents=True, exist_ok=True)
    signed_p.write_text(json.dumps(approval, indent=2, sort_keys=True),
                        encoding="utf-8")
    append_event("ic_approval_signed",
                 {"request_id": request_id, "decision": decision,
                  "ic_name": meta["ic_name"],
                  "signature_first_8": approval["signature"][:8]},
                 actor=meta["ic_name"])
    return approval


# ---------------------------------------------------------------------------
# Agent → check / consume approval
# ---------------------------------------------------------------------------


def check_approval(request_id: str) -> dict[str, Any]:
    """Returns {status: pending | approved | denied | expired, approval?}."""
    signed_p = case_dir() / _SIGNED / f"{request_id}.json"
    if not signed_p.exists():
        return {"status": "pending"}
    approval = json.loads(signed_p.read_text(encoding="utf-8"))
    if not verify_approval(approval):
        append_event("approval_invalid",
                     {"request_id": request_id, "reason": "signature_mismatch"},
                     actor="mcp_server")
        return {"status": "pending"}

    meta = _read_meta()
    ttl = int(meta.get("ttl_seconds", DEFAULT_TTL_SECONDS))
    # Use calendar.timegm so the ISO-UTC string is treated as UTC, not local.
    decided_utc = calendar.timegm(time.strptime(approval["decided_at"],
                                                 "%Y-%m-%dT%H:%M:%SZ"))
    age = time.time() - decided_utc
    if age > ttl:
        return {"status": "expired", "approval": approval}
    return {"status": approval["decision"], "approval": approval}


def verify_approval(approval: dict[str, Any]) -> bool:
    key = _ic_key_path("verifier").read_bytes()
    expected = hmac.new(key, _signed_payload(approval),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, approval["signature"])


def consume_approval(approval: dict[str, Any], execution_id: str,
                     actor: str = "mcp_server") -> None:
    """Mark an approval as consumed (single-use)."""
    consumed_p = case_dir() / _CONSUMED / f"{approval['request_id']}.json"
    if consumed_p.exists():
        raise ApprovalInvalidError(f"approval {approval['request_id']} already consumed")
    consumed_p.parent.mkdir(parents=True, exist_ok=True)
    # Atomic create — fail if file appears between check and write
    fd = os.open(consumed_p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    try:
        os.write(fd, json.dumps({
            "request_id": approval["request_id"],
            "execution_id": execution_id,
            "consumed_at": _now_iso(),
        }, sort_keys=True).encode("utf-8"))
    finally:
        os.close(fd)
    append_event("action_executed",
                 {"request_id": approval["request_id"],
                  "execution_id": execution_id,
                  "gate": approval["gate"]},
                 actor=actor)


def require_approval(approval: dict[str, Any], expected_gate: str) -> None:
    """Call at the top of every action MCP function. Raises ApprovalInvalidError on any failure."""
    if approval.get("gate") != expected_gate:
        raise ApprovalInvalidError(f"gate mismatch: expected {expected_gate}, got {approval.get('gate')}")
    if approval.get("decision") != "approved":
        raise ApprovalInvalidError(f"decision={approval.get('decision')}")
    if not verify_approval(approval):
        raise ApprovalInvalidError("signature_mismatch")
    # Context-drift check
    if approval.get("agent_context_hash") != _current_context_hash():
        raise ApprovalInvalidError("agent_context_drift")
    # Double-spend check
    consumed_p = case_dir() / _CONSUMED / f"{approval['request_id']}.json"
    if consumed_p.exists():
        raise ApprovalInvalidError("already_consumed")
