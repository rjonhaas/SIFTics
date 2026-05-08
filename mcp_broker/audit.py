"""Per-call audit logger for the SIFTics MCP broker.

Writes one JSON line per tool invocation with: timestamp, tool name,
arg digest (full args truncated to a hash for sensitive values), result
summary (rows/bytes/status), exit status, latency_ms.

This is structurally similar to scripts/audit_log.sh but operates at
the MCP function-call layer rather than the bash command layer. Both
chains together give judges full traceability from agent decision down
to tool execution.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Optional


@dataclasses.dataclass
class AuditEntry:
    timestamp_utc: str
    tool: str
    args_digest: str  # SHA-256 of canonical-JSON args
    args_summary: dict[str, Any]  # human-readable preview (sensitive values redacted)
    result_summary: str
    status: str  # "ok" | "error"
    latency_ms: int
    error_message: Optional[str] = None


SENSITIVE_KEY_HINTS = ("token", "password", "secret", "api_key", "apikey")


def _redact(args: dict[str, Any]) -> dict[str, Any]:
    """Replace values for sensitive-looking keys with [REDACTED]."""
    redacted = {}
    for k, v in args.items():
        if any(hint in k.lower() for hint in SENSITIVE_KEY_HINTS):
            redacted[k] = "[REDACTED]"
        elif isinstance(v, str) and len(v) > 200:
            redacted[k] = v[:100] + f"...[truncated, {len(v)} chars]"
        else:
            redacted[k] = v
    return redacted


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _digest(payload: Any) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def log(
    log_path: str,
    tool: str,
    args: dict[str, Any],
    result_summary: str,
    status: str,
    latency_ms: int,
    error_message: Optional[str] = None,
) -> None:
    """Append one audit entry. Creates parent dir if missing.
    Never raises — audit failure should not break the tool call."""
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        entry = AuditEntry(
            timestamp_utc=_now_utc(),
            tool=tool,
            args_digest=_digest(args),
            args_summary=_redact(args),
            result_summary=result_summary,
            status=status,
            latency_ms=latency_ms,
            error_message=error_message,
        )
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(dataclasses.asdict(entry), ensure_ascii=False) + "\n")
    except Exception as exc:  # noqa: BLE001 — audit must never raise
        # Last resort: stderr so it shows up in the MCP server log
        import sys
        sys.stderr.write(f"[audit] failed to write: {exc}\n")


class timed:
    """Context manager for timing tool calls. Use:
        with timed() as t: do_work()
        ...
        latency_ms = t.ms
    """

    def __enter__(self) -> "timed":
        self._start = time.perf_counter()
        self.ms = 0
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.ms = int((time.perf_counter() - self._start) * 1000)


def wrap(log_path: str, tool: str):
    """Decorator factory: wraps a callable to log every invocation.

    Example:
        @wrap("/tmp/audit.jsonl", "velociraptor.list_clients")
        def list_clients(...): ...

    The wrapped function still returns the same value; logging is a side effect.
    """

    def decorator(fn):  # noqa: ANN001
        def wrapper(*args, **kwargs):  # noqa: ANN002
            with timed() as t:
                try:
                    result = fn(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    log(
                        log_path=log_path,
                        tool=tool,
                        args=kwargs if kwargs else {"_args": list(args)},
                        result_summary="",
                        status="error",
                        latency_ms=t.ms if hasattr(t, "ms") else 0,
                        error_message=f"{type(exc).__name__}: {exc}",
                    )
                    raise
            summary = _summarize(result)
            log(
                log_path=log_path,
                tool=tool,
                args=kwargs if kwargs else {"_args": list(args)},
                result_summary=summary,
                status="ok",
                latency_ms=t.ms,
            )
            return result

        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper

    return decorator


def _summarize(result: Any) -> str:
    """Cheap one-line summary of a tool result for the audit log."""
    if result is None:
        return "None"
    if isinstance(result, (list, tuple)):
        return f"{type(result).__name__} of {len(result)} items"
    if isinstance(result, dict):
        keys = list(result.keys())[:5]
        return f"dict with {len(result)} keys: {keys}"
    if isinstance(result, str):
        if len(result) > 80:
            return f"str[{len(result)}]: {result[:60]}..."
        return f"str: {result}"
    if isinstance(result, (int, float, bool)):
        return f"{type(result).__name__}: {result}"
    return f"{type(result).__name__}"
