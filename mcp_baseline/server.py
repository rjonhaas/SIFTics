"""mcp_baseline — Custom MCP exposing Rathbun's known-good Windows baseline.

Lookups are structured equality (not embeddings). The DB is built once by
`scripts/build_baseline_db.sh` from upstream repos and shipped with the release.

Tables (created by build_baseline_db.py):
    files       (path, sha256, build, edition, signer, size, version)
    registry    (hive, key_path, value_name, value_data_hash, build, edition)
    services    (name, image_path, sha256, build, edition)
    scheduled   (task_name, action, build, edition)

Run modes:
    python -m mcp_baseline.server                  stdio (Claude Code default)
    python -m mcp_baseline.server --transport sse  HTTP for any MCP client
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

try:
    from siftics.audit import append_event as _audit
except ImportError:
    def _audit(*a, **kw): pass  # type: ignore[misc]

mcp = FastMCP("siftics-baseline")

_DB_ENV = "SIFTICS_BASELINE_DB"
_DEFAULT_DB = Path(__file__).parent / "baseline.sqlite"


def _db() -> sqlite3.Connection:
    p = Path(os.environ.get(_DB_ENV, _DEFAULT_DB))
    if not p.exists():
        raise RuntimeError(
            f"baseline DB not found at {p}. Run scripts/build_baseline_db.sh "
            f"or set {_DB_ENV} to point at an existing DB."
        )
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    return conn


def _row_list(rows) -> list[dict]:
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# File / binary lookups
# ---------------------------------------------------------------------------


@mcp.tool()
def lookup_by_sha256(sha256: str) -> dict:
    """Is this SHA-256 hash present in the Windows baseline?

    Returns {'known': bool, 'matches': [...]} — `matches` lists each
    (path, build, edition, signer) tuple where the hash appears.
    """
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT path, build, edition, signer, size, version "
            "FROM files WHERE sha256 = ?", (sha256.lower(),)
        ).fetchall()
        result = {"known": bool(rows), "matches": _row_list(rows)}
    finally:
        conn.close()
    try:
        _audit("baseline_lookup", {
            "source_type": "deterministic",
            "lookup_type": "sha256",
            "sha256": sha256.lower(),
            "known": result["known"],
            "match_count": len(result["matches"]),
        }, actor="mcp_baseline")
    except RuntimeError:
        pass
    return result


@mcp.tool()
def lookup_by_name_path(name: str, path: str = "") -> dict:
    """Lookup baseline file by name, optionally constraining to a path prefix.

    Use this for masquerade detection: if a file named svchost.exe is found at
    C:\\Users\\Public\\, name lookup returns matches *but* the paths show it
    should only be at C:\\Windows\\System32\\ — so the case path is anomalous.

    Returns {'known': bool, 'matches': [...]} with up to 50 examples.
    """
    conn = _db()
    try:
        sql = ("SELECT path, sha256, build, edition, signer "
               "FROM files WHERE LOWER(SUBSTR(path, INSTR(path, '\\')+1)) = ? "
               "OR LOWER(path) LIKE ?")
        like = f"%\\{name.lower()}"
        rows = conn.execute(sql, (name.lower(), like)).fetchmany(50)
        result = {"known": bool(rows), "matches": _row_list(rows)}
        if path:
            result["case_path_matches_baseline"] = any(
                path.lower() == r["path"].lower() for r in rows
            )
    finally:
        conn.close()
    try:
        _audit("baseline_lookup", {
            "source_type": "deterministic",
            "lookup_type": "name_path",
            "name": name,
            "observed_path": path or None,
            "known": result["known"],
            "match_count": len(result["matches"]),
        }, actor="mcp_baseline")
    except RuntimeError:
        pass
    return result


@mcp.tool()
def classify_path_anomaly(name: str, observed_path: str) -> dict:
    """Higher-level helper: given a filename and an observed path, judge whether
    the path matches any baseline location for that name.

    Returns {'anomaly': bool, 'baseline_paths': [...], 'observed_path': ...}.
    """
    lookup = lookup_by_name_path(name)
    if not lookup["known"]:
        result = {"anomaly": True, "reason": "name_not_in_baseline",
                  "baseline_paths": [], "observed_path": observed_path}
    else:
        baseline_paths = sorted({m["path"].lower() for m in lookup["matches"]})
        if observed_path.lower() in baseline_paths:
            result = {"anomaly": False, "reason": "matches_baseline_location",
                      "baseline_paths": baseline_paths, "observed_path": observed_path}
        else:
            result = {"anomaly": True, "reason": "name_exists_but_wrong_location",
                      "baseline_paths": baseline_paths, "observed_path": observed_path}
    try:
        _audit("baseline_lookup", {
            "source_type": "deterministic",
            "lookup_type": "path_anomaly",
            "name": name,
            "observed_path": observed_path,
            "anomaly": result["anomaly"],
            "reason": result["reason"],
        }, actor="mcp_baseline")
    except RuntimeError:
        pass
    return result


# ---------------------------------------------------------------------------
# Registry lookups
# ---------------------------------------------------------------------------


@mcp.tool()
def lookup_registry_value(hive: str, key_path: str, value_name: str = "") -> dict:
    """Is this registry value present in any clean Windows baseline?

    Used by the persistence-scan path: Run keys / Services / IFEO / etc are
    looked up; anything not in baseline is a candidate for review.
    """
    conn = _db()
    try:
        if value_name:
            rows = conn.execute(
                "SELECT key_path, value_name, build, edition "
                "FROM registry WHERE LOWER(hive) = ? AND LOWER(key_path) = ? "
                "AND LOWER(value_name) = ? LIMIT 25",
                (hive.lower(), key_path.lower(), value_name.lower())
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT key_path, value_name, build, edition "
                "FROM registry WHERE LOWER(hive) = ? AND LOWER(key_path) = ? "
                "LIMIT 25",
                (hive.lower(), key_path.lower())
            ).fetchall()
        result = {"known": bool(rows), "matches": _row_list(rows)}
    finally:
        conn.close()
    try:
        _audit("baseline_lookup", {
            "source_type": "deterministic",
            "lookup_type": "registry",
            "hive": hive,
            "key_path": key_path,
            "value_name": value_name or None,
            "known": result["known"],
            "match_count": len(result["matches"]),
        }, actor="mcp_baseline")
    except RuntimeError:
        pass
    return result


# ---------------------------------------------------------------------------
# Service / scheduled task lookups
# ---------------------------------------------------------------------------


@mcp.tool()
def lookup_service(name: str, image_path: str = "") -> dict:
    """Is this Windows service name (with optional image path) a stock service?"""
    conn = _db()
    try:
        if image_path:
            rows = conn.execute(
                "SELECT name, image_path, build, edition "
                "FROM services WHERE LOWER(name) = ? AND LOWER(image_path) = ? "
                "LIMIT 25",
                (name.lower(), image_path.lower())
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT name, image_path, build, edition "
                "FROM services WHERE LOWER(name) = ? LIMIT 25",
                (name.lower(),)
            ).fetchall()
        result = {"known": bool(rows), "matches": _row_list(rows)}
    finally:
        conn.close()
    try:
        _audit("baseline_lookup", {
            "source_type": "deterministic",
            "lookup_type": "service",
            "name": name,
            "image_path": image_path or None,
            "known": result["known"],
            "match_count": len(result["matches"]),
        }, actor="mcp_baseline")
    except RuntimeError:
        pass
    return result


@mcp.tool()
def lookup_scheduled_task(task_name: str) -> dict:
    """Is this Scheduled Task name part of a stock Windows install?"""
    conn = _db()
    try:
        rows = conn.execute(
            "SELECT task_name, action, build, edition "
            "FROM scheduled WHERE LOWER(task_name) = ? LIMIT 25",
            (task_name.lower(),)
        ).fetchall()
        result = {"known": bool(rows), "matches": _row_list(rows)}
    finally:
        conn.close()
    try:
        _audit("baseline_lookup", {
            "source_type": "deterministic",
            "lookup_type": "scheduled_task",
            "task_name": task_name,
            "known": result["known"],
            "match_count": len(result["matches"]),
        }, actor="mcp_baseline")
    except RuntimeError:
        pass
    return result


# ---------------------------------------------------------------------------
# DB introspection (useful for the agent to know what's available)
# ---------------------------------------------------------------------------


@mcp.tool()
def baseline_meta() -> dict:
    """Return counts and provenance of the baseline DB."""
    conn = _db()
    try:
        out: dict[str, Any] = {}
        for table in ("files", "registry", "services", "scheduled"):
            try:
                n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.OperationalError:
                n = 0
            out[f"{table}_count"] = n
        try:
            out["provenance"] = dict(conn.execute(
                "SELECT key, value FROM meta"
            ).fetchall())
        except sqlite3.OperationalError:
            out["provenance"] = {}
        return out
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="SIFTics baseline MCP server.")
    parser.add_argument("--transport", choices=("stdio", "sse"), default="stdio")
    parser.add_argument("--port", type=int, default=9102)
    args = parser.parse_args()
    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse", port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
