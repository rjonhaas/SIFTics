"""Software Bill of Materials for the SIFTics runtime.

The SBOM is a deterministic snapshot of every Python package installed in
the active environment plus the SIFTics git commit and the host platform.
Two reasons it exists:

1.  At case-init, the SBOM hash is appended as the *first* hash-chained
    audit event. Every finding produced later is therefore cryptographically
    downstream of a known toolchain state. If anyone questions whether the
    analyst tooling was compromised mid-investigation, the snapshot stored
    at ``<case>/sbom.json`` can be re-computed and compared to the hash in
    audit row 1 — drift is provable.

2.  At any later moment (audit verification, Authority Gate check, hunt
    package signing) the same hash can be re-derived and compared. A
    diverged toolchain is grounds for refusing to fire an active hunt or
    publish intel.

The package fingerprint is the SHA-256 of every file in the package's
dist-info plus the file's relative path, hashed in sorted order. This
catches both version drift (different ``version``) and post-publish
mutation (same version, different bytes — the dominant npm/PyPI attack
pattern of the past two years).

Only the standard library is used. Adding pip-audit, sigstore, or
CycloneDX exporters on top of this module is straightforward and they all
read the same ``compute_sbom()`` shape.
"""
from __future__ import annotations

import hashlib
import importlib.metadata as md
import json
import platform
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1"


def _package_sha256(dist: md.Distribution) -> str:
    """Hash every file in the package's RECORD + its path, in sorted order.

    This intentionally hashes the *installed* bytes, not the metadata Pip
    received from the index. A package whose installed contents have been
    rewritten post-install (the disk-image phase of any real attack) will
    produce a different hash even if the version string is unchanged.
    """
    h = hashlib.sha256()
    files = dist.files or []
    for f in sorted(files, key=lambda p: str(p)):
        try:
            target = Path(dist.locate_file(f))
        except Exception:
            continue
        if not target.exists() or target.is_dir():
            continue
        try:
            content_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        except (OSError, PermissionError):
            # Skip unreadable files but keep going — partial fingerprint is
            # still better than no fingerprint, and the missing files will
            # show up as drift on the next verification.
            continue
        h.update(str(f).encode("utf-8"))
        h.update(b":")
        h.update(content_hash.encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def _git_head() -> str | None:
    """Read ``.git/HEAD`` without requiring the git binary.

    Returns the commit sha (40 hex chars) the SIFTics working tree currently
    points at, or ``None`` if the repo isn't a git checkout (running from a
    pip-installed wheel, for instance).
    """
    repo_root = Path(__file__).resolve().parent.parent
    head_file = repo_root / ".git" / "HEAD"
    if not head_file.exists():
        return None
    head = head_file.read_text(encoding="utf-8").strip()
    if head.startswith("ref: "):
        ref_path = repo_root / ".git" / head[5:]
        if not ref_path.exists():
            return None
        return ref_path.read_text(encoding="utf-8").strip()
    return head  # detached HEAD — already a commit sha


def compute_sbom() -> dict[str, Any]:
    """Snapshot the current Python environment's package state + repo + platform.

    Output structure::

        {
          "schema_version": "1",
          "python_version": "3.12.3",
          "platform":       "Linux-6.8.0-...",
          "siftics_git_head": "abc1234...",   # may be None
          "packages": {
            "<pkg_name>": {"version": "x.y.z", "sha256": "..."},
            ...
          }
        }

    Sort order on ``packages`` is alphabetical so the hash is deterministic.
    """
    packages: dict[str, dict[str, str]] = {}
    for dist in md.distributions():
        name = (dist.metadata or {}).get("Name")
        if not name:
            continue
        if name in packages:
            continue  # first-resolved wins; matches importlib ordering
        packages[name] = {
            "version": dist.version or "",
            "sha256": _package_sha256(dist),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "python_version": ".".join(str(x) for x in sys.version_info[:3]),
        "platform": platform.platform(),
        "siftics_git_head": _git_head(),
        "packages": dict(sorted(packages.items())),
    }


def hash_sbom(sbom: dict[str, Any]) -> str:
    """Deterministic SHA-256 of a SBOM dict — same canonical-JSON shape as
    the audit row hashes so cross-comparison is trivial."""
    return hashlib.sha256(
        json.dumps(sbom, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def write_sbom(path: Path, sbom: dict[str, Any]) -> None:
    """Persist the SBOM to disk (pretty-printed for human review)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(sbom, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def read_sbom(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_sbom_against_disk(snapshot_path: Path) -> tuple[bool, str, str]:
    """Re-compute the current SBOM and compare to a snapshot on disk.

    Returns (ok, current_hash, snapshot_hash). ``ok`` is True when the two
    hashes match — i.e. no drift since the snapshot was taken.
    """
    snapshot = read_sbom(snapshot_path)
    current = compute_sbom()
    return hash_sbom(snapshot) == hash_sbom(current), hash_sbom(current), hash_sbom(snapshot)
