"""Deterministic DFIR evidence ingest.

The Investigation Section Chief should not start cold on a pile of raw ZIPs.
This module performs the boring, reproducible operations first: hash the
evidence, classify obvious artifact containers, inspect ZIP central directories,
extract small high-value members into a controlled work area, and write a
compact manifest for the agent to consume.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from . import audit

_MANIFEST = "evidence_manifest.json"
_QUICKLOOK = "evidence_quicklook.md"
_WORK_ROOT = "work/ingest"

_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}
_TEXT_EXTS = {".txt", ".csv", ".json", ".log", ".xml", ".yaml", ".yml"}
_DISK_EXTS = {".e01", ".e02", ".e03", ".e04", ".e05", ".aff", ".dd", ".raw", ".img"}
_MEMORY_EXTS = {".mem", ".vmem", ".dmp", ".raw"}
_WINDOWS_ARTIFACT_EXTS = {".evtx", ".pf", ".lnk", ".dat", ".hve"}


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def _artifact_kind(name: str) -> str:
    lower = name.lower()
    suffix = Path(lower).suffix
    if suffix == ".zip":
        return "zip_container"
    if suffix in _PCAP_EXTS:
        return "network_capture"
    if suffix in _DISK_EXTS:
        return "disk_image"
    if suffix in _MEMORY_EXTS:
        return "memory_image"
    if suffix in _WINDOWS_ARTIFACT_EXTS:
        return "windows_artifact"
    if "$mft" in lower or lower.endswith("/$mft"):
        return "ntfs_metadata"
    return "unknown"


def _classify_members(names: list[str]) -> dict[str, int]:
    counts = {
        "network_capture": 0,
        "disk_image": 0,
        "memory_image": 0,
        "windows_artifact": 0,
        "ntfs_metadata": 0,
        "text": 0,
        "unknown": 0,
    }
    for name in names:
        suffix = Path(name.lower()).suffix
        kind = _artifact_kind(name)
        if kind in counts and kind != "zip_container":
            counts[kind] += 1
        elif suffix in _TEXT_EXTS:
            counts["text"] += 1
        else:
            counts["unknown"] += 1
    return counts


def _safe_member_path(base: Path, member_name: str) -> Path:
    # ZIP members are POSIX-style regardless of host OS. Reject absolute paths,
    # drive-like paths, and parent traversal before extraction.
    posix = PurePosixPath(member_name)
    if posix.is_absolute() or ".." in posix.parts:
        raise ValueError(f"unsafe zip member path: {member_name!r}")
    if posix.parts and ":" in posix.parts[0]:
        raise ValueError(f"unsafe zip member path: {member_name!r}")
    target = (base / Path(*posix.parts)).resolve()
    base_resolved = base.resolve()
    if os.path.commonpath([str(base_resolved), str(target)]) != str(base_resolved):
        raise ValueError(f"unsafe zip member path: {member_name!r}")
    return target


def _should_extract_member(info: zipfile.ZipInfo, max_bytes: int) -> bool:
    suffix = Path(info.filename.lower()).suffix
    if info.is_dir():
        return False
    if info.file_size > max_bytes:
        return False
    return suffix in _PCAP_EXTS or suffix in _TEXT_EXTS


def _extract_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with zf.open(info, "r") as src, target.open("wb") as dst:
        shutil.copyfileobj(src, dst)


def _run_command(args: list[str], timeout: int = 20, max_chars: int = 6000) -> dict[str, Any]:
    if not shutil.which(args[0]):
        return {"available": False, "command": args, "output": f"{args[0]} not installed"}
    try:
        proc = subprocess.run(args, check=False, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout)
        output = proc.stdout[-max_chars:]
        return {
            "available": True,
            "command": args,
            "returncode": proc.returncode,
            "output": output,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "available": True,
            "command": args,
            "timeout": timeout,
            "output": (exc.stdout or "")[-max_chars:] if isinstance(exc.stdout, str) else "",
        }


def _pcap_quicklook(path: Path) -> dict[str, Any]:
    quicklook: dict[str, Any] = {"path": str(path)}
    quicklook["capinfos"] = _run_command(["capinfos", str(path)], timeout=20)
    quicklook["conversations"] = _run_command(
        ["tshark", "-r", str(path), "-q", "-z", "conv,ip"], timeout=30)
    quicklook["http_requests"] = _run_command(
        ["tshark", "-r", str(path), "-Y", "http.request", "-T", "fields",
         "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
         "-e", "http.host", "-e", "http.request.uri"],
        timeout=30,
    )
    return quicklook


def _inspect_zip(path: Path, extract_root: Path, max_extract_bytes: int) -> dict[str, Any]:
    out: dict[str, Any] = {
        "member_count": 0,
        "total_uncompressed_bytes": 0,
        "members_preview": [],
        "member_type_counts": {},
        "extracted": [],
        "pcap_quicklooks": [],
    }
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        out["member_count"] = len(infos)
        out["total_uncompressed_bytes"] = sum(i.file_size for i in infos)
        names = [i.filename for i in infos if not i.is_dir()]
        out["member_type_counts"] = _classify_members(names)
        out["members_preview"] = [
            {
                "name": i.filename,
                "size": i.file_size,
                "compressed_size": i.compress_size,
                "crc": f"{i.CRC:08x}",
                "kind": _artifact_kind(i.filename),
            }
            for i in infos[:80]
            if not i.is_dir()
        ]
        target_base = extract_root / path.stem
        for info in infos:
            if not _should_extract_member(info, max_extract_bytes):
                continue
            target = _safe_member_path(target_base, info.filename)
            _extract_member(zf, info, target)
            row = {
                "member": info.filename,
                "path": str(target),
                "size": info.file_size,
                "sha256": _sha256(target),
                "kind": _artifact_kind(info.filename),
            }
            out["extracted"].append(row)
            if Path(info.filename.lower()).suffix in _PCAP_EXTS:
                out["pcap_quicklooks"].append(_pcap_quicklook(target))
    return out


def _manifest_summary(manifest: dict[str, Any]) -> str:
    lines = [
        "# Evidence Quicklook",
        "",
        f"Generated: {manifest['generated_at']}",
        f"Case directory: `{manifest['case_dir']}`",
        f"Evidence directory: `{manifest['evidence_dir']}`",
        f"Evidence files: {manifest['evidence_file_count']}",
        "",
        "## Files",
        "",
    ]
    for item in manifest["evidence"]:
        lines.append(
            f"- `{item['name']}` - {item['kind']}, {item['size']} bytes, "
            f"sha256 `{item['sha256'][:16]}...`"
        )
        zip_info = item.get("zip")
        if zip_info:
            counts = {k: v for k, v in zip_info.get("member_type_counts", {}).items() if v}
            lines.append(
                f"  - ZIP members: {zip_info['member_count']}; "
                f"uncompressed bytes: {zip_info['total_uncompressed_bytes']}; "
                f"types: {counts or '{}'}"
            )
            extracted = zip_info.get("extracted") or []
            if extracted:
                lines.append("  - Extracted high-value members:")
                for ex in extracted[:20]:
                    lines.append(
                        f"    - `{ex['path']}` ({ex['kind']}, {ex['size']} bytes)"
                    )
            if zip_info.get("members_preview"):
                lines.append("  - First members:")
                for member in zip_info["members_preview"][:10]:
                    lines.append(
                        f"    - `{member['name']}` ({member['kind']}, {member['size']} bytes)"
                    )
    if manifest.get("pcap_quicklooks"):
        lines.extend(["", "## PCAP Quicklooks", ""])
        for ql in manifest["pcap_quicklooks"]:
            lines.append(f"### `{ql['path']}`")
            capinfos = ql.get("capinfos", {})
            if capinfos.get("available"):
                lines.extend(["", "```text", capinfos.get("output", "").strip(), "```", ""])
            else:
                lines.append(f"- capinfos unavailable: {capinfos.get('output')}")
            http = ql.get("http_requests", {})
            if http.get("available") and http.get("output", "").strip():
                lines.extend(["HTTP request sample:", "```text",
                              http["output"].strip()[:3000], "```", ""])
    lines.extend([
        "",
        "## Recommended Next Actions",
        "",
        "- Read this manifest before broad artifact exploration.",
        "- Open ASR rows for confirmed hosts only after artifact-backed identification.",
        "- Record every factual claim with `finding_record()` before briefing it.",
        "- Use extracted PCAP/text quicklook outputs as pivots, not as ground truth replacements for source evidence.",
    ])
    return "\n".join(lines) + "\n"


def run_case_ingest(case_path: str | Path | None = None,
                    max_extract_bytes: int = 512 * 1024 * 1024) -> dict[str, Any]:
    """Create/update the deterministic evidence manifest for a case.

    Args:
        case_path: case directory. Defaults to ``SIFTICS_CASE_DIR``.
        max_extract_bytes: per-member extraction ceiling for high-value ZIP
            members. Large disk and memory images remain inside evidence ZIPs.
    """
    cd = Path(case_path).expanduser().resolve() if case_path else audit.case_dir()
    evidence_dir = cd / "evidence"
    work_dir = cd / _WORK_ROOT
    extract_root = work_dir / "extracted"
    work_dir.mkdir(parents=True, exist_ok=True)
    extract_root.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": _now_iso(),
        "case_dir": str(cd),
        "evidence_dir": str(evidence_dir),
        "work_dir": str(work_dir),
        "max_extract_bytes": max_extract_bytes,
        "evidence_file_count": 0,
        "evidence": [],
        "pcap_quicklooks": [],
        "errors": [],
    }

    if not evidence_dir.exists():
        manifest["errors"].append(f"evidence directory does not exist: {evidence_dir}")
    else:
        for path in sorted(p for p in evidence_dir.iterdir() if p.is_file()):
            item: dict[str, Any] = {
                "name": path.name,
                "path": str(path),
                "size": path.stat().st_size,
                "mtime": int(path.stat().st_mtime),
                "sha256": _sha256(path),
                "kind": _artifact_kind(path.name),
            }
            if path.suffix.lower() == ".zip":
                try:
                    item["zip"] = _inspect_zip(path, extract_root, max_extract_bytes)
                    for extracted in item["zip"].get("extracted", []):
                        if extracted.get("kind") == "network_capture":
                            # The ZIP inspector already ran pcap quicklook; keep
                            # one flattened list so the prompt can find it fast.
                            pass
                    manifest["pcap_quicklooks"].extend(
                        item["zip"].get("pcap_quicklooks", []))
                except Exception as exc:  # noqa: BLE001 - manifest should survive one bad exhibit
                    item["zip_error"] = str(exc)
                    manifest["errors"].append(f"{path.name}: {exc}")
            elif item["kind"] == "network_capture":
                ql = _pcap_quicklook(path)
                item["pcap_quicklook"] = ql
                manifest["pcap_quicklooks"].append(ql)
            manifest["evidence"].append(item)

    manifest["evidence_file_count"] = len(manifest["evidence"])
    manifest_path = cd / _MANIFEST
    quicklook_path = cd / _QUICKLOOK
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True),
                             encoding="utf-8")
    quicklook_path.write_text(_manifest_summary(manifest), encoding="utf-8")

    old_case = os.environ.get("SIFTICS_CASE_DIR")
    os.environ["SIFTICS_CASE_DIR"] = str(cd)
    try:
        row = audit.append_event(
            "case_ingest_completed",
            {
                "manifest_path": _MANIFEST,
                "quicklook_path": _QUICKLOOK,
                "evidence_file_count": manifest["evidence_file_count"],
                "extracted_count": sum(
                    len((item.get("zip") or {}).get("extracted", []))
                    for item in manifest["evidence"]
                ),
                "pcap_quicklook_count": len(manifest["pcap_quicklooks"]),
                "errors": manifest["errors"][:5],
            },
            actor="dfir-operations",
        )
    finally:
        if old_case is None:
            os.environ.pop("SIFTICS_CASE_DIR", None)
        else:
            os.environ["SIFTICS_CASE_DIR"] = old_case
    manifest["audit_seq"] = row["seq"]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True),
                             encoding="utf-8")
    return manifest


def _current_evidence_fingerprint(cd: Path) -> list[dict[str, Any]]:
    evidence_dir = cd / "evidence"
    if not evidence_dir.exists():
        return []
    return [
        {
            "name": p.name,
            "size": p.stat().st_size,
            "mtime": int(p.stat().st_mtime),
        }
        for p in sorted(evidence_dir.iterdir())
        if p.is_file()
    ]


def manifest_is_current(case_path: str | Path | None = None) -> bool:
    cd = Path(case_path).expanduser().resolve() if case_path else audit.case_dir()
    try:
        manifest = read_manifest(cd)
    except FileNotFoundError:
        return False
    recorded = [
        {
            "name": item.get("name"),
            "size": item.get("size"),
            "mtime": item.get("mtime"),
        }
        for item in manifest.get("evidence", [])
    ]
    return recorded == _current_evidence_fingerprint(cd)


def ensure_case_ingest(case_path: str | Path | None = None,
                       max_extract_bytes: int = 512 * 1024 * 1024) -> dict[str, Any]:
    cd = Path(case_path).expanduser().resolve() if case_path else audit.case_dir()
    if manifest_is_current(cd):
        return read_manifest(cd)
    return run_case_ingest(cd, max_extract_bytes=max_extract_bytes)


def read_manifest(case_path: str | Path | None = None) -> dict[str, Any]:
    cd = Path(case_path).expanduser().resolve() if case_path else audit.case_dir()
    p = cd / _MANIFEST
    if not p.exists():
        raise FileNotFoundError(f"{p} does not exist; run deterministic ingest first")
    return json.loads(p.read_text(encoding="utf-8"))


def read_quicklook(case_path: str | Path | None = None, max_chars: int = 12000) -> str:
    cd = Path(case_path).expanduser().resolve() if case_path else audit.case_dir()
    p = cd / _QUICKLOOK
    if not p.exists():
        raise FileNotFoundError(f"{p} does not exist; run deterministic ingest first")
    text = p.read_text(encoding="utf-8")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n[quicklook truncated]\n"
