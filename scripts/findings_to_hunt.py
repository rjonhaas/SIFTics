#!/usr/bin/env python3
"""
findings_to_hunt.py — Convert SIFTics analysis outputs into Velociraptor
hunt artifact YAML definitions.

Reads (whatever exists; missing inputs are skipped):
  analysis/ioc_master.csv
  analysis/anomalies.csv
  analysis/<MACHINE>/Memory/memory_anomalies.csv
  analysis/<MACHINE>/Network/pcap_anomalies.csv

Emits:
  analysis/hunt_artifacts/<artifact_name>.yaml          (one per finding)
  analysis/hunt_artifacts/manifest.json                 (catalog with provenance)

Each artifact is a complete Velociraptor YAML that can be uploaded with
`mcp_broker.tools.velociraptor upload_artifact`. Naming scheme:
  SIFTICS_<case>_<category>_<short_hash>
where short_hash is a SHA-256 prefix of the IOC value (so repeated runs
on the same case are idempotent).

Usage:
    python3 scripts/findings_to_hunt.py /cases/<case_name>
"""

from __future__ import annotations

import argparse
import csv
import datetime
import glob
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterator, Optional

# ── helpers ─────────────────────────────────────────────────────────────────


def short_hash(value: str, length: int = 10) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def case_slug(case_root: Path) -> str:
    """Sanitize the case name for use in artifact names (alnum only)."""
    name = case_root.name or "case"
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")[:40] or "case"


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def read_csv(path: Path, max_rows: int = 100_000) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    rows = []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            if i >= max_rows:
                break
            rows.append(row)
    return rows


def col(row: dict[str, str], *names: str) -> str:
    for n in names:
        v = row.get(n)
        if v:
            return v
    return ""


# ── artifact templates ──────────────────────────────────────────────────────


def yaml_escape(value: str) -> str:
    """Quote a string for safe YAML embedding (single-quoted scalar)."""
    return value.replace("'", "''")


def artifact_ip(case: str, ip: str, source: str) -> dict[str, Any]:
    name = f"SIFTICS_{case}_ip_{short_hash(ip)}"
    yaml_body = (
        f"name: {name}\n"
        f"description: |\n"
        f"  SIFTics-generated hunt: detect outbound connections to IOC IP {ip}.\n"
        f"  Source: {source}\n"
        f"author: siftics\n"
        f"type: CLIENT\n"
        f"parameters:\n"
        f"  - name: TargetIP\n"
        f"    default: '{yaml_escape(ip)}'\n"
        f"sources:\n"
        f"  - query: |\n"
        f"      SELECT Pid, Name, Laddr.IP AS LocalIP, Raddr.IP AS RemoteIP,\n"
        f"             Raddr.Port AS RemotePort, Status\n"
        f"      FROM Artifact.Windows.Network.Netstat()\n"
        f"      WHERE Raddr.IP = TargetIP\n"
    )
    return {"name": name, "yaml": yaml_body, "ioc_type": "ip", "ioc_value": ip,
            "source_finding": source}


def artifact_domain(case: str, domain: str, source: str) -> dict[str, Any]:
    name = f"SIFTICS_{case}_dom_{short_hash(domain)}"
    yaml_body = (
        f"name: {name}\n"
        f"description: |\n"
        f"  SIFTics-generated hunt: detect DNS queries to IOC domain {domain}.\n"
        f"  Source: {source}\n"
        f"author: siftics\n"
        f"type: CLIENT\n"
        f"parameters:\n"
        f"  - name: TargetDomain\n"
        f"    default: '{yaml_escape(domain)}'\n"
        f"sources:\n"
        f"  - query: |\n"
        f"      SELECT EventTime, ClientIP, QueryName, QueryType\n"
        f"      FROM Artifact.Windows.Detection.DNS()\n"
        f"      WHERE QueryName =~ TargetDomain\n"
    )
    return {"name": name, "yaml": yaml_body, "ioc_type": "domain",
            "ioc_value": domain, "source_finding": source}


def artifact_hash(case: str, sha256: str, source: str,
                  search_glob: str = r"C:\\**\\*.exe") -> dict[str, Any]:
    name = f"SIFTICS_{case}_hash_{sha256[:10]}"
    yaml_body = (
        f"name: {name}\n"
        f"description: |\n"
        f"  SIFTics-generated hunt: search for files matching SHA-256 {sha256}.\n"
        f"  Source: {source}\n"
        f"author: siftics\n"
        f"type: CLIENT\n"
        f"parameters:\n"
        f"  - name: TargetHash\n"
        f"    default: '{yaml_escape(sha256)}'\n"
        f"  - name: SearchGlob\n"
        f"    default: '{yaml_escape(search_glob)}'\n"
        f"sources:\n"
        f"  - query: |\n"
        f"      SELECT FullPath, Size, Mtime, Hash.SHA256 AS Sha256\n"
        f"      FROM Artifact.Generic.Forensic.LocalHashes.Glob(\n"
        f"        HashGlob=SearchGlob\n"
        f"      )\n"
        f"      WHERE Sha256 = TargetHash\n"
    )
    return {"name": name, "yaml": yaml_body, "ioc_type": "sha256",
            "ioc_value": sha256, "source_finding": source}


def artifact_path(case: str, path: str, source: str) -> dict[str, Any]:
    """Glob-style path search."""
    name = f"SIFTICS_{case}_path_{short_hash(path)}"
    yaml_body = (
        f"name: {name}\n"
        f"description: |\n"
        f"  SIFTics-generated hunt: detect presence of file path {path}.\n"
        f"  Source: {source}\n"
        f"author: siftics\n"
        f"type: CLIENT\n"
        f"parameters:\n"
        f"  - name: TargetPath\n"
        f"    default: '{yaml_escape(path)}'\n"
        f"sources:\n"
        f"  - query: |\n"
        f"      SELECT FullPath, Size, Mtime, Hash.SHA256 AS Sha256\n"
        f"      FROM glob(globs=TargetPath)\n"
        f"      WHERE NOT IsDir\n"
    )
    return {"name": name, "yaml": yaml_body, "ioc_type": "path",
            "ioc_value": path, "source_finding": source}


def artifact_process(case: str, process_name: str, source: str) -> dict[str, Any]:
    name = f"SIFTICS_{case}_proc_{short_hash(process_name)}"
    yaml_body = (
        f"name: {name}\n"
        f"description: |\n"
        f"  SIFTics-generated hunt: detect process name '{process_name}' (regex match).\n"
        f"  Source: {source}\n"
        f"author: siftics\n"
        f"type: CLIENT\n"
        f"parameters:\n"
        f"  - name: TargetProcessName\n"
        f"    default: '{yaml_escape(process_name)}'\n"
        f"sources:\n"
        f"  - query: |\n"
        f"      SELECT Pid, Ppid, Name, Exe, CommandLine, Username, CreateTime\n"
        f"      FROM pslist()\n"
        f"      WHERE Name =~ TargetProcessName\n"
    )
    return {"name": name, "yaml": yaml_body, "ioc_type": "process",
            "ioc_value": process_name, "source_finding": source}


def artifact_registry(case: str, key_path: str, source: str) -> dict[str, Any]:
    name = f"SIFTICS_{case}_reg_{short_hash(key_path)}"
    yaml_body = (
        f"name: {name}\n"
        f"description: |\n"
        f"  SIFTics-generated hunt: inspect registry key {key_path}.\n"
        f"  Source: {source}\n"
        f"author: siftics\n"
        f"type: CLIENT\n"
        f"parameters:\n"
        f"  - name: TargetKey\n"
        f"    default: '{yaml_escape(key_path)}'\n"
        f"sources:\n"
        f"  - query: |\n"
        f"      SELECT FullPath, Name, Type, Data\n"
        f"      FROM glob(globs=TargetKey, accessor='registry')\n"
    )
    return {"name": name, "yaml": yaml_body, "ioc_type": "registry",
            "ioc_value": key_path, "source_finding": source}


# ── input parsers ───────────────────────────────────────────────────────────


def from_ioc_master(case: str, analysis_dir: Path) -> Iterator[dict[str, Any]]:
    """Convert each row in ioc_master.csv to a Velociraptor artifact."""
    rows = read_csv(analysis_dir / "ioc_master.csv")
    for row in rows:
        ioc_type = (col(row, "Type", "type") or "").lower().strip()
        value = col(row, "Value", "value", "IOC", "ioc").strip()
        if not value:
            continue
        provenance = (
            f"ioc_master.csv (sources: "
            f"{col(row, 'Sources', 'sources') or '?'})"
        )
        if ioc_type == "ip":
            yield artifact_ip(case, value, provenance)
        elif ioc_type == "domain":
            yield artifact_domain(case, value, provenance)
        elif ioc_type in ("sha256", "hash", "filehash"):
            if re.fullmatch(r"[0-9a-fA-F]{64}", value):
                yield artifact_hash(case, value.lower(), provenance)
        elif ioc_type == "path":
            yield artifact_path(case, value, provenance)
        elif ioc_type == "registry":
            yield artifact_registry(case, value, provenance)


def from_memory_anomalies(case: str, analysis_dir: Path) -> Iterator[dict[str, Any]]:
    """Each MACHINE/Memory/memory_anomalies.csv → process / IP artifacts."""
    for csv_path in analysis_dir.glob("*/Memory/memory_anomalies.csv"):
        machine = csv_path.parts[-3]
        for row in read_csv(csv_path):
            sev = (row.get("Severity") or "").upper()
            cat = row.get("Category") or ""
            process = row.get("Process") or ""
            evidence = row.get("Evidence") or ""

            if sev not in ("HIGH", "MEDIUM"):
                continue

            provenance = f"{machine}/Memory/memory_anomalies.csv ({cat})"

            if cat in ("wrong-parent", "suspicious-path", "malfind-rwx"):
                if process and len(process) >= 3:
                    yield artifact_process(case, process, provenance)

            if cat in ("netscan-ioc-match", "external-conn"):
                # Evidence column has "TCP IP:PORT (state)"
                m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", evidence)
                if m:
                    yield artifact_ip(case, m.group(1), provenance)


def from_pcap_anomalies(case: str, analysis_dir: Path) -> Iterator[dict[str, Any]]:
    """Each MACHINE/Network/pcap_anomalies.csv → IP / domain artifacts."""
    for csv_path in analysis_dir.glob("*/Network/pcap_anomalies.csv"):
        machine = csv_path.parts[-3]
        for row in read_csv(csv_path):
            sev = (row.get("Severity") or "").upper()
            cat = row.get("Category") or ""
            value = (row.get("Value") or "").strip()
            if sev not in ("HIGH", "MEDIUM") or not value:
                continue
            provenance = f"{machine}/Network/pcap_anomalies.csv ({cat})"
            if cat in ("beacon-ioc", "beacon-likely", "beacon-possible"):
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
                    yield artifact_ip(case, value, provenance)
            elif cat == "dns-suspicious":
                yield artifact_domain(case, value, provenance)


def from_attack_path(case: str, analysis_dir: Path) -> Iterator[dict[str, Any]]:
    """attack_path.csv → process artifact for the lateral-movement method."""
    rows = read_csv(analysis_dir / "attack_path.csv")
    seen = set()
    for row in rows:
        method = (col(row, "Method") or "").strip()
        account = (col(row, "Account") or "").strip()
        if not method:
            continue
        # Hunt for the method — e.g. "RDP", "SMB", "WMI", "PsExec"
        # Map to an artifact based on what's known
        if method.lower() == "psexec" and "psexec" not in seen:
            yield artifact_process(case, "psexec(?:svc)?\\.exe",
                                    f"attack_path.csv (method=PsExec)")
            seen.add("psexec")
        if method.lower() == "wmi" and "wmi" not in seen:
            yield artifact_process(case, "wmiprvse\\.exe",
                                    f"attack_path.csv (method=WMI)")
            seen.add("wmi")
        # Account-based hunting: pivot for the account name
        # (a separate artifact would need to scan EVTX 4624 — left as TODO)


# ── main ────────────────────────────────────────────────────────────────────


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("case_root", help="Case root directory (e.g. /cases/jack)")
    p.add_argument("--out-dir", default=None,
                   help="Override output dir (default: <case_root>/analysis/hunt_artifacts)")
    p.add_argument("--force", action="store_true",
                   help="Re-generate even if artifact already exists")
    args = p.parse_args()

    case_root = Path(args.case_root).resolve()
    if not case_root.is_dir():
        print(f"ERROR: case_root not found: {case_root}", file=sys.stderr)
        return 1
    analysis_dir = case_root / "analysis"
    if not analysis_dir.is_dir():
        print(f"ERROR: analysis dir not found: {analysis_dir}", file=sys.stderr)
        return 1

    out_dir = Path(args.out_dir) if args.out_dir else analysis_dir / "hunt_artifacts"
    out_dir.mkdir(parents=True, exist_ok=True)

    case = case_slug(case_root)

    # Generate
    artifacts: list[dict[str, Any]] = []
    seen_names = set()
    generators = [
        from_ioc_master(case, analysis_dir),
        from_memory_anomalies(case, analysis_dir),
        from_pcap_anomalies(case, analysis_dir),
        from_attack_path(case, analysis_dir),
    ]
    for gen in generators:
        for art in gen:
            if art["name"] in seen_names:
                continue
            seen_names.add(art["name"])
            artifacts.append(art)

    # Write each artifact
    written = 0
    skipped = 0
    for art in artifacts:
        target = out_dir / f"{art['name']}.yaml"
        if target.exists() and not args.force:
            skipped += 1
            continue
        target.write_text(art["yaml"], encoding="utf-8")
        written += 1

    # Manifest
    manifest = {
        "generated_utc": now_utc(),
        "case_root": str(case_root),
        "case_slug": case,
        "artifact_count": len(artifacts),
        "written_count": written,
        "skipped_count": skipped,
        "artifacts": [
            {k: v for k, v in art.items() if k != "yaml"} for art in artifacts
        ],
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    print(f"Generated {len(artifacts)} hunt artifacts ({written} new, {skipped} skipped)")
    print(f"Output: {out_dir}")
    print(f"Manifest: {out_dir / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
