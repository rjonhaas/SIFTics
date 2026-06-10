"""IOC generation and publishing register (intel.jsonl).

Converts evidence findings into structured threat intelligence artifacts:
  - STIX 2.1 indicator objects (JSON) — for TIP sharing
  - YARA rules                        — for file/memory scanning
  - Sigma rules                       — for SIEM detection

Each IOC is stored in intel.jsonl with status draft → approved → published.
Publishing requires a signed IC approval (gate: publish_intel).

Generation is template-based and deterministic — the same finding always
produces the same artifact so the audit chain is reproducible.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from .audit import append_event, case_dir

_INTEL = "intel.jsonl"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _intel_path() -> Path:
    return case_dir() / _INTEL


def _next_id() -> str:
    existing = ioc_list()
    nums = []
    for r in existing:
        try:
            nums.append(int(r["ioc_id"].split("-")[1]))
        except (IndexError, ValueError):
            pass
    return f"IOC-{(max(nums) + 1):03d}" if nums else "IOC-001"


# ---------------------------------------------------------------------------
# Format generators
# ---------------------------------------------------------------------------

def _stix_indicator(ioc_type: str, ioc_value: str, context: str,
                    case_id: str, ioc_id: str) -> dict[str, Any]:
    """Generate a STIX 2.1 indicator object."""
    patterns = {
        "email":          f"[email-addr:value = '{ioc_value}']",
        "ip_address":     f"[ipv4-addr:value = '{ioc_value}']",
        "domain":         f"[domain-name:value = '{ioc_value}']",
        "url":            f"[url:value = '{ioc_value}']",
        "user_agent":     f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{ioc_value}']",
        "mac_address":    f"[network-traffic:src_ref.type = 'mac-addr' AND network-traffic:src_ref.value = '{ioc_value}']",
        "filename":       f"[file:name = '{ioc_value}']",
    }
    # File hash — detect by length
    if ioc_type == "file_hash":
        hl = len(ioc_value.replace(":", "").replace("-", ""))
        if hl == 32:
            pattern = f"[file:hashes.MD5 = '{ioc_value}']"
        elif hl == 40:
            pattern = f"[file:hashes.SHA-1 = '{ioc_value}']"
        else:
            pattern = f"[file:hashes.'SHA-256' = '{ioc_value}']"
    else:
        pattern = patterns.get(ioc_type, f"[artifact:payload_bin = '{ioc_value}']")

    ts = _now_iso()
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, ioc_id)}",
        "created": ts,
        "modified": ts,
        "name": f"{ioc_type.replace('_', ' ').title()}: {ioc_value}",
        "description": context,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts,
        "labels": ["malicious-activity"],
        "external_references": [
            {"source_name": "SIFTics", "description": f"Case: {case_id}, IOC: {ioc_id}"}
        ],
    }
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [obj],
    }
    return bundle


def _yara_rule(ioc_type: str, ioc_value: str, context: str,
               case_id: str, ioc_id: str) -> str:
    """Generate a YARA rule. Most useful for file hashes, filenames, strings."""
    safe_id = ioc_id.replace("-", "_")
    meta = (
        f'    description = "{context}"\n'
        f'    author = "SIFTics"\n'
        f'    case_id = "{case_id}"\n'
        f'    ioc_id = "{ioc_id}"\n'
        f'    date = "{_now_iso()[:10]}"\n'
        f'    status = "draft — review before deployment"'
    )

    if ioc_type == "file_hash":
        hl = len(ioc_value.replace(":", "").replace("-", ""))
        if hl == 32:
            cond = f'        hash.md5(0, filesize) == "{ioc_value.lower()}"'
        elif hl == 40:
            cond = f'        hash.sha1(0, filesize) == "{ioc_value.lower()}"'
        else:
            cond = f'        hash.sha256(0, filesize) == "{ioc_value.lower()}"'
        return (
            f"import \"hash\"\n\n"
            f"rule SIFTics_{safe_id} {{\n"
            f"  meta:\n{meta}\n"
            f"  condition:\n{cond}\n"
            f"}}"
        )

    if ioc_type == "filename":
        return (
            f"rule SIFTics_{safe_id} {{\n"
            f"  meta:\n{meta}\n"
            f"  strings:\n"
            f'    $fn = "{ioc_value}" ascii wide nocase\n'
            f"  condition:\n"
            f"    $fn\n"
            f"}}"
        )

    # For all other types: embed the IOC value as a string
    return (
        f"rule SIFTics_{safe_id} {{\n"
        f"  meta:\n{meta}\n"
        f"  strings:\n"
        f'    $ioc = "{ioc_value}" ascii wide\n'
        f"  condition:\n"
        f"    $ioc\n"
        f"}}"
    )


def _sigma_rule(ioc_type: str, ioc_value: str, context: str,
                case_id: str, ioc_id: str) -> str:
    """Generate a Sigma rule YAML."""
    logsource_map = {
        "email":          {"category": "proxy"},
        "ip_address":     {"category": "firewall"},
        "domain":         {"category": "dns"},
        "url":            {"category": "proxy"},
        "user_agent":     {"category": "proxy"},
        "mac_address":    {"category": "network"},
        "filename":       {"category": "file_event",   "product": "windows"},
        "file_hash":      {"category": "process_creation", "product": "windows"},
        "process_pattern":{"category": "process_creation", "product": "windows"},
        "registry_key":   {"category": "registry_event",   "product": "windows"},
    }
    field_map = {
        "email":          ("cs-uri-query|contains", ioc_value),
        "ip_address":     ("dst_ip", ioc_value),
        "domain":         ("dns.question.name|contains", ioc_value),
        "url":            ("c-uri|contains", ioc_value),
        "user_agent":     ("cs(User-Agent)|contains", ioc_value),
        "mac_address":    ("src_mac", ioc_value),
        "filename":       ("TargetFilename|endswith", ioc_value),
        "file_hash":      ("Hashes|contains", ioc_value),
        "process_pattern":("CommandLine|contains", ioc_value),
        "registry_key":   ("TargetObject|contains", ioc_value),
    }
    src = logsource_map.get(ioc_type, {"category": "network"})
    field, val = field_map.get(ioc_type, ("cs-uri|contains", ioc_value))
    src_lines = "\n".join(f"  {k}: {v}" for k, v in src.items())
    return (
        f"title: SIFTics - {ioc_type.replace('_', ' ').title()} - {ioc_value[:40]}\n"
        f"id: {uuid.uuid5(uuid.NAMESPACE_DNS, ioc_id + 'sigma')}\n"
        f"status: experimental\n"
        f"description: |\n"
        f"  {context}\n"
        f"  Case: {case_id} | IOC: {ioc_id}\n"
        f"author: SIFTics\n"
        f"date: {_now_iso()[:10]}\n"
        f"logsource:\n{src_lines}\n"
        f"detection:\n"
        f"  selection:\n"
        f"    {field}: '{val}'\n"
        f"  condition: selection\n"
        f"falsepositives:\n"
        f"  - Legitimate use — review before deployment\n"
        f"level: medium\n"
        f"tags:\n"
        f"  - siftics\n"
        f"  - case.{case_id}\n"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

SUPPORTED_IOC_TYPES = [
    "email", "ip_address", "domain", "url", "file_hash",
    "user_agent", "mac_address", "filename", "process_pattern", "registry_key",
]

FORMATS_BY_TYPE: dict[str, list[str]] = {
    "email":           ["stix", "sigma"],
    "ip_address":      ["stix", "sigma"],
    "domain":          ["stix", "sigma"],
    "url":             ["stix", "sigma"],
    "file_hash":       ["stix", "yara"],
    "user_agent":      ["stix", "sigma"],
    "mac_address":     ["stix", "sigma"],
    "filename":        ["stix", "yara", "sigma"],
    "process_pattern": ["sigma"],
    "registry_key":    ["sigma", "yara"],
}


def generate_ioc(
    ioc_type: str,
    ioc_value: str,
    context: str,
    finding_id: str = "",
    formats: list[str] | None = None,
    actor: str = "investigation-section-chief",
) -> dict[str, Any]:
    """Generate STIX/YARA/Sigma artifacts and store in intel.jsonl."""
    if ioc_type not in SUPPORTED_IOC_TYPES:
        raise ValueError(f"unsupported ioc_type: {ioc_type}")

    try:
        from .case_state import case_get_header
        header = case_get_header()
        case_id = header.get("case_id", "unknown")
    except Exception:
        case_id = "unknown"

    ioc_id = _next_id()
    requested = set(formats or FORMATS_BY_TYPE.get(ioc_type, ["stix"]))
    available = set(FORMATS_BY_TYPE.get(ioc_type, ["stix"]))
    to_generate = requested & available

    artifacts: dict[str, Any] = {}
    if "stix" in to_generate:
        artifacts["stix"] = json.dumps(
            _stix_indicator(ioc_type, ioc_value, context, case_id, ioc_id),
            indent=2,
        )
    if "yara" in to_generate:
        artifacts["yara"] = _yara_rule(ioc_type, ioc_value, context, case_id, ioc_id)
    if "sigma" in to_generate:
        artifacts["sigma"] = _sigma_rule(ioc_type, ioc_value, context, case_id, ioc_id)

    row: dict[str, Any] = {
        "ioc_id": ioc_id,
        "finding_id": finding_id,
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "context": context,
        "formats_generated": sorted(artifacts.keys()),
        "artifacts": artifacts,
        "status": "draft",
        "generated_at": _now_iso(),
        "generated_by": actor,
        "published_at": None,
    }

    p = _intel_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    append_event("ioc_generated", {
        "ioc_id": ioc_id,
        "ioc_type": ioc_type,
        "ioc_value_first_40": ioc_value[:40],
        "formats": sorted(artifacts.keys()),
        "finding_id": finding_id,
    }, actor=actor)

    return row


def ioc_list(status: str = "") -> list[dict[str, Any]]:
    """Return all IOCs, optionally filtered by status (draft/approved/published)."""
    p = _intel_path()
    if not p.exists():
        return []
    rows = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if status and row.get("status") != status:
                continue
            rows.append(row)
    return rows


def ioc_get(ioc_id: str) -> dict[str, Any] | None:
    for row in ioc_list():
        if row["ioc_id"] == ioc_id:
            return row
    return None


def ioc_publish(ioc_ids: list[str], execution_id: str,
                actor: str = "investigation-section-chief") -> list[dict[str, Any]]:
    """Mark IOCs as published. Rewrites intel.jsonl with updated status."""
    id_set = set(ioc_ids)
    rows = ioc_list()
    updated = []
    for row in rows:
        if row["ioc_id"] in id_set:
            row["status"] = "published"
            row["published_at"] = _now_iso()
            updated.append(row)

    p = _intel_path()
    with p.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    append_event("intel_published", {
        "ioc_ids": ioc_ids,
        "execution_id": execution_id,
        "count": len(updated),
        "_v1_note": "push to external TIP is stubbed; artifacts stored locally",
    }, actor=actor)
    return updated


def ioc_count(status: str = "") -> int:
    return len(ioc_list(status=status))
