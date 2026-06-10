"""Evidence-linked findings register (findings.jsonl).

Each finding ties a factual claim to the exact artifact, tool, command, and
output excerpt that supports it. This creates a reproducible chain of custody:
anyone can re-run the command and verify the claim independently.

Schema
------
  finding_id     F-NNN sequential identifier
  claim          one-sentence factual statement (what was found)
  artifact_path  path inside the forensic image (Windows path or relative)
  artifact_source which disk image / exhibit the artifact lives in
  tool           name of the tool used (icat, strings, evtxecmd, pypff, …)
  command        exact command run, reproducible by a third party
  output_excerpt relevant slice of stdout / output that supports the claim
  linked_itq     ITQ-NNN this finding answers (optional)
  linked_asr     ASR-NNN this finding belongs to (optional)
  linked_cet     CCA-NNN this finding belongs to (optional)
  recorded_at    ISO-8601 UTC
  recorded_by    actor string
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .audit import append_event, case_dir

_FINDINGS = "findings.jsonl"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _findings_path() -> Path:
    return case_dir() / _FINDINGS


def _next_id() -> str:
    existing = finding_list()
    if not existing:
        return "F-001"
    nums = []
    for f in existing:
        try:
            nums.append(int(f["finding_id"].split("-")[1]))
        except (IndexError, ValueError):
            pass
    return f"F-{(max(nums) + 1):03d}" if nums else "F-001"


def finding_record(
    claim: str,
    artifact_path: str,
    artifact_source: str,
    tool: str,
    command: str,
    output_excerpt: str,
    linked_itq: str = "",
    linked_asr: str = "",
    linked_cet: str = "",
    actor: str = "investigation-section-chief",
) -> dict[str, Any]:
    """Append a new finding to findings.jsonl and write a finding_recorded audit event."""
    finding_id = _next_id()
    row: dict[str, Any] = {
        "finding_id": finding_id,
        "claim": claim,
        "artifact_path": artifact_path,
        "artifact_source": artifact_source,
        "tool": tool,
        "command": command,
        "output_excerpt": output_excerpt,
        "linked_itq": linked_itq,
        "linked_asr": linked_asr,
        "linked_cet": linked_cet,
        "recorded_at": _now_iso(),
        "recorded_by": actor,
    }
    p = _findings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    append_event(
        "finding_recorded",
        {
            "finding_id": finding_id,
            "claim_first_120": claim[:120],
            "artifact_source": artifact_source,
            "tool": tool,
            "linked_itq": linked_itq,
        },
        actor=actor,
    )
    return row


def finding_list(linked_itq: str = "", linked_asr: str = "") -> list[dict[str, Any]]:
    """Return all findings, optionally filtered by ITQ or ASR link."""
    p = _findings_path()
    if not p.exists():
        return []
    rows: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if linked_itq and row.get("linked_itq") != linked_itq:
                continue
            if linked_asr and row.get("linked_asr") != linked_asr:
                continue
            rows.append(row)
    return rows


def finding_count() -> int:
    return len(finding_list())
