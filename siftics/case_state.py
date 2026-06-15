"""Case state - append-only JSONL files for the COP, ASR, CET, and inquiries.

All write paths go through audit.append_event so every change is recorded in the
hash-chained log. Reads return the latest version of each row (versioning via
`superseded_by` chains).
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .audit import audit_path, append_event, case_dir, iter_events  # noqa: F401

_CASE_HEADER = "case.json"
_ASR = "suit.jsonl"          # generic label: "Affected Systems Register"
_CET = "cca.jsonl"           # generic label: "Containment & Eradication Tracker"
_ITQ = "grid.jsonl"          # legacy storage for Lines of Inquiry checks
_BRIEFINGS = "briefings"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _default_itq_template_path() -> Path | None:
    """Return the packaged Lines of Inquiry seed template when available."""
    template = Path(__file__).resolve().parent / "templates" / "itq_questions.yaml"
    return template if template.exists() else None


def next_case_id(base_dir: str | Path = "~/Desktop/cases") -> str:
    """Suggest the next case ID in YYYY-MM-DD-NN format.

    Scans `base_dir` for existing case directories whose name starts with
    today's date and returns the next two-digit sequence (zero-padded).
    First case of the day → 2026-06-10-01; tenth → 2026-06-10-10.

    Used by both the CLI (setup.sh) and the new-case UI route so the
    operator never has to type a case name unless they want a custom one.
    """
    today = time.strftime("%Y-%m-%d", time.gmtime())
    base = Path(str(base_dir)).expanduser()
    n = 1
    if base.is_dir():
        prefix = f"{today}-"
        used = sorted(
            int(p.name[len(prefix):])
            for p in base.iterdir()
            if p.is_dir() and p.name.startswith(prefix) and p.name[len(prefix):].isdigit()
        )
        if used:
            n = used[-1] + 1
    return f"{today}-{n:02d}"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


@dataclass
class Role:
    name: str
    contact: str = ""
    role: str = ""


@dataclass
class CaseHeader:
    case_id: str
    name: str
    opened_at: str
    incident_commander: dict[str, Any]
    # Free-form briefing the IC writes at case-init. This is the IC's
    # initial *hypothesis* of what happened and what evidence was pulled -
    # the kind of one-paragraph sendoff a real IC would give an analyst
    # walking onto a case. The agent reads it on first turn for
    # orientation but treats it as the IC's read, not ground truth - the
    # investigation still has to verify against evidence.
    context: str = ""
    deputy_ic: dict[str, Any] = field(default_factory=dict)
    ops_exec: list[dict[str, Any]] = field(default_factory=list)
    ir_lead: dict[str, Any] = field(default_factory=dict)
    forensics_lead: dict[str, Any] = field(default_factory=dict)
    press_lead: dict[str, Any] = field(default_factory=dict)
    impact_level: str = "moderate"
    scope: dict[str, Any] = field(default_factory=dict)
    external_tickets: list[dict[str, Any]] = field(default_factory=list)
    current_briefing_id: str | None = None
    last_updated_at: str = ""
    last_updated_by: str = ""


@dataclass
class SystemRow:
    """Affected Systems Register row (CIMTK: SUIT)."""
    serial_no: str
    version: int
    system_type: str
    system_identifier: str
    location: str
    date_of_detection: str
    date_of_compromise: str
    how_determined: str
    impact_rating: str
    impact_description: str
    planned_action: str
    system_safe: str                    # not_safe | safe | pending_verification
    duration_estimate_hours: int = 0
    complexity: str = "medium"
    dependencies: list[str] = field(default_factory=list)
    notes: str = ""
    linked_findings: list[str] = field(default_factory=list)
    linked_hunts: list[str] = field(default_factory=list)
    written_by: str = "mcp_server"
    written_at: str = ""
    superseded_by: str | None = None


@dataclass
class AssetRow:
    """Containment & Eradication Tracker row (CIMTK: CCA)."""
    cca_no: str
    version: int
    data_source: str
    source_paths: list[str]
    timestamp_compromised: str
    owner_informed: bool
    analysis_status: str                # not_started | in_progress | checked | none_present_complete
    leaked: str                         # not_yet_checked | no | yes
    effort_to_remediate_days: int
    priority_order: int
    secrets_status: str = "not_yet_checked"
    cloud_creds_status: str = "not_yet_checked"
    certs_priv_keys_status: str = "not_yet_checked"
    ssh_api_keys_status: str = "not_yet_checked"
    full_remediation_required: bool = False
    ip_impact: str = "unknown"
    third_party_products: list[str] = field(default_factory=list)
    notes: str = ""
    point_of_contact: str = ""
    written_by: str = "mcp_server"
    written_at: str = ""
    superseded_by: str | None = None


@dataclass
class Question:
    """Line of Inquiry check row (legacy ITQ / CIMTK Grid storage)."""
    question_id: str
    question: str
    category: str = "general"
    answer: str = ""
    answer_source: str = ""             # ic | agent | auto_tooling
    answered_at: str = ""
    notes: str = ""
    resulting_task: str = ""
    task_priority: str = "medium"
    allocated_to: str = ""
    task_due: str = ""
    status: str = "open"                # open | in_progress | completed | not_applicable
    linked_findings: list[str] = field(default_factory=list)


@dataclass
class Briefing:
    briefing_id: str
    written_by: str
    written_at: str
    summary_md: str


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------


def _path(name: str) -> Path:
    return case_dir() / name


def _read_jsonl(name: str) -> list[dict[str, Any]]:
    p = _path(name)
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def _append_jsonl(name: str, row: dict[str, Any]) -> None:
    p = _path(name)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def _latest_versions(rows: Iterable[dict[str, Any]], id_field: str) -> dict[str, dict[str, Any]]:
    """Walk superseded_by chains; return id → latest row."""
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        rid = row[id_field]
        if rid not in by_id or row.get("version", 0) > by_id[rid].get("version", 0):
            by_id[rid] = row
    # Drop superseded entries (where superseded_by points to a known later id)
    for rid, row in list(by_id.items()):
        sup = row.get("superseded_by")
        if sup and sup in by_id:
            del by_id[rid]
    return by_id


# ---------------------------------------------------------------------------
# Case header
# ---------------------------------------------------------------------------


def case_get_header() -> dict[str, Any]:
    p = _path(_CASE_HEADER)
    if not p.exists():
        raise FileNotFoundError(f"{p} does not exist — run case-init first")
    return json.loads(p.read_text(encoding="utf-8"))


def case_write_header(header: dict[str, Any], actor: str = "mcp_server") -> dict[str, Any]:
    p = _path(_CASE_HEADER)
    p.parent.mkdir(parents=True, exist_ok=True)
    header["last_updated_at"] = _now_iso()
    header["last_updated_by"] = actor
    p.write_text(json.dumps(header, indent=2, sort_keys=True), encoding="utf-8")
    append_event("case_header_updated", {"fields_changed": list(header.keys())}, actor=actor)
    return header


def case_update_header(fields: dict[str, Any], actor: str = "mcp_server") -> dict[str, Any]:
    header = case_get_header()
    header.update(fields)
    return case_write_header(header, actor=actor)


# ---------------------------------------------------------------------------
# Affected Systems Register (SUIT)
# ---------------------------------------------------------------------------


def asr_all() -> list[dict[str, Any]]:
    rows = _read_jsonl(_ASR)
    return list(_latest_versions(rows, "serial_no").values())


def asr_open() -> list[dict[str, Any]]:
    return [r for r in asr_all() if r.get("system_safe") != "safe"]


def asr_get(serial_no: str) -> dict[str, Any] | None:
    return _latest_versions(_read_jsonl(_ASR), "serial_no").get(serial_no)


def _next_serial(prefix: str, jsonl_name: str, id_field: str) -> str:
    existing = _read_jsonl(jsonl_name)
    nums = [int(r[id_field].split("-", 1)[1])
            for r in existing
            if isinstance(r.get(id_field), str) and "-" in r[id_field]]
    return f"{prefix}-{(max(nums) if nums else 0) + 1}"


def asr_append(row: dict[str, Any], actor: str = "mcp_server") -> dict[str, Any]:
    row = dict(row)  # don't mutate caller's dict
    row.setdefault("serial_no", _next_serial("ASR", _ASR, "serial_no"))
    row["version"] = 1
    row["written_at"] = _now_iso()
    row["written_by"] = actor
    row["superseded_by"] = None
    _append_jsonl(_ASR, row)
    append_event("asr_appended",
                 {"serial_no": row["serial_no"],
                  "system_identifier": row.get("system_identifier"),
                  "impact_rating": row.get("impact_rating")},
                 actor=actor)
    return row


def asr_update(serial_no: str, fields: dict[str, Any], actor: str = "mcp_server") -> dict[str, Any]:
    prev = asr_get(serial_no)
    if prev is None:
        raise KeyError(f"ASR row {serial_no} not found")
    new_row = {**prev, **fields,
               "version": int(prev.get("version", 1)) + 1,
               "written_at": _now_iso(), "written_by": actor,
               "superseded_by": None}
    _append_jsonl(_ASR, new_row)
    append_event("asr_updated",
                 {"serial_no": serial_no, "fields_changed": list(fields.keys())},
                 actor=actor)
    return new_row


# ---------------------------------------------------------------------------
# Containment & Eradication Tracker (CCA)
# ---------------------------------------------------------------------------


def cet_all() -> list[dict[str, Any]]:
    rows = _read_jsonl(_CET)
    return list(_latest_versions(rows, "cca_no").values())


def cet_pending() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in cet_all():
        for k in ("secrets_status", "cloud_creds_status",
                  "certs_priv_keys_status", "ssh_api_keys_status"):
            if r.get(k) not in ("rolled_complete", "none_present_complete"):
                out.append(r)
                break
    return out


def cet_append(row: dict[str, Any], actor: str = "mcp_server") -> dict[str, Any]:
    row = dict(row)
    row.setdefault("cca_no", _next_serial("CET", _CET, "cca_no"))
    row["version"] = 1
    row["written_at"] = _now_iso()
    row["written_by"] = actor
    row["superseded_by"] = None
    _append_jsonl(_CET, row)
    append_event("cet_appended",
                 {"cca_no": row["cca_no"], "data_source": row.get("data_source"),
                  "priority_order": row.get("priority_order")},
                 actor=actor)
    return row


def cet_update(cca_no: str, fields: dict[str, Any], actor: str = "mcp_server") -> dict[str, Any]:
    prev = next((r for r in cet_all() if r["cca_no"] == cca_no), None)
    if prev is None:
        raise KeyError(f"CET row {cca_no} not found")
    new_row = {**prev, **fields,
               "version": int(prev.get("version", 1)) + 1,
               "written_at": _now_iso(), "written_by": actor,
               "superseded_by": None}
    _append_jsonl(_CET, new_row)
    append_event("cet_updated",
                 {"cca_no": cca_no, "fields_changed": list(fields.keys())},
                 actor=actor)
    return new_row


# ---------------------------------------------------------------------------
# Lines of Inquiry (legacy ITQ storage)
# ---------------------------------------------------------------------------


def itq_all() -> list[dict[str, Any]]:
    return _read_jsonl(_ITQ)


def itq_unanswered() -> list[dict[str, Any]]:
    return [q for q in itq_all() if q.get("status") in ("open", "in_progress")]


def itq_progress() -> dict[str, Any]:
    rows = itq_all()
    total = len(rows)
    if total == 0:
        return {"answered": 0, "total": 0, "pct": 0.0}
    done = sum(1 for q in rows if q.get("status") in ("completed", "not_applicable"))
    return {"answered": done, "total": total, "pct": round(100 * done / total, 1)}


def itq_seed_from_template(template_path: Path | str, actor: str = "mcp_server") -> int:
    """Seed grid.jsonl from a YAML template. Returns number of questions written."""
    import yaml
    template_path = Path(template_path)
    data = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    written = 0
    target = _path(_ITQ)
    if target.exists():
        raise FileExistsError(f"{target} already exists; refusing to overwrite")
    target.parent.mkdir(parents=True, exist_ok=True)
    for category, questions in data.get("categories", {}).items():
        for q in questions:
            row = {
                "question_id": q["id"],
                "question": q["text"],
                "category": category,
                "answer": "",
                "answer_source": "",
                "answered_at": "",
                "notes": "",
                "resulting_task": q.get("default_task", ""),
                "task_priority": q.get("priority", "medium"),
                "allocated_to": "",
                "task_due": "",
                "status": "open",
                "linked_findings": [],
            }
            _append_jsonl(_ITQ, row)
            written += 1
    append_event("itq_seeded",
                 {"template": template_path.name, "questions_written": written},
                 actor=actor)
    return written


def itq_answer(question_id: str, answer: str, source: str = "agent",
               resulting_task: str | None = None,
               actor: str = "mcp_server") -> dict[str, Any]:
    rows = itq_all()
    target_idx = next((i for i, r in enumerate(rows) if r["question_id"] == question_id), None)
    if target_idx is None:
        raise KeyError(f"ITQ {question_id} not found")
    rows[target_idx]["answer"] = answer
    rows[target_idx]["answer_source"] = source
    rows[target_idx]["answered_at"] = _now_iso()
    if resulting_task is not None:
        rows[target_idx]["resulting_task"] = resulting_task
    rows[target_idx]["status"] = "completed"

    # Rewrite the entire file (cheap for ~50 questions). For larger sets, switch
    # to per-update append + latest-version semantics like ASR/CET.
    p = _path(_ITQ)
    with p.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")

    append_event("itq_answered",
                 {"question_id": question_id, "source": source},
                 actor=actor)
    return rows[target_idx]


# ---------------------------------------------------------------------------
# Briefings
# ---------------------------------------------------------------------------


def briefing_post(summary_md: str, author: str = "investigation-section-chief") -> dict[str, Any]:
    bid = _now_iso().replace(":", "-")
    p = case_dir() / _BRIEFINGS / f"{bid}.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(summary_md, encoding="utf-8")
    append_event("briefing_posted",
                 {"briefing_id": bid, "author": author, "bytes": len(summary_md)},
                 actor=author)
    # Update case header pointer
    try:
        header = case_get_header()
        header["current_briefing_id"] = bid
        case_write_header(header, actor=author)
    except FileNotFoundError:
        pass
    return {"briefing_id": bid, "written_by": author, "written_at": _now_iso(),
            "summary_md": summary_md}


def briefing_latest() -> dict[str, Any] | None:
    bdir = case_dir() / _BRIEFINGS
    if not bdir.exists():
        return None
    files = sorted(bdir.glob("*.md"))
    if not files:
        return None
    latest = files[-1]
    return {"briefing_id": latest.stem,
            "written_at": latest.stem.replace("-", ":", 2),
            "summary_md": latest.read_text(encoding="utf-8")}


def briefing_history(limit: int = 20) -> list[dict[str, Any]]:
    bdir = case_dir() / _BRIEFINGS
    if not bdir.exists():
        return []
    files = sorted(bdir.glob("*.md"), reverse=True)[:limit]
    return [
        {"briefing_id": f.stem, "summary_md": f.read_text(encoding="utf-8")}
        for f in files
    ]


# ---------------------------------------------------------------------------
# Case init (used by `sift-case-init` CLI)
# ---------------------------------------------------------------------------


def init_case(case_id: str, name: str, ic_name: str, ic_contact: str = "",
              itq_template: Path | str | None = None,
              context: str = "") -> dict[str, Any]:
    """Create a fresh case directory layout. Idempotent only on cold start.

    The very first hash-chained audit event written for a case is a
    Software Bill of Materials snapshot (``sbom_snapshot``). Every later
    event is therefore cryptographically downstream of a known toolchain
    state; if anyone questions whether the analyst tooling was compromised
    mid-investigation, the snapshot persisted at ``<case>/sbom.json`` can
    be re-computed and compared to ``payload.sbom_hash`` in audit row 1.
    """
    from . import sbom as _sbom  # local import keeps the case_state surface area unchanged

    cd = case_dir()
    cd.mkdir(parents=True, exist_ok=True)
    if (cd / _CASE_HEADER).exists():
        raise FileExistsError(f"Case already initialised at {cd}")

    # Snapshot the runtime before any case state is written so this lands as
    # the first row of forensic_audit.jsonl.
    snapshot = _sbom.compute_sbom()
    snapshot_hash = _sbom.hash_sbom(snapshot)
    _sbom.write_sbom(cd / "sbom.json", snapshot)
    append_event(
        "sbom_snapshot",
        {
            "sbom_hash": snapshot_hash,
            "sbom_path": "sbom.json",
            "package_count": len(snapshot["packages"]),
            "siftics_git_head": snapshot["siftics_git_head"],
            "python_version": snapshot["python_version"],
            "platform": snapshot["platform"],
        },
        actor="case-init",
    )

    header = asdict(CaseHeader(
        case_id=case_id,
        name=name,
        opened_at=_now_iso(),
        incident_commander={"name": ic_name, "contact": ic_contact,
                            "ic_pubkey_fingerprint": ""},
        context=context.strip(),
        last_updated_at=_now_iso(),
        last_updated_by="case-init",
    ))
    case_write_header(header, actor="case-init")
    append_event("case_initialised",
                 {"case_id": case_id, "ic_name": ic_name},
                 actor="case-init")
    seed_template = Path(itq_template) if itq_template else _default_itq_template_path()
    if seed_template:
        itq_seed_from_template(seed_template, actor="case-init")
    return header
