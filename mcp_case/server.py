"""mcp_case — Custom MCP server exposing the case state to any MCP client.

Run as stdio (default; for Claude Code):
    python -m mcp_case.server

Run as HTTP+SSE:
    python -m mcp_case.server --transport sse --port 9100

Required env: SIFTICS_CASE_DIR (path to the case directory).

Architectural property: every function below is *typed* and *narrow*. There is no
`run_shell()`, `eval_python()`, or `read_file_arbitrary()`. The agent can only
mutate the COP via the 11 typed functions in this file.
"""
from __future__ import annotations

import argparse
import os
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from siftics import audit, case_state, findings as findings_lib

mcp = FastMCP("siftics-case-state")


# ---------------------------------------------------------------------------
# Audit-chain referential integrity (anti-fabrication guard)
# ---------------------------------------------------------------------------
#
# Authority Gate actions emit IDs shaped <prefix>_<hex> — e.g. intel_5a01abc2
# for an executed publish_intel gate, exec_* for a hunt, iso_*/cont_* for
# containment, req_* for an approval request. The agent legitimately
# references these IDs back in ASR notes / CET entries / case header fields
# to anchor narrative to executed actions.
#
# The failure mode this guard prevents: agent writes a fabricated ID into an
# ASR note ("ISOLATION REQUESTED (iso_ae59264c)") without firing the gate
# workflow that would produce a real iso_ae59264c action_executed event in
# forensic_audit.jsonl. The note looks authoritative; the ID resolves to
# nothing.
#
# Rule (enforced at the schema layer of every case-state write that carries
# free text): every action-ID-shaped token in the write payload MUST exist
# in the audit chain's prior payloads. References to real IDs are fine;
# invented IDs are rejected.

_ACTION_ID_PREFIXES = (
    "iso", "exec", "hunt", "gate", "req", "cont", "intel",
    "isolation", "containment", "approval", "sig",
)
_ACTION_ID_PATTERN = re.compile(
    r"\b(?:" + "|".join(_ACTION_ID_PREFIXES) + r")_[a-f0-9]{4,}\b",
    re.IGNORECASE,
)


def _walk_strings(obj):
    """Yield every string value reachable in obj (recurses into dict /
    list / tuple). None and other scalar types are skipped."""
    if obj is None:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _walk_strings(v)


def _audit_chain_known_action_ids() -> set[str]:
    """Collect every action-ID-shaped token that appears in any prior
    audit event payload. These are the IDs the agent may legitimately
    reference in a subsequent case-state write."""
    known: set[str] = set()
    for ev in case_state.iter_events():
        payload = ev.get("payload")
        if not payload:
            continue
        for s in _walk_strings(payload):
            for m in _ACTION_ID_PATTERN.findall(s):
                known.add(m.lower())
    return known


def _verify_audit_chain_refs(payload, write_name: str) -> None:
    """Anti-fabrication guard. Walks every string in payload; any
    action-ID-shaped token that does not exist in the audit chain
    raises ValueError. Calls at the MCP tool boundary so the agent
    cannot persist a fabricated reference.

    To reference a real action ID, the agent must have fired the action
    through the Authority Gate workflow first (request_approval → sign
    → action_executed). That produces an audit event with the ID; only
    then may the ID appear in ASR notes, CET entries, case header
    fields, briefings, etc.
    """
    found: set[str] = set()
    for s in _walk_strings(payload):
        for m in _ACTION_ID_PATTERN.findall(s):
            found.add(m.lower())
    if not found:
        return
    known = _audit_chain_known_action_ids()
    unknown = sorted(found - known)
    if unknown:
        raise ValueError(
            f"audit-chain referential integrity violation in {write_name}: "
            f"the following action-ID-shaped strings appear in the payload "
            f"but do not exist anywhere in forensic_audit.jsonl: {unknown}. "
            f"This is the anti-fabrication guard — every {{prefix}}_{{hex}} "
            f"token referenced in case state must trace back to a real "
            f"audit-chain event. To produce a real ID, fire the action "
            f"through the gate workflow first: ic_request_approval → "
            f"sign_approval → action_executed."
        )


# ---------------------------------------------------------------------------
# Case header (Incident Common Operating Picture)
# ---------------------------------------------------------------------------


@mcp.tool()
def case_get_header() -> dict:
    """Return the current Incident COP header - IC, deputies, scope, impact
    level, plus the IC's free-form ``context`` briefing if one was written
    at case-init. The briefing is the IC's initial *hypothesis* of what
    happened and what evidence was pulled; treat it as orientation, not as
    ground truth, and verify every claim against evidence."""
    return case_state.case_get_header()


@mcp.tool()
def case_update_header(fields: dict[str, Any]) -> dict:
    """Update fields in the case header. Writes case_header_updated audit event.

    Args:
        fields: mapping of field name to new value (e.g. {"impact_level": "critical"}).
    """
    _verify_audit_chain_refs(fields, write_name="case_update_header")
    return case_state.case_update_header(fields, actor="investigation-section-chief")


@mcp.tool()
def case_set_motivation(text: str) -> dict:
    """Set the attacker-motivation field on the case header.

    Call this **once hypothesis convergence is established** — i.e. when
    one attacker-intent hypothesis has substantively more supporting
    evidence than the alternatives in the Hypothesis Engine, and you can
    write a one- or two-sentence characterisation grounded in specific
    finding IDs or ASR rows.

    The text goes verbatim into the "Why" sentence of the report's
    Executive Summary, so write it as a complete sentence (subject + verb)
    that a CISO could read aloud. Cite evidence inline.

    Examples (good):
      - "Financially-motivated ransomware deployment — coreupdater service
         + vssadmin shadow-delete on F-009/F-011 align with RansomHub TTPs."
      - "Espionage-aligned credential theft for downstream access — DCSync
         on CITADEL-DC01 (F-008) followed by KRBTGT hash export, no
         destructive payload observed."

    Examples (insufficient):
      - "Unknown."
      - "Probably ransomware."
      - "TBD"

    Writes a `case_motivation_set` audit event so a reviewer replaying
    the chain sees the moment the IC narrative locked in.

    Args:
        text: the motivation sentence. Must be at least 25 characters
              and contain a verb-shaped statement, not a placeholder.
    """
    cleaned = (text or "").strip()
    if len(cleaned) < 25:
        raise ValueError(
            "case_set_motivation requires a substantive characterisation "
            "(>= 25 chars). Wait for hypothesis convergence before calling."
        )
    if cleaned.lower() in {"unknown", "tbd", "pending", "n/a", "none"}:
        raise ValueError(
            "case_set_motivation rejects placeholder values. Either skip "
            "the call (the Executive Summary handles the empty case) or "
            "wait for evidence before naming a motive."
        )
    header = case_state.case_update_header({"motivation": cleaned},
                                           actor="investigation-section-chief")
    # Separate audit event so the moment of characterisation is greppable
    case_state.append_event("case_motivation_set",
                            {"length": len(cleaned),
                             "first_120_chars": cleaned[:120]},
                            actor="investigation-section-chief")
    return header


def _read_locked_completeness_categories() -> list[dict] | None:
    """Return the locked checklist of investigation categories for this case,
    or None if no checklist has been locked yet.

    The lock is the first `case_completeness_checklist_locked` audit event.
    Subsequent calls to `case_completeness_check` must evaluate coverage
    against this list (with explicit expansion events recorded separately).
    """
    for ev in case_state.iter_events():
        if ev.get("type") == "case_completeness_checklist_locked":
            return (ev.get("payload") or {}).get("categories") or []
    return None


@mcp.tool()
def case_completeness_check(review: dict) -> dict:
    """Record the persona-driven completeness review of the case.

    Companion to `anti_forensics_review` — both run at the same pre-close
    checkpoint and complement each other. While `anti_forensics_review`
    handles the open-ended adversarial domain, this tool handles the
    bounded "did we exercise the investigation categories this case
    demands" question.

    **Creative-mitigation determinism pattern** (first-run-locks-the-questions):

      - First call to this tool (no prior `case_completeness_checklist_locked`
        event in the audit chain): the persona enumerates the investigation
        categories this specific case demands, given attacker actions,
        host platform, evidence types. The enumeration is written to the
        audit chain as `case_completeness_checklist_locked` — that list is
        now the canonical checklist for the case.
      - Subsequent calls: the persona reads the locked checklist and
        produces a coverage assessment indexed by category_id. The schema
        rejects any coverage_assessment entry whose category_id is not in
        the lock — proposing new categories requires explicit
        `proposed_new_categories` + `expansion_rationale` and writes a
        separate `case_completeness_checklist_expansion_proposed` event
        that the IC can review.

    The result: rerunning the critic on the same case state produces
    matching gaps (deterministic against the locked checklist), but the
    *first* enumeration is full persona judgement (where it matters).

    Expected ``review`` shape::

        {
          "action_hash": "<sha256 of case state at review time>",
          "investigation_categories": [   # required on first call;
                                          # informational on subsequent calls
                                          # (must match locked set)
            {
              "category_id": "timezone_registry_read",
              "rationale": "Windows hosts in ASR — timestamps anchor every
                            finding; offset undetectable without TZ hive",
              "what_should_have_run": "RegRipper -p timezone or regipy on
                                       the SYSTEM hive of each Windows host"
            },
            ...
          ],
          "coverage_assessment": [
            {
              "category_id": "timezone_registry_read",
              "what_was_actually_done": "Agent computed a 62-min offset
                                         empirically from PCAP↔EVTX
                                         correlation (F-009) but did not
                                         read the registry key",
              "gap": "Empirical offset is not a substitute for the registry
                      value — record the TZ key for chain integrity",
              "gap_severity": "medium"
            },
            ...
          ],
          # Optional — only on subsequent calls
          "proposed_new_categories": [   # if persona judges the case has
                                          # evolved (new ASR rows, new
                                          # attacker actions) and additional
                                          # categories now apply
            {"category_id": "...", "rationale": "...",
             "what_should_have_run": "..."}
          ],
          "expansion_rationale": "<why these are new — required if
                                  proposed_new_categories non-empty>",
          "summary": "<>=30 chars substantive conclusion>",
          "reviewer_certainty": "high" | "medium" | "low"
        }

    Validation:
      - On first call: investigation_categories required, non-empty;
        each carries category_id, rationale (≥30 chars), what_should_have_run
      - On subsequent calls: investigation_categories must equal the lock
        (set comparison on category_id); any divergence rejected unless
        flagged via proposed_new_categories with expansion_rationale
      - coverage_assessment: every category_id must be in the active set
        (lock ∪ proposed_new); gap_severity ∈ {high, medium, low, none};
        severity=none requires empty gap; severity≠none requires substantive gap
      - summary ≥ 30 chars
      - reviewer_certainty ∈ {high, medium, low}

    Audit events:
      - First call → `case_completeness_checklist_locked` (the lock)
        + `case_completeness_check_run` (the assessment)
      - Subsequent call → `case_completeness_check_run`
      - Subsequent call with proposed_new_categories →
        `case_completeness_checklist_expansion_proposed`
        + `case_completeness_check_run`

    Returns ``{"audit_row_seq": int, "is_first_run": bool,
               "categories_assessed": int, "gaps_high": int,
               "gaps_medium": int, "gaps_low": int,
               "expansion_proposed": bool, "reviewer_certainty": str}``.

    Raises ``ValueError`` on schema violations.
    """
    if not isinstance(review, dict):
        raise ValueError("completeness review must be a dict")

    locked = _read_locked_completeness_categories()
    is_first_run = locked is None

    provided = review.get("investigation_categories") or []
    proposed_new = review.get("proposed_new_categories") or []
    expansion_rationale = (review.get("expansion_rationale") or "").strip()

    if not isinstance(provided, list):
        raise ValueError("investigation_categories must be a list")
    if not isinstance(proposed_new, list):
        raise ValueError("proposed_new_categories must be a list")

    def _validate_category_shape(cats: list, label: str) -> None:
        for i, c in enumerate(cats):
            if not isinstance(c, dict):
                raise ValueError(f"{label}[{i}] must be a dict")
            cid = (c.get("category_id") or "").strip()
            if not cid or " " in cid:
                raise ValueError(
                    f"{label}[{i}].category_id must be a non-empty, "
                    f"space-free identifier; got {cid!r}")
            rationale = (c.get("rationale") or "").strip()
            if len(rationale) < 30:
                raise ValueError(
                    f"{label}[{i}].rationale must be at least 30 chars "
                    f"(substantive — why this category applies to THIS case)")
            if not (c.get("what_should_have_run") or "").strip():
                raise ValueError(
                    f"{label}[{i}].what_should_have_run must be non-empty "
                    f"(name the specific tool / command / artefact source)")

    if is_first_run:
        if not provided:
            raise ValueError(
                "first call to case_completeness_check requires non-empty "
                "investigation_categories — the persona enumerates the "
                "checklist this case demands; that enumeration is locked "
                "into the audit chain for subsequent runs")
        if proposed_new:
            raise ValueError(
                "proposed_new_categories not allowed on first call — the "
                "initial enumeration IS the lock; expansion only makes "
                "sense once a lock exists")
        _validate_category_shape(provided, "investigation_categories")
        active_categories = provided
    else:
        # Lock exists. Provided categories MUST equal the locked set.
        locked_ids = {c["category_id"] for c in locked}
        provided_ids = {c.get("category_id") for c in provided}
        if provided_ids != locked_ids:
            raise ValueError(
                f"investigation_categories must equal the locked checklist "
                f"(locked: {sorted(locked_ids)}; provided: "
                f"{sorted(x for x in provided_ids if x)}); "
                f"to add categories, set proposed_new_categories instead")
        if proposed_new:
            _validate_category_shape(proposed_new, "proposed_new_categories")
            if len(expansion_rationale) < 30:
                raise ValueError(
                    "proposed_new_categories requires expansion_rationale "
                    "≥ 30 chars explaining why the case has evolved to "
                    "demand additional categories")
        active_categories = list(locked) + list(proposed_new)

    active_ids = {c["category_id"] for c in active_categories}
    coverage = review.get("coverage_assessment") or []
    if not isinstance(coverage, list):
        raise ValueError("coverage_assessment must be a list")

    allowed_sev = {"high", "medium", "low", "none"}
    counts = {"high": 0, "medium": 0, "low": 0, "none": 0}
    seen_in_coverage: set[str] = set()
    for i, c in enumerate(coverage):
        if not isinstance(c, dict):
            raise ValueError(f"coverage_assessment[{i}] must be a dict")
        cid = c.get("category_id")
        if cid not in active_ids:
            raise ValueError(
                f"coverage_assessment[{i}].category_id={cid!r} is not in the "
                f"active category set; either add it via "
                f"proposed_new_categories or fix the typo")
        if cid in seen_in_coverage:
            raise ValueError(
                f"coverage_assessment[{i}].category_id={cid!r} duplicated")
        seen_in_coverage.add(cid)
        sev = c.get("gap_severity")
        if sev not in allowed_sev:
            raise ValueError(
                f"coverage_assessment[{i}].gap_severity must be one of "
                f"{sorted(allowed_sev)}; got {sev!r}")
        gap_text = c.get("gap")
        if sev == "none":
            if gap_text:
                raise ValueError(
                    f"coverage_assessment[{i}] has gap_severity=none "
                    f"but a non-empty gap description")
        else:
            if not isinstance(gap_text, str) or not gap_text.strip():
                raise ValueError(
                    f"coverage_assessment[{i}] has gap_severity={sev!r} "
                    f"but no gap description")
        counts[sev] += 1

    # Every active category must appear in coverage_assessment
    missing_from_coverage = active_ids - seen_in_coverage
    if missing_from_coverage:
        raise ValueError(
            f"coverage_assessment is missing entries for: "
            f"{sorted(missing_from_coverage)}")

    summary = (review.get("summary") or "").strip()
    if len(summary) < 30:
        raise ValueError(
            "completeness review summary must be at least 30 chars")
    cert = review.get("reviewer_certainty")
    if cert not in {"high", "medium", "low"}:
        raise ValueError(
            f"reviewer_certainty must be one of high|medium|low; got {cert!r}")

    # Write the lock on first run
    if is_first_run:
        case_state.append_event(
            "case_completeness_checklist_locked",
            {"categories": provided},
            actor="completeness-reviewer",
        )

    # Record expansion proposal separately so the IC can review
    if proposed_new:
        case_state.append_event(
            "case_completeness_checklist_expansion_proposed",
            {"new_categories": proposed_new,
             "expansion_rationale": expansion_rationale},
            actor="completeness-reviewer",
        )

    row = case_state.append_event(
        "case_completeness_check_run", review,
        actor="completeness-reviewer")

    return {
        "audit_row_seq": row["seq"],
        "is_first_run": is_first_run,
        "categories_assessed": len(active_categories),
        "gaps_high": counts["high"],
        "gaps_medium": counts["medium"],
        "gaps_low": counts["low"],
        "expansion_proposed": bool(proposed_new),
        "reviewer_certainty": cert,
    }


@mcp.tool()
def case_add_external_ticket(system: str, ticket_id: str, url: str) -> dict:
    """Link an external ticket (Jira, ServiceNow, etc.) into the case."""
    header = case_state.case_get_header()
    header.setdefault("external_tickets", []).append(
        {"system": system, "id": ticket_id, "url": url}
    )
    return case_state.case_write_header(header, actor="investigation-section-chief")


# ---------------------------------------------------------------------------
# Affected Systems Register (ASR / SUIT)
# ---------------------------------------------------------------------------


@mcp.tool()
def asr_append(
    system_type: str,
    system_identifier: str,
    location: str,
    date_of_detection: str,
    date_of_compromise: str,
    how_determined: str,
    impact_rating: str,
    impact_description: str,
    planned_action: str,
    system_safe: str = "not_safe",
    duration_estimate_hours: int = 0,
    complexity: str = "medium",
    dependencies: list[str] | None = None,
    notes: str = "",
    linked_findings: list[str] | None = None,
    linked_hunts: list[str] | None = None,
) -> dict:
    """Append a new row to the Affected Systems Register.

    Args:
        system_type: e.g. "Windows 11 workstation".
        system_identifier: hostname or unique ID.
        location: IP and/or OU path.
        date_of_detection: ISO-8601 UTC.
        date_of_compromise: ISO-8601 UTC (best estimate; pre-fill from earliest evidence).
        how_determined: brief evidence chain ("Sysmon Event 1: …").
        impact_rating: low | moderate | high | critical.
        system_safe: not_safe | safe | pending_verification.
    """
    payload = {
        "system_type": system_type, "system_identifier": system_identifier,
        "location": location, "date_of_detection": date_of_detection,
        "date_of_compromise": date_of_compromise, "how_determined": how_determined,
        "impact_rating": impact_rating, "impact_description": impact_description,
        "planned_action": planned_action, "system_safe": system_safe,
        "duration_estimate_hours": duration_estimate_hours,
        "complexity": complexity, "dependencies": dependencies or [],
        "notes": notes, "linked_findings": linked_findings or [],
        "linked_hunts": linked_hunts or [],
    }
    _verify_audit_chain_refs(payload, write_name="asr_append")
    return case_state.asr_append(payload, actor="investigation-section-chief")


@mcp.tool()
def asr_update(serial_no: str, fields: dict[str, Any]) -> dict:
    """Update a row in the Affected Systems Register. Appends a new version row.

    Args:
        serial_no: ASR-N identifier.
        fields: mapping of field to new value (e.g. {"system_safe": "safe"}).
    """
    _verify_audit_chain_refs(fields, write_name="asr_update")
    return case_state.asr_update(serial_no, fields, actor="investigation-section-chief")


@mcp.tool()
def asr_open() -> list[dict]:
    """Return ASR rows where system_safe is not yet 'safe'."""
    return case_state.asr_open()


@mcp.tool()
def asr_all() -> list[dict]:
    """Return every ASR row (latest versions only)."""
    return case_state.asr_all()


# ---------------------------------------------------------------------------
# Containment & Eradication Tracker (CET / CCA)
# ---------------------------------------------------------------------------


@mcp.tool()
def cet_append(
    data_source: str,
    source_paths: list[str],
    timestamp_compromised: str,
    owner_informed: bool,
    analysis_status: str,
    leaked: str,
    effort_to_remediate_days: int,
    priority_order: int,
    secrets_status: str = "not_yet_checked",
    cloud_creds_status: str = "not_yet_checked",
    certs_priv_keys_status: str = "not_yet_checked",
    ssh_api_keys_status: str = "not_yet_checked",
    full_remediation_required: bool = False,
    ip_impact: str = "unknown",
    third_party_products: list[str] | None = None,
    notes: str = "",
    point_of_contact: str = "",
) -> dict:
    """Append a row to the Containment & Eradication Tracker.

    Args:
        analysis_status: not_started | in_progress | checked | none_present_complete.
        leaked: not_yet_checked | no | yes.
        priority_order: integer ≥ 1; lower is more urgent.
        *_status fields: not_yet_checked | none_present_complete | checked_roll_scheduled | rolled_complete.
    """
    payload = {
        "data_source": data_source, "source_paths": source_paths,
        "timestamp_compromised": timestamp_compromised,
        "owner_informed": owner_informed, "analysis_status": analysis_status,
        "leaked": leaked, "effort_to_remediate_days": effort_to_remediate_days,
        "priority_order": priority_order, "secrets_status": secrets_status,
        "cloud_creds_status": cloud_creds_status,
        "certs_priv_keys_status": certs_priv_keys_status,
        "ssh_api_keys_status": ssh_api_keys_status,
        "full_remediation_required": full_remediation_required,
        "ip_impact": ip_impact, "third_party_products": third_party_products or [],
        "notes": notes, "point_of_contact": point_of_contact,
    }
    _verify_audit_chain_refs(payload, write_name="cet_append")
    return case_state.cet_append(payload, actor="investigation-section-chief")


@mcp.tool()
def cet_update(cca_no: str, fields: dict[str, Any]) -> dict:
    """Update a CET row (append new version)."""
    _verify_audit_chain_refs(fields, write_name="cet_update")
    return case_state.cet_update(cca_no, fields, actor="investigation-section-chief")


@mcp.tool()
def cet_pending() -> list[dict]:
    """Return CET rows where any *_status is still pending."""
    return case_state.cet_pending()


# ---------------------------------------------------------------------------
# Initial Triage Questionnaire (ITQ / Grid)
# ---------------------------------------------------------------------------


@mcp.tool()
def itq_unanswered() -> list[dict]:
    """Return triage questions still open or in progress.
    This is the primary 'what to drive next' surface for the agent.
    """
    return case_state.itq_unanswered()


@mcp.tool()
def itq_answer(question_id: str, answer: str, source: str = "agent",
               resulting_task: str = "") -> dict:
    """Answer one ITQ question. Appends itq_answered audit event.

    Args:
        question_id: ITQ-NNN identifier.
        answer: free text answer.
        source: ic | agent | auto_tooling.
        resulting_task: optional task to record (overrides default_task).
    """
    return case_state.itq_answer(question_id, answer, source=source,
                                  resulting_task=(resulting_task or None),
                                  actor="investigation-section-chief")


@mcp.tool()
def itq_progress() -> dict:
    """Return {answered, total, pct} progress through the questionnaire."""
    return case_state.itq_progress()


# ---------------------------------------------------------------------------
# Briefings
# ---------------------------------------------------------------------------


@mcp.tool()
def briefing_post(summary_md: str) -> dict:
    """Write a new briefing into the case directory and update the current pointer.

    Args:
        summary_md: markdown body; will be timestamped and saved.
    """
    return case_state.briefing_post(summary_md,
                                     author="investigation-section-chief")


@mcp.tool()
def briefing_latest() -> dict | None:
    """Return the most recent briefing (id, written_at, summary_md)."""
    return case_state.briefing_latest()


# ---------------------------------------------------------------------------
# Evidence-linked findings register
# ---------------------------------------------------------------------------


@mcp.tool()
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
) -> dict:
    """Record a finding with full evidence chain: claim → artifact → tool → command → output.

    Call this **every time** you state a factual claim that comes from an artifact.
    A finding is reproducible — a third party must be able to re-run `command`
    against `artifact_source` and see `output_excerpt` to verify `claim`.

    Args:
        claim:           One-sentence factual statement. What was found.
                         e.g. "Subject authenticated <service> with <account identifier>"
        artifact_path:   Path to the artifact inside the image or case dir.
                         e.g. "C:\\Users\\<user>\\AppData\\Local\\<vendor>\\<app>\\<logfile>"
        artifact_source: Which exhibit the artifact lives in.
                         e.g. "<case_id>_workstation.dd" or "memdump.mem"
        tool:            Tool used to extract/parse the artifact.
                         e.g. "icat", "strings", "EvtxECmd", "pypff", "fls", "regipy"
        command:         Exact command, reproducible by anyone with the image.
                         e.g. "icat -o <offset> <image> <inode> | grep -i <pattern>"
        output_excerpt:  Relevant slice of stdout that supports the claim (≤ 500 chars).
                         e.g. "<timestamp> INFO Account: <recovered identifier>"
        linked_itq:      ITQ-NNN this finding answers (optional).
        linked_asr:      ASR serial this finding belongs to (optional).
        linked_cet:      CCA number this finding belongs to (optional).

    Returns the finding row including its assigned F-NNN id.
    """
    return findings_lib.finding_record(
        claim=claim,
        artifact_path=artifact_path,
        artifact_source=artifact_source,
        tool=tool,
        command=command,
        output_excerpt=output_excerpt,
        linked_itq=linked_itq,
        linked_asr=linked_asr,
        linked_cet=linked_cet,
        actor="investigation-section-chief",
    )


@mcp.tool()
def finding_list(linked_itq: str = "", linked_asr: str = "") -> list[dict]:
    """Return recorded findings, optionally filtered by ITQ or ASR link.

    Use with no args to get all findings. Use linked_itq="ITQ-051" to see
    only findings that support a specific triage answer.
    """
    return findings_lib.finding_list(linked_itq=linked_itq, linked_asr=linked_asr)


# ---------------------------------------------------------------------------
# Command Staff consults — Safety Officer & Legal Officer
# ---------------------------------------------------------------------------
#
# These tools record structured assessments from the Safety Officer and Legal
# Officer roles (see skills/safety-officer.md, skills/legal-officer.md).
# The agent loads the relevant skill as a sub-prompt, produces the assessment
# JSON, and submits it via the matching tool. The tool validates schema, writes
# a hash-chained audit event, and returns the audit row id + verdict.
#
# In a follow-up commit, `ic_approval.request_approval()` will refuse to issue
# an ApprovalRequest unless a recent matching assessment exists in the audit
# chain (and refuse outright on Safety hard_stop / Legal counsel-required).
# That wire-up is staged separately because it requires updating every site in
# tests/test_constraints.py to seed clear consults first.

_SAFETY_DIMENSIONS = frozenset({
    "business_impact", "personnel_safety", "investigation_safety",
    "scope_pollution", "operational_tempo",
})
_SAFETY_VERDICTS = frozenset({"clear", "caution", "hard_stop"})
_DIMENSION_SCORES = frozenset({"low", "medium", "high", "critical"})


def _validate_assessment(assessment: dict, required_dims: frozenset[str],
                         allowed_verdicts: frozenset[str], role: str) -> None:
    """Shared schema check for Safety/Legal assessments."""
    if not isinstance(assessment, dict):
        raise ValueError(f"{role} assessment must be a dict")
    required_top = {"action_hash", "verdict", "dimensions", "preconditions",
                    "cited_evidence"}
    missing = required_top - assessment.keys()
    if missing:
        raise ValueError(
            f"{role} assessment missing required fields: {sorted(missing)}")
    if assessment["verdict"] not in allowed_verdicts:
        raise ValueError(
            f"{role} verdict must be one of {sorted(allowed_verdicts)}, "
            f"got {assessment['verdict']!r}")
    dims = assessment.get("dimensions") or {}
    if set(dims.keys()) != required_dims:
        raise ValueError(
            f"{role} dimensions must be exactly {sorted(required_dims)}, "
            f"got {sorted(dims.keys())}")
    for name, entry in dims.items():
        if not isinstance(entry, dict):
            raise ValueError(f"{role} dimension {name!r} must be a dict")
        score = entry.get("score")
        if score not in _DIMENSION_SCORES:
            raise ValueError(
                f"{role} dimension {name!r}: score must be one of "
                f"{sorted(_DIMENSION_SCORES)}, got {score!r}")
        rationale = entry.get("rationale") or ""
        if not isinstance(rationale, str) or len(rationale) > 400:
            raise ValueError(
                f"{role} dimension {name!r}: rationale must be a string "
                f"of <=400 chars")


@mcp.tool()
def consult_safety_officer(assessment: dict) -> dict:
    """Record a Safety Officer assessment for a pending or proposed Authority
    Gate.

    The agent computes the assessment by loading the `/safety-officer` skill,
    reviewing the action context, and producing the structured output per the
    skill's output schema. This tool validates the schema and writes a
    `safety_assessment` audit event linked to the action's content hash.

    The five dimensions are: ``business_impact``, ``personnel_safety``,
    ``investigation_safety``, ``scope_pollution``, ``operational_tempo``.
    Verdicts: ``clear``, ``caution``, ``hard_stop``. Personnel-safety is the
    only dimension that hard-stops; everything else caps at ``caution``.

    Returns ``{"audit_row_seq": int, "verdict": str}``.

    Raises ``ValueError`` if the schema is malformed.
    """
    _validate_assessment(assessment, _SAFETY_DIMENSIONS,
                          _SAFETY_VERDICTS, role="safety")
    # Enforce the personnel_safety hard-stop rule at the schema level so a
    # malformed verdict cannot smuggle through.
    ps = assessment["dimensions"]["personnel_safety"]["score"]
    if ps in ("high", "critical") and assessment["verdict"] != "hard_stop":
        raise ValueError(
            f"safety assessment must be hard_stop when personnel_safety "
            f"is {ps!r}; got verdict={assessment['verdict']!r}")
    row = audit.append_event(
        "safety_assessment", assessment, actor="safety-officer")
    return {"audit_row_seq": row["seq"], "verdict": assessment["verdict"]}


_LEGAL_DIMENSIONS = frozenset({
    "privilege_scope", "breach_notification", "regulator_triggers",
    "evidence_admissibility", "third_party_nda_scope",
})
_LEGAL_VERDICTS = frozenset({"clear", "caution", "outside_counsel_required"})


@mcp.tool()
def consult_legal_officer(assessment: dict) -> dict:
    """Record a Legal Officer assessment for a pending or proposed Authority
    Gate.

    The agent computes the assessment by loading the `/legal-officer` skill,
    reviewing the action context, and producing the structured output per the
    skill's output schema. This tool validates the schema and writes a
    `legal_review` audit event linked to the action's content hash.

    The five dimensions are: ``privilege_scope``, ``breach_notification``,
    ``regulator_triggers``, ``evidence_admissibility``, ``third_party_nda_scope``.
    Verdicts: ``clear``, ``caution``, ``outside_counsel_required``.

    The Legal Officer can only require that outside counsel be looped into the
    matter — it does not substitute for counsel's judgment. When the verdict
    is ``outside_counsel_required``, the IC must record a
    ``counsel_acknowledged`` event before the gate is signable.

    Returns ``{"audit_row_seq": int, "verdict": str,
               "counsel_loop_required": bool, "clocks_started": list}``.

    Raises ``ValueError`` if the schema is malformed.
    """
    _validate_assessment(assessment, _LEGAL_DIMENSIONS,
                          _LEGAL_VERDICTS, role="legal")
    if not isinstance(assessment.get("counsel_loop_required"), bool):
        raise ValueError("legal assessment requires boolean counsel_loop_required")
    clocks = assessment.get("clocks_started", [])
    if not isinstance(clocks, list):
        raise ValueError("legal assessment clocks_started must be a list")
    row = audit.append_event(
        "legal_review", assessment, actor="legal-officer")
    return {
        "audit_row_seq": row["seq"],
        "verdict": assessment["verdict"],
        "counsel_loop_required": assessment["counsel_loop_required"],
        "clocks_started": clocks,
    }


@mcp.tool()
def anti_forensics_review(review: dict) -> dict:
    """Record the agent's anti-forensics review of the case.

    Anti-forensics is open-ended adversarial — no fixed checklist captures
    its surface for an arbitrary case. The agent loads the
    ``/anti-forensics-review`` skill, reads the case, enumerates every
    distinct attacker action recorded, reasons about plausible evasion
    techniques for each, and checks coverage. This tool validates the
    structured output and writes an ``anti_forensics_review_completed``
    audit event.

    Distinct from ``case_completeness_check`` (which catches bounded
    yes/no tool-invocation gaps) — both run at the same pre-close
    checkpoint and complement each other.

    Expected ``review`` shape::

        {
          "action_hash": "<sha256 of case state at time of review>",
          "attacker_actions_enumerated": [
            {"action": "...", "source_finding_ids": ["F-012", "F-014"]},
            ...
          ],
          "coverage_assessment": [
            {
              "action_idx": <int — index into attacker_actions_enumerated>,
              "plausible_evasions": ["...", "..."],
              "what_was_checked": ["..."],
              "gap": "<gap description, or null>",
              "gap_severity": "high" | "medium" | "low" | "none"
            },
            ...
          ],
          "summary": "<short summary, >= 30 chars>",
          "reviewer_certainty": "high" | "medium" | "low"
        }

    Validation rules:
      - attacker_actions_enumerated must be non-empty (an empty case is
        not a reviewable case; load the skill again and read more findings)
      - every coverage_assessment.action_idx must reference a valid index
      - gap_severity must be high|medium|low|none; if "none", gap must be
        null or empty; if not "none", gap must be a non-empty string
      - summary >= 30 chars
      - reviewer_certainty must be one of {high, medium, low}

    Returns ``{"audit_row_seq": int, "actions_reviewed": int,
               "gaps_high": int, "gaps_medium": int, "gaps_low": int,
               "reviewer_certainty": str}``.

    Raises ``ValueError`` on schema violations.
    """
    if not isinstance(review, dict):
        raise ValueError("anti-forensics review must be a dict")

    actions = review.get("attacker_actions_enumerated") or []
    if not isinstance(actions, list) or not actions:
        raise ValueError(
            "anti_forensics_review requires non-empty "
            "attacker_actions_enumerated — an empty case is not a "
            "reviewable case; read more findings before calling this tool")

    coverage = review.get("coverage_assessment") or []
    if not isinstance(coverage, list):
        raise ValueError("coverage_assessment must be a list")

    allowed_sev = {"high", "medium", "low", "none"}
    counts = {"high": 0, "medium": 0, "low": 0, "none": 0}
    for i, c in enumerate(coverage):
        if not isinstance(c, dict):
            raise ValueError(f"coverage_assessment[{i}] must be a dict")
        idx = c.get("action_idx")
        if not isinstance(idx, int) or not (0 <= idx < len(actions)):
            raise ValueError(
                f"coverage_assessment[{i}].action_idx must reference a valid "
                f"index into attacker_actions_enumerated (0..{len(actions) - 1})")
        sev = c.get("gap_severity")
        if sev not in allowed_sev:
            raise ValueError(
                f"coverage_assessment[{i}].gap_severity must be one of "
                f"{sorted(allowed_sev)}; got {sev!r}")
        gap_text = c.get("gap")
        if sev == "none":
            if gap_text:
                raise ValueError(
                    f"coverage_assessment[{i}] has gap_severity=none "
                    f"but a non-empty gap description; either set a "
                    f"non-none severity or clear the gap field")
        else:
            if not isinstance(gap_text, str) or not gap_text.strip():
                raise ValueError(
                    f"coverage_assessment[{i}] has gap_severity={sev!r} "
                    f"but no gap description — describe the gap or set "
                    f"gap_severity to none")
        counts[sev] += 1

    summary = (review.get("summary") or "").strip()
    if len(summary) < 30:
        raise ValueError(
            "anti-forensics review summary must be at least 30 chars "
            "(write a substantive one-line conclusion)")

    cert = review.get("reviewer_certainty")
    if cert not in {"high", "medium", "low"}:
        raise ValueError(
            f"reviewer_certainty must be one of high|medium|low; got {cert!r}")

    row = audit.append_event(
        "anti_forensics_review_completed", review,
        actor="anti-forensics-reviewer")
    return {
        "audit_row_seq": row["seq"],
        "actions_reviewed": len(actions),
        "gaps_high": counts["high"],
        "gaps_medium": counts["medium"],
        "gaps_low": counts["low"],
        "reviewer_certainty": cert,
    }


_FINANCE_DIMENSIONS = frozenset({
    "current_spend", "projection_window", "vendor_engagement",
    "recovery_cost_class", "breach_insurance_scope",
})
_FINANCE_VERDICTS = frozenset({"clear", "advisory", "budget_warning"})


@mcp.tool()
def consult_finance_officer(assessment: dict) -> dict:
    """Record a Finance Officer assessment for the case or for a specific
    proposed action.

    The agent loads the ``/finance-officer`` skill, reviews the cost
    tracker state + the remaining ITQ / open hypotheses / planned hunts,
    and produces the structured assessment per the skill's output schema.
    This tool validates the schema and writes a ``finance_assessment``
    audit event.

    **Doctrine note:** Finance Officer is *informational*. The
    architectural budget hard-stop is the G9 circuit breaker in
    ``siftics/cost_tracker.py`` (``check_budget_or_raise``), which fires
    when the per-case spend hits the configured ceiling regardless of
    what Finance recommends. Finance surfaces the cost trajectory so
    the IC can see the wall before the breaker trips — it doesn't add
    a new architectural constraint.

    The five dimensions are: ``current_spend``, ``projection_window``,
    ``vendor_engagement``, ``recovery_cost_class``, ``breach_insurance_scope``.
    Verdicts: ``clear``, ``advisory``, ``budget_warning``.

    Validation rule: when ``current_spend`` is ``critical`` OR
    ``projection_window`` is ``critical``, the verdict must be
    ``budget_warning`` — the schema layer rejects any other verdict so
    a malformed score-vs-verdict combination cannot smuggle through.

    Returns ``{"audit_row_seq": int, "verdict": str,
               "advisory_to_ic": bool}``.

    Raises ``ValueError`` on schema violations.
    """
    _validate_assessment(assessment, _FINANCE_DIMENSIONS,
                          _FINANCE_VERDICTS, role="finance")
    # Structural rule: critical-budget scores must produce budget_warning.
    # Same shape as the Safety Officer personnel_safety hard-stop guard —
    # ensures a score that the persona can compute cannot be paired with
    # a verdict that masks the implication.
    dims = assessment["dimensions"]
    if any(dims[d]["score"] == "critical"
           for d in ("current_spend", "projection_window")):
        if assessment["verdict"] != "budget_warning":
            raise ValueError(
                "finance assessment must be 'budget_warning' when "
                "current_spend or projection_window is critical; got "
                f"verdict={assessment['verdict']!r}")
    row = audit.append_event(
        "finance_assessment", assessment, actor="finance-officer")
    return {
        "audit_row_seq": row["seq"],
        "verdict": assessment["verdict"],
        "advisory_to_ic": assessment["verdict"] != "clear",
    }


_PIO_DRAFT_TYPES = frozenset({
    "holding_statement", "customer_notification", "press_release",
    "executive_briefing", "customer_faq",
})

# Draft types that MUST cite at least one evidence_ref for every factual
# claim — these go to external audiences and can't carry unverified facts.
_PIO_DRAFTS_REQUIRING_EVIDENCE = frozenset({
    "customer_notification", "press_release",
})


@mcp.tool()
def pio_draft_statement(draft: dict) -> dict:
    """Record a Public Information Officer (PIO) draft statement.

    The agent loads the ``/public-information-officer`` skill, reviews the
    facts confirmed in the audit chain, and produces a draft of one of the
    five PIO deliverables. This tool validates the structure and writes a
    ``pio_draft_recorded`` audit event.

    **Critical workflow detail (NIMS doctrine):** PIO drafts go through a
    three-step approval — PIO drafts → Legal reviews for compliance and
    privilege → IC signs off before publication. This tool only records
    the *draft*; it does NOT publish. The signed-publication flow goes
    through the existing Authority Gate mechanism.

    Expected ``draft`` shape::

        {
          "draft_type": "holding_statement"
                       | "customer_notification"
                       | "press_release"
                       | "executive_briefing"
                       | "customer_faq",
          "audience": "<who reads this — 'customers', 'press', 'board', etc.>",
          "content": "<draft text, >= 50 chars>",
          "evidence_refs": ["F-009", "ASR-1", ...],  # finding/ASR IDs
                                                       # backing every factual claim
          "unconfirmed_claims": [                      # explicitly-labelled
              "Attacker may still be active.",         #   "as of now, unconfirmed"
              ...
          ],
          "requires_legal_review": true,   # always true; workflow gate
          "requires_ic_signoff":   true    # always true; workflow gate
        }

    Validation rules:
      - draft_type must be one of the five
      - content >= 50 chars
      - requires_legal_review and requires_ic_signoff must both be True
      - press_release and customer_notification must have at least one
        evidence_ref (external audiences can't carry unverified facts)
      - unconfirmed_claims, when present, must be a list (an empty list
        is OK — that affirmatively states "no unconfirmed claims")

    Returns ``{"audit_row_seq": int, "draft_type": str, "evidence_count": int,
               "unconfirmed_count": int}``.

    Raises ``ValueError`` on schema violations.
    """
    if not isinstance(draft, dict):
        raise ValueError("pio draft must be a dict")
    dt = draft.get("draft_type")
    if dt not in _PIO_DRAFT_TYPES:
        raise ValueError(
            f"pio draft_type must be one of {sorted(_PIO_DRAFT_TYPES)}; got {dt!r}")
    content = (draft.get("content") or "").strip()
    if len(content) < 50:
        raise ValueError("pio draft content must be at least 50 chars")
    if draft.get("requires_legal_review") is not True:
        raise ValueError(
            "pio drafts must carry requires_legal_review=True — Legal review "
            "is the second step of the PIO → Legal → IC workflow and is "
            "not optional")
    if draft.get("requires_ic_signoff") is not True:
        raise ValueError(
            "pio drafts must carry requires_ic_signoff=True — IC sign-off is "
            "the third step of the PIO → Legal → IC workflow and is not optional")
    refs = draft.get("evidence_refs", [])
    if not isinstance(refs, list):
        raise ValueError("pio draft evidence_refs must be a list (may be empty)")
    if dt in _PIO_DRAFTS_REQUIRING_EVIDENCE and not refs:
        raise ValueError(
            f"pio draft_type={dt!r} must cite at least one evidence_ref "
            "(external audience — no unbacked claims)")
    unconfirmed = draft.get("unconfirmed_claims", [])
    if not isinstance(unconfirmed, list):
        raise ValueError("pio draft unconfirmed_claims must be a list (may be empty)")

    row = audit.append_event("pio_draft_recorded", draft, actor="public-information-officer")
    return {
        "audit_row_seq": row["seq"],
        "draft_type": dt,
        "evidence_count": len(refs),
        "unconfirmed_count": len(unconfirmed),
    }


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="SIFTics case-state MCP server.")
    parser.add_argument("--transport", choices=("stdio", "sse"), default="stdio")
    parser.add_argument("--port", type=int, default=9100,
                        help="Only used with --transport sse.")
    args = parser.parse_args()
    if not os.environ.get("SIFTICS_CASE_DIR"):
        raise SystemExit("SIFTICS_CASE_DIR is required.")
    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse", port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
