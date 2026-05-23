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
from typing import Any

from mcp.server.fastmcp import FastMCP

from siftics import case_state

mcp = FastMCP("siftics-case-state")


# ---------------------------------------------------------------------------
# Case header (Incident Common Operating Picture)
# ---------------------------------------------------------------------------


@mcp.tool()
def case_get_header() -> dict:
    """Return the current Incident COP header — IC, deputies, scope, impact level."""
    return case_state.case_get_header()


@mcp.tool()
def case_update_header(fields: dict[str, Any]) -> dict:
    """Update fields in the case header. Writes case_header_updated audit event.

    Args:
        fields: mapping of field name to new value (e.g. {"impact_level": "critical"}).
    """
    return case_state.case_update_header(fields, actor="investigation-section-chief")


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
    return case_state.asr_append({
        "system_type": system_type, "system_identifier": system_identifier,
        "location": location, "date_of_detection": date_of_detection,
        "date_of_compromise": date_of_compromise, "how_determined": how_determined,
        "impact_rating": impact_rating, "impact_description": impact_description,
        "planned_action": planned_action, "system_safe": system_safe,
        "duration_estimate_hours": duration_estimate_hours,
        "complexity": complexity, "dependencies": dependencies or [],
        "notes": notes, "linked_findings": linked_findings or [],
        "linked_hunts": linked_hunts or [],
    }, actor="investigation-section-chief")


@mcp.tool()
def asr_update(serial_no: str, fields: dict[str, Any]) -> dict:
    """Update a row in the Affected Systems Register. Appends a new version row.

    Args:
        serial_no: ASR-N identifier.
        fields: mapping of field to new value (e.g. {"system_safe": "safe"}).
    """
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
    return case_state.cet_append({
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
    }, actor="investigation-section-chief")


@mcp.tool()
def cet_update(cca_no: str, fields: dict[str, Any]) -> dict:
    """Update a CET row (append new version)."""
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
