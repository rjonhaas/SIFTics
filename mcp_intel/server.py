"""mcp_intel — IOC generation and threat intel publishing MCP server.

Tools exposed to the agent:
  generate_ioc      Convert a finding into STIX/YARA/Sigma artifacts (stored as draft)
  ioc_list          List generated IOCs, optionally filtered by status
  publish_intel     Push approved IOCs to the TIP — requires IC approval gate

Architectural property: publish_intel is gated on a signed ICApproval
for gate "publish_intel". Publishing to a shared TIP affects other analysts
and detection systems — it has the same blast-radius profile as a fleet
hunt and requires the same IC sign-off.

v1 note: the actual TIP push in publish_intel is stubbed. The gate,
artifact generation, and audit chain are fully wired.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from siftics import ic_approval, intel as intel_lib

mcp = FastMCP("siftics-intel")


@mcp.tool()
def generate_ioc(
    ioc_type: str,
    ioc_value: str,
    context: str,
    finding_id: str = "",
    formats: list[str] | None = None,
) -> dict:
    """Generate STIX/YARA/Sigma artifacts from a finding and store as a draft IOC.

    Call this when a finding contains an actionable indicator — something that
    another analyst or detection system could use to hunt for the same threat.
    Not every finding is an IOC: timestamps, victim names, and case-context
    facts should NOT be passed here. IOC-worthy findings include: malicious
    email addresses, attacker IPs, C2 domains, suspicious file hashes, known
    bad user-agents, malware filenames.

    Args:
        ioc_type:   One of: email | ip_address | domain | url | file_hash |
                    user_agent | mac_address | filename | process_pattern | registry_key
        ioc_value:  The raw IOC value (e.g. "user@example.com", "203.0.113.42")
        context:    One sentence: what this IOC means in the investigation.
                    e.g. "Attacker-controlled email observed in plaintext HTTP cookies during attack window"
        finding_id: F-NNN identifier linking this IOC to its source finding (recommended)
        formats:    List of formats to generate. Defaults to the recommended set
                    for the ioc_type. Options: stix | yara | sigma.
                    Not all formats apply to all types — unsupported combinations
                    are silently skipped.

    Returns the IOC row including generated artifact text and assigned IOC-NNN id.
    After generation, propose an Authority Gate to publish if the IC should
    operationalize this indicator.
    """
    return intel_lib.generate_ioc(
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        context=context,
        finding_id=finding_id,
        formats=formats,
        actor="investigation-section-chief",
    )


@mcp.tool()
def ioc_list(status: str = "") -> list[dict]:
    """List generated IOCs.

    Args:
        status: Filter by status — draft | approved | published.
                Omit to return all.

    Returns list of IOC rows including artifact text.
    Use this before proposing a publish_intel gate to show the IC what
    will be published.
    """
    return intel_lib.ioc_list(status=status)


@mcp.tool()
def propose_publish_intel(ioc_ids: list[str], rationale: str = "") -> dict:
    """Open an Authority Gate asking the IC to approve pushing IOCs to the TIP.

    Call this immediately after the last `generate_ioc()` in a batch. This is
    step 7 of the Investigation Section Chief's operating loop — the "fight
    evil" handoff: SIFTics found the indicators, the IC decides whether they
    are mature enough to publish to other defenders.

    Args:
        ioc_ids:   list of IOC-NNN identifiers to publish (must already exist
                   in intel.jsonl via prior generate_ioc() calls).
        rationale: one-sentence justification the IC reads to decide. Example:
                   "Verified perpetrator email from HTTP cookie; mature enough
                   to circulate so other incident responders can pivot."

    Returns the ApprovalRequest dict with request_id. The IC signs at /gates;
    the agent then calls `publish_intel(ioc_ids, approval)` once approved.
    """
    from siftics import audit  # local import to keep top-of-module identical
    if not ioc_ids:
        return {"error": "ioc_ids must not be empty"}
    iocs = intel_lib.ioc_list()
    known = {row["ioc_id"] for row in iocs}
    missing = [i for i in ioc_ids if i not in known]
    if missing:
        return {"error": f"unknown ioc_ids: {missing}. "
                f"Call generate_ioc() for them first."}
    # The signable action is the IOC batch, not the agent's prose rationale.
    # Otherwise each wording tweak creates a new action_hash and forces fresh
    # safety/legal consults for the same operational decision.
    canonical_action = {
        "action_class": "intel_publication",
        "ioc_ids": sorted(ioc_ids),
    }
    ah = ic_approval.action_hash(canonical_action)

    pending_dir = audit.case_dir() / "approvals" / "pending"
    signed_dir = audit.case_dir() / "approvals" / "signed"
    if pending_dir.exists():
        for p in sorted(pending_dir.glob("*.json")):
            if (signed_dir / p.name).exists():
                continue
            try:
                existing = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if (existing.get("gate") == "publish_intel"
                    and existing.get("action_hash") == ah):
                return {
                    "request_id": existing["request_id"],
                    "ioc_ids": sorted(ioc_ids),
                    "pending_approval_at": (
                        f"approvals/pending/{existing['request_id']}.json"
                    ),
                    "status": "existing_pending_approval",
                    "_workflow_note": (
                        "An Authority Gate for this IOC batch is already "
                        "pending. Visible at /gates."
                    ),
                }

    summary = (f"Publish {len(ioc_ids)} IOC(s) to the threat-intel platform — "
               f"{rationale or 'mature enough to circulate to other defenders'}")
    approval_request = ic_approval.request_approval(
        gate="publish_intel",
        summary=summary,
        action=canonical_action,
        proposed_by="investigation-section-chief",
    )
    audit.append_event("intel_publication_proposed", {
        "request_id": approval_request["request_id"],
        "action_hash": ah,
        "ioc_ids": sorted(ioc_ids),
        "rationale": rationale,
    }, actor="investigation-section-chief")
    return {
        "request_id": approval_request["request_id"],
        "ioc_ids": sorted(ioc_ids),
        "pending_approval_at": (
            f"approvals/pending/{approval_request['request_id']}.json"
        ),
        "_workflow_note": (
            "Pending Authority Gate opened. Visible at /gates and in the "
            "dashboard's pending counter. Once the IC signs, call "
            "publish_intel(ioc_ids, approval) to execute."
        ),
    }


@mcp.tool()
def publish_intel(ioc_ids: list[str], approval: dict) -> dict:
    """Publish approved IOCs to the threat intelligence platform.

    Requires a signed IC approval for gate 'publish_intel'. The IC's
    question is: 'Are these indicators mature enough to share with other
    analysts and feed into detection systems?'

    Args:
        ioc_ids:  List of IOC-NNN identifiers to publish.
        approval: Signed ICApproval object from check_approval(). REQUIRED.

    v1 note: The actual TIP push is stubbed — artifacts are marked published
    in intel.jsonl and the full audit event is written, but no external
    system receives them. The workflow is production-ready; the integration
    endpoint is the remaining wire-up.
    """
    ic_approval.require_approval(approval, expected_gate="publish_intel")
    execution_id = f"intel_{uuid.uuid4().hex[:8]}"

    published = intel_lib.ioc_publish(
        ioc_ids=ioc_ids,
        execution_id=execution_id,
        actor="mcp_intel",
    )

    ic_approval.consume_approval(approval, execution_id=execution_id,
                                  actor="mcp_intel")
    return {
        "execution_id": execution_id,
        "published_count": len(published),
        "ioc_ids": [r["ioc_id"] for r in published],
        "status": "published",
        "_v1_note": "TIP push stubbed — artifacts stored in intel.jsonl",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="SIFTics Intel IOC MCP server.")
    parser.add_argument("--transport", choices=("stdio", "sse"), default="stdio")
    parser.add_argument("--port", type=int, default=9104)
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
