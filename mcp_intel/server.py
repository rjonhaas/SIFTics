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
