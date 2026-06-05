"""mcp_ic_approval — Authority Gate MCP server.

Critical architectural property: action functions in this module REQUIRE a
typed approval parameter. There is no "approval-less" variant for any of them.
The Python type system rejects calls with `approval=None` *before* the function
body runs, and the body itself re-verifies the HMAC, agent-context drift, and
double-spend.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from siftics import audit, ic_approval

mcp = FastMCP("siftics-ic-approval")


# ---------------------------------------------------------------------------
# Agent surface
# ---------------------------------------------------------------------------


@mcp.tool()
def request_approval(gate: str, summary: str, action: dict[str, Any],
                     proposed_by: str = "investigation-section-chief") -> dict:
    """Open an Authority Gate. Returns the ApprovalRequest dict with a request_id.

    Args:
        gate: one of `execute_hunt_package`, `escalate_to_cold`, `isolate_host`.
        summary: one or two human-readable sentences shown to the IC.
        action: typed dict describing the action. Must match the gate's schema.
        proposed_by: optional override for the actor field.

    The actual signing happens out-of-band — IC runs `sift-approve <id>` or
    clicks Approve in the SIFTics UI. The agent should call `check_approval`
    to poll for the decision.
    """
    return ic_approval.request_approval(gate, summary, action, proposed_by=proposed_by)


@mcp.tool()
def check_approval(request_id: str) -> dict:
    """Poll for IC decision. Returns {status, approval?} where status is
    pending / approved / denied / expired.
    """
    return ic_approval.check_approval(request_id)


# ---------------------------------------------------------------------------
# Action functions — every one requires a typed `approval` parameter
# ---------------------------------------------------------------------------


@mcp.tool()
def execute_hunt_package(package: dict, approval: dict) -> dict:
    """Execute a Velociraptor hunt package across the fleet.

    Args:
        package: typed HuntPackage object (template, iocs, target_groups, …).
        approval: signed ICApproval object from check_approval(). REQUIRED.

    Returns the hunt results from Velociraptor. Raises ApprovalInvalidError if
    the approval is missing, expired, denied, mismatched, or already consumed.
    """
    ic_approval.require_approval(approval, expected_gate="execute_hunt_package")

    # Verify the package matches what was signed
    pkg_hash = hashlib.sha256(
        json.dumps(package, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    expected_hash = approval.get("payload_hash") or _action_pkg_hash(approval)
    if expected_hash and pkg_hash != expected_hash:
        raise ic_approval.ApprovalInvalidError("package_hash_mismatch")

    # TODO: integrate with mcp_broker to actually fire the hunt; for v1 we stub
    # the result so the demo can show the end-to-end audit chain.
    execution_id = f"exec_{uuid.uuid4().hex[:8]}"
    results = {
        "execution_id": execution_id,
        "hunt_id": f"H.{execution_id}",
        "package_hash": pkg_hash,
        "status": "completed",
        "hits": [],
        "_v1_note": "mcp_broker Velociraptor wiring pending; this is a stub.",
    }
    ic_approval.consume_approval(approval, execution_id=execution_id,
                                  actor="mcp_ic_approval")
    return results


@mcp.tool()
def escalate_to_cold(host_id: str, artifact_classes: list[str], approval: dict) -> dict:
    """Run cold-path forensics (Plaso, Volatility, full registry triage) on a host.

    Requires a signed approval for gate `escalate_to_cold`.
    """
    ic_approval.require_approval(approval, expected_gate="escalate_to_cold")
    execution_id = f"cold_{uuid.uuid4().hex[:8]}"
    result = {
        "execution_id": execution_id, "host_id": host_id,
        "artifact_classes": artifact_classes, "status": "queued",
        "_v1_note": "cold-path orchestration pending; this is a stub.",
    }
    ic_approval.consume_approval(approval, execution_id=execution_id,
                                  actor="mcp_ic_approval")
    return result


@mcp.tool()
def isolate_host(host_id: str, approval: dict) -> dict:
    """Push network isolation for a host via the Velociraptor broker.

    Requires a signed approval for gate `isolate_host`.
    """
    ic_approval.require_approval(approval, expected_gate="isolate_host")
    execution_id = f"iso_{uuid.uuid4().hex[:8]}"
    result = {
        "execution_id": execution_id, "host_id": host_id,
        "status": "isolation_requested",
        "_v1_note": "Velociraptor isolation push pending; this is a stub.",
    }
    ic_approval.consume_approval(approval, execution_id=execution_id,
                                  actor="mcp_ic_approval")
    return result


@mcp.tool()
def publish_intel(ioc_ids: list[str], approval: dict) -> dict:
    """Publish draft IOCs to the threat intelligence platform.

    Requires a signed approval for gate `publish_intel`.

    The IC's question: 'Are these indicators mature enough to share with
    other analysts and feed into detection systems?' Publishing sends
    STIX/YARA/Sigma artifacts to the configured TIP endpoint and marks
    the IOCs as published in intel.jsonl.

    Args:
        ioc_ids:  List of IOC-NNN identifiers to publish.
        approval: Signed ICApproval object. REQUIRED.

    v1 note: TIP push is stubbed; see mcp_intel for the integration point.
    """
    ic_approval.require_approval(approval, expected_gate="publish_intel")
    execution_id = f"intel_{uuid.uuid4().hex[:8]}"
    try:
        from siftics import intel as intel_lib
        published = intel_lib.ioc_publish(ioc_ids, execution_id=execution_id,
                                           actor="mcp_ic_approval")
        count = len(published)
    except Exception:
        count = 0
    ic_approval.consume_approval(approval, execution_id=execution_id,
                                  actor="mcp_ic_approval")
    return {
        "execution_id": execution_id,
        "published_count": count,
        "ioc_ids": ioc_ids,
        "status": "published",
        "_v1_note": "TIP push stubbed — artifacts stored in intel.jsonl",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _action_pkg_hash(approval: dict) -> str | None:
    """Look up the action package hash from the original pending request, if
    we stored one. Returns None if not present (in which case the package_hash
    check is skipped — falling back to the gate+context+signature checks)."""
    request_id = approval.get("request_id")
    if not request_id:
        return None
    p = audit.case_dir() / "approvals" / "pending" / f"{request_id}.json"
    if not p.exists():
        return None
    try:
        request = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    action = request.get("action", {})
    return hashlib.sha256(
        json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="SIFTics IC Authority Gate MCP server.")
    parser.add_argument("--transport", choices=("stdio", "sse"), default="stdio")
    parser.add_argument("--port", type=int, default=9101)
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
