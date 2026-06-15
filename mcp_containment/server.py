"""mcp_containment — Response actions MCP server.

This server is the universal output of the containment_action authority gate.
It produces a structured action checklist that names every concrete step the
IC (or downstream response team) needs to take for a given compromised entity.

Each configured response target (Velociraptor, Elastic, Entra ID) elevates
the relevant checklist item from "recommended" to "executable" — and the
gate fires the actual call only after IC approval.

When a target is not configured, the checklist item is marked "manual
action required" with the exact command/UI path the human should use.

Architectural property: every action MCP function requires a typed `approval`
parameter. The containment_action gate is structurally identical to the
other authority gates (execute_hunt_package, publish_intel).
"""
from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from typing import Any, Literal

import httpx
from mcp.server.fastmcp import FastMCP

from siftics import audit, ic_approval

try:
    from siftics.runtime_config import (
        load_config as _load_runtime_config,
        resolve_integration_key as _resolve_integration_key,
        MissingAPIKey as _MissingAPIKey,
    )
except ImportError:
    _load_runtime_config = None  # type: ignore[assignment]


mcp = FastMCP("siftics-containment")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _targets():
    """Return ResponseTargetsConfig — or None if SIFTics isn't installed."""
    if _load_runtime_config is None:
        return None
    try:
        return _load_runtime_config().response_targets
    except Exception:
        return None


def _checklist_row(name: str, target: str, action: str,
                   automated: bool, command: str = "",
                   rationale: str = "") -> dict:
    return {
        "step": name,
        "target_system": target,
        "action": action,
        "automated_by_siftics": automated,
        "manual_command_if_not_automated": command,
        "rationale": rationale,
        "status": "pending_ic_approval",
    }


# ---------------------------------------------------------------------------
# Action proposers — these build the checklist; they do NOT execute anything
# ---------------------------------------------------------------------------


@mcp.tool()
def propose_host_isolation(host_id: str, severity: str = "high",
                            rationale: str = "") -> dict:
    """Generate a checklist for isolating a compromised host.

    Args:
        host_id: hostname, FQDN, or IP of the compromised system.
        severity: low | medium | high | critical — informs the IC of urgency.
        rationale: one-sentence justification (e.g. "Meterpreter C2 confirmed").

    Returns a structured checklist. To execute, request a containment_action
    Authority Gate citing the returned action_id.
    """
    tgt = _targets()
    velo = tgt.velociraptor if tgt else None
    velo_ready = bool(velo and velo.enabled and velo.api_url)

    checklist = [
        _checklist_row(
            "Network isolation",
            "Velociraptor" if velo_ready else "Network / Firewall",
            f"Quarantine {host_id} from production network",
            automated=velo_ready,
            command=f"# Manual: block at firewall by IP/MAC\n# Velociraptor: Server.Utils.QuarantineClient artifact",
            rationale="Prevent lateral movement and C2 callbacks while preserving evidence on the endpoint.",
        ),
        _checklist_row(
            "Live triage collection",
            "Velociraptor" if velo_ready else "KAPE / VR offline collector",
            f"Capture volatile state from {host_id} before reboot",
            automated=velo_ready,
            command=f"# Velociraptor: Generic.Collectors.File + Windows.Memory.Acquisition",
            rationale="Memory, prefetch, and current processes are lost on reboot; capture before isolation forces shutdown.",
        ),
        _checklist_row(
            "Credential review",
            "IAM team",
            f"Reset all credentials known to have logged into {host_id} in the last 30 days",
            automated=False,
            command=f"# Pull SAM hive + recent Security.evtx 4624 events for account list",
            rationale="Compromised host may have cached or harvested credentials.",
        ),
    ]

    action_id = f"act_{uuid.uuid4().hex[:8]}"

    # Canonical action dict — deterministic shape so the agent's prior
    # consult_safety_officer / consult_legal_officer calls (which had to
    # cite the same action_hash) match the gate request below. The
    # action_id is intentionally excluded from this dict so the hash is
    # stable across the consult/request boundary; it's recorded
    # separately on the gate metadata.
    canonical_action = {
        "action_class": "host_isolation",
        "target_entity": host_id,
        "severity": severity,
        "rationale": rationale,
    }

    audit.append_event("containment_proposed", {
        "action_id": action_id,
        "action_class": "host_isolation",
        "target_entity": host_id,
        "severity": severity,
        "automation_available": velo_ready,
        "checklist_steps": len(checklist),
    }, actor="investigation-section-chief")

    # Authority Gate: surface this proposal to the IC by opening a pending
    # approval request. Will raise SafetyConsultRequired /
    # LegalConsultRequired / SafetyHardStop / LegalCounselRequired if the
    # Command Staff consults for this canonical_action haven't been
    # recorded yet — the agent must call consult_safety_officer +
    # consult_legal_officer FIRST with the same canonical action shape.
    summary = (f"Isolate {host_id} ({severity}) — "
               f"{rationale or 'compromised host'}")
    approval_request = ic_approval.request_approval(
        gate="containment_action",
        summary=summary,
        action=canonical_action,
        proposed_by="investigation-section-chief",
    )

    return {
        "action_id": action_id,
        "request_id": approval_request["request_id"],
        "action_class": "host_isolation",
        "target_entity": host_id,
        "severity": severity,
        "rationale": rationale,
        "checklist": checklist,
        "automation_available": velo_ready,
        "pending_approval_at": (
            f"approvals/pending/{approval_request['request_id']}.json"
        ),
        "_workflow_note": (
            "Pending Authority Gate request created — visible on the "
            "dashboard and at /gates. The IC must sign before any "
            "containment_action execution will fire."
        ),
    }


@mcp.tool()
def propose_user_account_response(user_principal: str, severity: str = "high",
                                    rationale: str = "") -> dict:
    """Generate a checklist for responding to a compromised user account.

    Args:
        user_principal: user@domain or sAMAccountName.
        severity: low | medium | high | critical.
        rationale: one-sentence justification.

    Returns a structured checklist. Items elevate to automated if Entra ID
    is configured and enabled in /setup; otherwise they remain manual.
    """
    tgt = _targets()
    entra = tgt.entra_id if tgt else None
    entra_ready = bool(entra and entra.enabled and entra.tenant_id and entra.client_id)
    entra_live = bool(entra_ready and entra.live_mode)

    automation_label = "Entra ID" if entra_ready else "IAM team"

    checklist = [
        _checklist_row(
            "Revoke all active session tokens",
            automation_label,
            f"Force re-authentication for {user_principal} across all devices",
            automated=entra_live,
            command=f"# Manual: Entra admin -> Users -> {user_principal} -> Sign-ins -> Revoke sessions\n# Graph: POST /users/{user_principal}/revokeSignInSessions",
            rationale="Existing tokens may be in attacker possession; revocation forces a fresh auth flow.",
        ),
        _checklist_row(
            "Reset password",
            automation_label,
            f"Force password change for {user_principal} on next logon",
            automated=entra_live,
            command=f"# Manual: Entra admin -> Users -> {user_principal} -> Reset password\n# Graph: PATCH /users/{user_principal} (passwordProfile.forceChangePasswordNextSignIn=true)",
            rationale="If password was harvested, only a reset closes that path.",
        ),
        _checklist_row(
            "Review MFA registrations",
            automation_label,
            f"Audit MFA methods registered for {user_principal} for attacker-controlled phones/keys",
            automated=False,
            command=f"# Graph: GET /users/{user_principal}/authentication/methods",
            rationale="Attacker may have registered their own MFA method as persistence.",
        ),
        _checklist_row(
            "Sign-in log review",
            "SIEM (Elastic)" if tgt and tgt.elastic.enabled else "Entra ID admin",
            f"Pull all sign-ins for {user_principal} in the past 30 days, flag anomalous IPs and devices",
            automated=False,
            command=f"# Entra: Sign-in logs filtered by username\n# Elastic: index=azure-signinlogs userPrincipalName:\"{user_principal}\"",
            rationale="Determine timeline of compromise and identify other affected accounts/resources.",
        ),
    ]
    if severity in ("high", "critical"):
        checklist.append(_checklist_row(
            "Account disable (severe cases only)",
            automation_label,
            f"Disable {user_principal} entirely pending investigation completion",
            automated=False,
            command=f"# Graph: PATCH /users/{user_principal} (accountEnabled=false)",
            rationale="High-severity compromises warrant complete account lockout until full scope is established.",
        ))

    action_id = f"act_{uuid.uuid4().hex[:8]}"

    # Canonical action dict (see propose_host_isolation for the rationale)
    canonical_action = {
        "action_class": "user_account_response",
        "target_entity": user_principal,
        "severity": severity,
        "rationale": rationale,
    }

    audit.append_event("containment_proposed", {
        "action_id": action_id,
        "action_class": "user_account_response",
        "target_entity": user_principal,
        "severity": severity,
        "automation_available": entra_ready,
        "automation_live": entra_live,
        "checklist_steps": len(checklist),
    }, actor="investigation-section-chief")

    # Authority Gate — uses the dedicated `user_account_response` gate so the
    # gate name in /gates reads as the operator expects, rather than the
    # generic `containment_action` shared with host isolation.
    summary = (f"Account response for {user_principal} ({severity}) — "
               f"{rationale or 'compromised user account'}")
    approval_request = ic_approval.request_approval(
        gate="user_account_response",
        summary=summary,
        action=canonical_action,
        proposed_by="investigation-section-chief",
    )

    return {
        "action_id": action_id,
        "request_id": approval_request["request_id"],
        "action_class": "user_account_response",
        "target_entity": user_principal,
        "severity": severity,
        "rationale": rationale,
        "checklist": checklist,
        "automation_available": entra_ready,
        "automation_live": entra_live,
        "pending_approval_at": (
            f"approvals/pending/{approval_request['request_id']}.json"
        ),
        "_workflow_note": (
            "Pending Authority Gate request created — visible on the "
            "dashboard and at /gates. "
            + ("Entra ID is configured in live mode — approved actions "
               "will fire Graph API calls."
               if entra_live else
               "Entra ID is in stub mode — approval logs intent only; "
               "execute checklist manually after IC sign-off.")
        ),
    }


# ---------------------------------------------------------------------------
# Executor — gated, requires IC approval
# ---------------------------------------------------------------------------


@mcp.tool()
def containment_action(action_id: str, action_class: str,
                        target_entity: str, approval: dict) -> dict:
    """Execute a previously-proposed containment action.

    Requires a signed approval for gate `containment_action`. The IC's
    question is: 'Should we take these actions against this entity now?'

    Args:
        action_id: act_NNN from propose_*().
        action_class: 'host_isolation' or 'user_account_response'.
        target_entity: hostname/IP or user principal — must match the proposal.
        approval: signed ICApproval object. REQUIRED.

    For each checklist item, if SIFTics has an automated path configured,
    the call is made and the result recorded. Otherwise the item is marked
    "logged for manual execution" and the IC's approval is the documented
    authorisation for the human action.
    """
    # Accept either the legacy unified gate or the dedicated per-class gates.
    # The executor's branch on action_class still does the work; this lets the
    # gate name match the action class in the UI without forking the executor.
    ic_approval.require_approval(
        approval,
        expected_gate=("containment_action", "host_isolation", "user_account_response"),
    )

    tgt = _targets()
    execution_id = f"exec_{uuid.uuid4().hex[:8]}"
    results: list[dict] = []

    if action_class == "host_isolation":
        velo = tgt.velociraptor if tgt else None
        if velo and velo.enabled and velo.api_url:
            results.append(_invoke_velociraptor_isolate(velo, target_entity))
        else:
            results.append({
                "step": "Network isolation",
                "status": "manual_required",
                "reason": "Velociraptor not configured or disabled in /setup",
            })

    elif action_class == "user_account_response":
        entra = tgt.entra_id if tgt else None
        if entra and entra.enabled and entra.live_mode:
            results.append(_invoke_entra_revoke(entra, target_entity))
            results.append(_invoke_entra_reset(entra, target_entity))
        elif entra and entra.enabled:
            results.append({
                "step": "All Entra actions",
                "status": "logged_for_manual_execution",
                "reason": "Entra ID is configured but live_mode is OFF (recommended for v1)",
                "ic_approval_signature_first_8": approval.get("signature", "")[:8],
            })
        else:
            results.append({
                "step": "All identity actions",
                "status": "manual_required",
                "reason": "Entra ID not configured in /setup",
            })

    else:
        return {"error": f"unknown action_class: {action_class}"}

    ic_approval.consume_approval(approval, execution_id=execution_id,
                                  actor="mcp_containment")
    audit.append_event("containment_executed", {
        "execution_id": execution_id,
        "action_id": action_id,
        "action_class": action_class,
        "target_entity": target_entity,
        "result_count": len(results),
        "all_manual": all(r.get("status") in ("manual_required", "logged_for_manual_execution")
                          for r in results),
    }, actor="mcp_containment")
    return {
        "execution_id": execution_id,
        "action_id": action_id,
        "action_class": action_class,
        "target_entity": target_entity,
        "results": results,
        "audit_entry": "containment_executed event written to forensic_audit.jsonl",
    }


# ---------------------------------------------------------------------------
# Concrete target invocations
# ---------------------------------------------------------------------------


def _invoke_velociraptor_isolate(velo, host_id: str) -> dict:
    """Stub for now — would call Velociraptor's QuarantineClient artifact."""
    return {
        "step": "Network isolation",
        "target": "Velociraptor",
        "host_id": host_id,
        "api_url": velo.api_url,
        "status": "stubbed_v1",
        "would_call": "Server.Utils.QuarantineClient",
        "_v1_note": "Real Velociraptor REST call will be wired in v2; this stub "
                     "confirms configuration is present and the gate fires.",
    }


def _invoke_entra_revoke(entra, user_principal: str) -> dict:
    """Stub for now — would POST /users/{upn}/revokeSignInSessions to Graph."""
    secret_present = False
    if _load_runtime_config:
        try:
            _resolve_integration_key(entra.client_secret)
            secret_present = True
        except Exception:
            pass
    return {
        "step": "Revoke sign-in sessions",
        "target": "Entra ID (Graph API)",
        "user_principal": user_principal,
        "tenant_id": entra.tenant_id or "",
        "client_secret_present": secret_present,
        "status": "stubbed_v1",
        "would_call": f"POST https://graph.microsoft.com/v1.0/users/{user_principal}/revokeSignInSessions",
    }


def _invoke_entra_reset(entra, user_principal: str) -> dict:
    """Stub for now — would PATCH /users/{upn} with passwordProfile."""
    return {
        "step": "Reset password",
        "target": "Entra ID (Graph API)",
        "user_principal": user_principal,
        "status": "stubbed_v1",
        "would_call": f"PATCH https://graph.microsoft.com/v1.0/users/{user_principal} "
                       "(passwordProfile.forceChangePasswordNextSignIn=true)",
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="SIFTics containment MCP server.")
    parser.add_argument("--transport", choices=("stdio", "sse"), default="stdio")
    parser.add_argument("--port", type=int, default=9105)
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
