from __future__ import annotations

import importlib


def _seed_clear_consults(action: dict) -> str:
    from siftics import audit, ic_approval

    ah = ic_approval.action_hash(action)
    audit.append_event("safety_assessment", {
        "action_hash": ah,
        "verdict": "clear",
        "dimensions": {dim: {"score": "low", "rationale": ""} for dim in (
            "business_impact", "personnel_safety", "investigation_safety",
            "scope_pollution", "operational_tempo")},
        "preconditions": [], "mitigations": [], "cited_evidence": [],
    }, actor="safety-officer")
    audit.append_event("legal_review", {
        "action_hash": ah,
        "verdict": "clear",
        "dimensions": {dim: {"score": "low", "rationale": ""} for dim in (
            "privilege_scope", "breach_notification", "regulator_triggers",
            "evidence_admissibility", "third_party_nda_scope")},
        "preconditions": [],
        "counsel_loop_required": False,
        "clocks_started": [],
        "cited_evidence": [],
    }, actor="legal-officer")
    return ah


def test_publish_intel_proposal_is_idempotent_for_same_ioc_batch(tmp_path, monkeypatch):
    monkeypatch.setenv("SIFTICS_CASE_DIR", str(tmp_path))

    import siftics.audit
    import siftics.case_state
    import siftics.ic_approval
    import siftics.intel
    import mcp_intel.server

    importlib.reload(siftics.audit)
    importlib.reload(siftics.case_state)
    importlib.reload(siftics.ic_approval)
    importlib.reload(siftics.intel)
    importlib.reload(mcp_intel.server)

    from siftics import audit, case_state, intel
    from mcp_intel.server import propose_publish_intel

    case_state.init_case(case_id="intel_gate", name="intel gate", ic_name="tester")
    first_ioc = intel.generate_ioc(
        "ip_address", "203.0.113.10", "attacker C2", finding_id="F-001")
    second_ioc = intel.generate_ioc(
        "file_hash", "a" * 64, "malware hash", finding_id="F-002")
    ioc_ids = [first_ioc["ioc_id"], second_ioc["ioc_id"]]

    action = {"action_class": "intel_publication", "ioc_ids": sorted(ioc_ids)}
    _seed_clear_consults(action)

    first = propose_publish_intel(ioc_ids, rationale="publish these indicators")
    second = propose_publish_intel(list(reversed(ioc_ids)),
                                   rationale="same IOCs, different wording")

    assert first["request_id"] == second["request_id"]
    assert second["status"] == "existing_pending_approval"

    pending = list((tmp_path / "approvals" / "pending").glob("*.json"))
    assert len(pending) == 1

    events = list(audit.iter_events())
    assert sum(1 for ev in events if ev["type"] == "ic_request_approval") == 1
    assert sum(1 for ev in events
               if ev["type"] == "intel_publication_proposed") == 1
