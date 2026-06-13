# Hackathon Submission - SANS Find Evil! 2026

SIFTics is the project's entry to the [SANS Find Evil! 2026 hackathon](https://findevil.devpost.com). This document maps every required deliverable to a file path, and explains how the project demonstrates each of the six judging criteria.

The README focuses on what SIFTics is and how to run it. The detailed compliance and criteria material lives here so the README stays an engineering doc and this file stays a submission doc.

---

## Required deliverables

| # | Required deliverable | Location in this repo |
|---|---|---|
| 1 | URL to code repository | [https://github.com/rjonhaas/SIFTics](https://github.com/rjonhaas/SIFTics) *(public)* |
| 2 | Open-source license (MIT or Apache 2.0) | [`LICENSE`](../LICENSE) *(repo root, MIT)* |
| 3 | README with setup instructions | [`README.md`](../README.md) - see Quickstart |
| 4 | Live deployment URL OR local setup instructions | Local - [`docs/QUICKSTART.md`](QUICKSTART.md) |
| 5 | Text description (features and functionality) | This file (Project description below) + [`docs/architecture.md`](architecture.md) |
| 6 | Demo video (≤ 5 min, live terminal, audio narration) | [`docs/demo_video.md`](demo_video.md) - YouTube link + storyboard; [`docs/demo_video_script.md`](demo_video_script.md) - word-for-word narration |
| 7 | Architecture Diagram | [`docs/architecture.md`](architecture.md) - three-layer deployment framing (§0), Mermaid + ASCII rendering, trust boundaries colour-coded (red = architectural, yellow = prompt-based) |
| 8 | Evidence Dataset Documentation | [`docs/datasets.md`](datasets.md) |
| 9 | Accuracy Report | [`docs/accuracy_report.md`](accuracy_report.md) - measured FP/FN, hallucinations, integrity, T1–T8 bypass test results |
| 10 | Agent Execution Logs | [`examples/run_2026-XX-XX/forensic_audit.jsonl`](../examples/) - hash-chained, end-to-end trace from finding to tool execution |

Every entry above has a direct link. Issues at [the repo](https://github.com/rjonhaas/SIFTics/issues) for anything unclear.

---

## Project description

SIFTics turns the SIFT Workstation into a machine-speed incident response agent that:

1. **Closes the speed gap** between attackers operating at 7-minute breakout times and human responders. The HOT execution layer produces candidate findings in seconds, generates a Velociraptor hunt package, surfaces it to the Incident Commander for cryptographically-signed approval, and fires it across the enterprise within tens of seconds.
2. **Operates under NIMS Incident Command System doctrine.** The Claude Code agent functions as the *Investigation Section Chief* (tactical autonomy); the human analyst is the *Incident Commander* (strategic authority). Authority Gates between them are **architecturally enforced** via HMAC-signed approval objects, not by prompt instructions.
3. **Maintains a tamper-evident audit chain.** Every tool execution, every IC decision, and every action result is logged as a hash-chained JSONL row; the chain is verifiable end-to-end with `audit_verify.sh`.
4. **Self-corrects under doctrine.** Phase-18 anomaly detection scans for cross-artifact contradictions and re-runs upstream phases up to three iterations until the contradiction count decreases. A pre-close *completeness critic* (`case_completeness_check()` MCP tool) runs persona-driven coverage assessment against the case state - anti-forensics scope, persistence parity, browser history, timezone, CTI lookup, credential-dump-on-DC-compromise - and returns ordered HIGH→LOW gaps the agent must address before any final briefing or motivation lock-in.
5. **Drives Velociraptor as an active hunt controller** (not just a parser). Findings become typed `HuntPackage` objects; approved packages execute as enterprise-wide hunts; results feed back into the Common Operating Picture (COP).
6. **Grounds AI enrichment in retrieved evidence, not model memory.** Every MITRE technique alignment, LOLBAS context note, and Sigma rule explanation is backed by a record retrieved from the embedded `mcp_rag` forensic index - not generated from training-time knowledge alone. Deterministic lookups (baseline hash checks, IOC exact-match) are typed separately from LLM enrichment in `forensic_audit.jsonl`, so analysts know exactly what to verify. See [`docs/accuracy_report.md §3`](accuracy_report.md) for the full hallucination accounting.

---

## How SIFTics maps to the six judging criteria

The criteria are equally weighted; ties cascade in the order listed.

| Criterion | Where to see it |
|---|---|
| **1. Autonomous Execution Quality** | `phases/run_self_correct.sh` + Phase 18 anomaly check + `case_completeness_check()` + `anti_forensics_review()` + the full self-correction arc in `examples/run_*/forensic_audit.jsonl` |
| **2. IR Accuracy** | [`docs/accuracy_report.md`](accuracy_report.md) - measured FP/FN against the DFIR Madness Stolen Szechuan Sauce ground truth and (where applicable) Caldera Debrief output for hunt_lab scenarios |
| **3. Breadth and Depth** | 20 phase scripts across Windows / Linux / memory / network / email / cross-machine attack-path correlation - [`phases/`](../phases/). Cross-source correlation between disk, memory, EVTX, and network is in the agent's reasoning chain. |
| **4. Constraint Implementation** | [`docs/constraint_implementation.md`](constraint_implementation.md) - architectural (red) vs prompt-based (yellow) guardrails. T1–T8 bypass test results in [`tests/test_constraints.py`](../tests/test_constraints.py) (14/14 passing). Anti-fabrication guard at the MCP write boundary. |
| **5. Audit Trail Quality** | `siftics/audit.py` - hash-chained `forensic_audit.jsonl` with line-hash linkage, SBOM at case-init, `audit_verify.sh` for independent replay. Any finding traces to its originating tool call via the `finding_record` chain. |
| **6. Usability and Documentation** | [`README.md`](../README.md), [`docs/QUICKSTART.md`](QUICKSTART.md), and the SIFTics web UI at `localhost:8080` - dashboard, `/gates`, `/audit`, `/findings`, `/report` (with auto-derived Executive Summary), `/setup` |

---

## On the asymmetry

The Find Evil! rules state honesty is valued over perfection: hallucinations and failures the team caught and documented count *for* the project; unflagged hallucinations count *against*. The accuracy report leads with the failures we found in testing and the architectural responses to each. The 1 FP from the Stolen Szechuan Sauce grading run (and the doctrine fix in commit `adc94a1`) is documented in [`docs/accuracy_report.md §3.2`](accuracy_report.md); the action-ID fabrication pattern we caught (and the structural fix in commit `ae433db`) is documented in `§3.1`.

---

## Last verification

The repository was at commit `1bfc55e` as of June 15, 2026, 11:45 PM EDT submission. Commits after that date are portfolio updates and out of scope for judging per the Official Rules.
