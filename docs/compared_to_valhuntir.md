# SIFTics vs Valhuntir - Honest Criterion-by-Criterion Comparison

[Valhuntir](https://github.com/AppliedIR/Valhuntir) is the reference bar for agentic DFIR in this hackathon. This document is SIFTics's honest read of where it lands vs Valhuntir on each of the six equal-weighted Find Evil! judging criteria. **Honesty over salesmanship** - every claim below is verifiable from the repo or from Valhuntir's own README.

> Authors: rjonhaas (SIFTics maintainer). Comparison was prepared without input from the Valhuntir team. If anything here misrepresents Valhuntir, please open an issue - we'll correct it.

---

## TL;DR

| Criterion (equal-weight; #1 is tiebreaker) | SIFTics with planned work | Valhuntir | Verdict |
|---|---|---|---|
| **1. Autonomous Execution Quality** *(tiebreaker)* | Explicit self-correction machinery (Phase 18 + `run_self_correct.sh` + Hypothesis Engine); mid-investigation correction; National Incident Management System (NIMS) Incident Command System Authority Gates with cryptographic signing | DRAFT findings → human approves; no mid-investigation self-correction described | **SIFTics ahead** |
| **2. IR Accuracy** | Zircolite + RAG + Rathbun + imphash + capa; *measured* against DEF CON DFIR CTF + CyberDefenders 166 | Hayabusa + 22K RAG + 2.6M baseline; no measured CTF benchmark claimed | **SIFTics slight edge** (measured > claimed) |
| **3. Breadth and Depth** | 20 phases across Win/Linux/memory/PCAP/email/attack-path; HOT/WARM/COLD depth-on-demand | 15 parsers across similar territory; OpenSearch gives depth on huge cases | **Wash** (different kinds of depth) |
| **4. Constraint Implementation** *(architectural vs prompt-based)* | T1–T8 measured bypass tests (14/14 pass); namespace-guarded MCP; cryptographic Incident Commander (IC) approval; budget circuit breaker | HMAC-signed approvals; PBKDF2 auth; typed MCP | **SIFTics edge** (measured bypass tests > claimed) |
| **5. Audit Trail Quality** | Hash-chained `forensic_audit.jsonl` + `audit_verify.sh` (tamper-evident, end-to-end); per-finding cost traceability via `llm_call` events | Append-only logs; HMAC on approvals only | **SIFTics ahead** |
| **6. Usability and Documentation** | Developer-focused; Flask + vanilla JS dashboard with block-level markdown rendering, transcript persistence, IOC generation UI (/intel), and evidence chain traceability (/findings); setup wizard for 5 LLM backends including local Ollama; compliance README | Browser Examiner Portal; multi-examiner workflows; more polished | **Valhuntir ahead, gap narrowing** |

**Net:** 2 wins + 1 slight edge + 1 edge + 1 wash + 1 loss. **Meaningfully ahead, not a blowout.**

---

## Criterion 1 - Autonomous Execution Quality (tiebreaker)

> *Does the agent reason about next steps, handle failures, and self-correct in real time?*

### What SIFTics has

- **Phase 18 anomaly check** scans for cross-artifact contradictions (e.g., Shimcache says binary executed at T1, MFT records creation at T2 > T1).
- **`run_self_correct.sh`** re-runs upstream phases up to three iterations until the contradiction count decreases. **Mid-investigation self-correction is explicit machinery, not an emergent property.**
- **Hypothesis Engine** (`hypothesis_score.py`) maintains a working-theory ledger; confidence is computed *mechanically* from signal weights, not LLM-guessed. Avoids anchoring on first plausible explanation.
- **NIMS ICS Authority Gates** - tactical autonomy for the agent within the investigation section; strategic decisions (scope expansion, fleet actions) gated by cryptographic IC approval.

### What Valhuntir has

- 9-phase workflow (case → register → ingest → scope → enrich → search → stage → approve → report).
- Findings staged as DRAFT; human examiner approves via Portal or CLI; HMAC-signed approval records.
- No mid-investigation self-correction described in their public docs.

### Verdict

**SIFTics ahead.** Valhuntir's autonomy story is "agent proposes, human disposes" - *one* human-in-the-loop boundary per finding. SIFTics's is "agent investigates, detects its own errors, re-runs upstream, surfaces gates" - *N* corrections per case.

### Demo move

Show Phase 18 catching a contradiction → `run_self_correct.sh` re-runs phase → updated finding aligns. **Tiebreaker criterion, on-camera.** Valhuntir's architecture cannot film this.

---

## Criterion 2 - IR Accuracy

> *Are findings correct? Hallucinations caught and flagged? Confirmed findings distinguished from inferences?*

### What SIFTics has

- **Measured accuracy** against three public datasets: NIST CFReDS, Digital Corpora Nitroba, Ali Hadi web server. Score card in [`accuracy_report.md §2`](accuracy_report.md).
- **Five independent signals** for binary classification (Rathbun baseline, imphash, ssdeep/TLSH, capa, semantic RAG) fused per finding.
- **Zircolite** applies the SigmaHQ rule set to EVTX before the agent reasons over the events.
- **Hash-chained provenance** - every finding traces to the tool execution that produced it.

### What Valhuntir has

- Hayabusa applies SIGMA rules with deterministic indexing.
- 22 000-record forensic-rag-mcp grounding in authoritative sources.
- 2.6M Windows known-good baseline (windows-triage-mcp).
- No measured CTF benchmark referenced in their docs.

### Verdict

**SIFTics slight edge** - measured beats claimed. Valhuntir likely has *broader* coverage (15-parser ingest is more comprehensive than SIFTics's HOT extractors today) but no public accuracy numbers to compare against.

### Honest caveats

- SIFTics's HOT layer is narrower than Valhuntir's ingest pipeline. Cases that depend on deep Volatility memory analysis or full Plaso super-timelines will route to SIFTics's COLD path, which is slower.
- Valhuntir's 2.6M baseline records may be more curated than Rathbun's community corpus.

---

## Criterion 3 - Breadth and Depth

> *How much case data can the agent handle? Depth on fewer types beats shallow coverage of many.*

### What SIFTics has

- 20 forensic phase scripts: NTFS, registry, EVTX, artifacts, execution, hunting, credential access, anti-forensics, IOC extraction, C2 beacon, browser, ransomware, web server, **email, Linux, CVE attribution, attack-path graph, anomaly check, memory, PCAP**.
- **9 domain knowledge skill files** guiding the agent: `windows-artifacts`, `linux-server-artifacts`, `malware-triage`, `timeline-reconstruction`, `anti-forensics-detection`, `reporting-conventions`, plus the original ISC, triage-methodology, and hypothesis-engine skills.
- HOT/WARM/COLD execution tiering - depth-on-demand.
- Cross-machine attack-path graph (Mermaid output) - multi-host scope.

### What Valhuntir has

- 15 parsers across similar territory (Windows Event Logs, EZ Tool artifacts, Volatility 3 memory, Suricata/tshark/Velociraptor JSON, Apache/Nginx, IIS/HTTPERR, Windows Defender MPLog, Scheduled Tasks XML, SSH auth logs, PowerShell transcripts, Prefetch/SRUM).
- OpenSearch-indexed evidence - handles large cases at scale.

### Verdict

**Wash.** Different kinds of depth: SIFTics goes deeper on *response* (active hunt loop, cross-machine attack-path); Valhuntir goes deeper on *scale* (indexed evidence). Judged at sole discretion.

---

## Criterion 4 - Constraint Implementation (architectural vs prompt-based)

> *Are guardrails architectural or prompt-based? Judges evaluate where security boundaries are enforced and whether they were tested for bypass.*

### What SIFTics has

- **14 architectural guardrails** documented and labelled in [`architecture.md §3`](architecture.md#3-trust-boundaries--architectural-vs-prompt-based) and [`constraint_implementation.md`](constraint_implementation.md).
- **T1–T8 bypass test harness** (14 sub-tests) - measured pass/fail. Run with `pytest tests/test_constraints.py -v`. **14/14 pass.**
- **Cryptographic IC approval** - HMAC-SHA256, PBKDF2 key derivation, single-use enforcement (`O_EXCL`), wrong-gate rejection, agent-context drift detection, TTL expiry.
- **Budget circuit breaker** at the LLM-call boundary - architectural, not prompt-based.
- **No `execute_shell()` / `eval()` / arbitrary file write** on the MCP surface.

### What Valhuntir has

- HMAC-signed approvals with PBKDF2 auth (similar primitive).
- Typed MCP functions (similar primitive).
- Forensic discipline reinforcement via system prompt and per-tool caveats - *some* of which are prompt-based.

### Verdict

**SIFTics edge** - measured bypass tests beat claimed architectural guardrails. Specifically, Valhuntir does not document a bypass test harness equivalent to T1–T8. If both architectures are "sound", the *measured* one is more defensible.

### Demo move

Show T1–T8 running live on-screen - all 14 green. *"Our constraints aren't claimed, they're measured."* Valhuntir cannot replicate this on-camera without writing the same harness.

---

## Criterion 5 - Audit Trail Quality

> *Can judges trace any finding back to the specific tool execution that produced it?*

### What SIFTics has

- **`forensic_audit.jsonl`** - hash-chained JSONL, `SHA-256(prev_line_hash || canonical(event))`.
- **`audit_verify.sh`** - recomputes the chain end-to-end; exit 0 = intact, ≠ 0 = tampered.
- **`llm_call` events** - every LLM call carries model, tokens, cache stats, cost. Per-finding cost traceability.
- **Approval lifecycle in the chain** - request → sign → execute → consume, each as a separate hashed event. Tracing a hunt finding back: `action_executed` → `ic_approval_signed` → `ic_request_approval` → original tool execution. **Five hops, all hashed, all verifiable.**

### What Valhuntir has

- "Append-only audit logs" mentioned in description.
- HMAC-signed approval records - cryptographic only at the approval moment, not over the whole chain.

### Verdict

**SIFTics ahead.** Hash-chained > append-only on tamper-detection. Per-call LLM cost traceability is a feature Valhuntir doesn't claim.

### Demo move

Run `audit_verify.sh` on-screen. Walk a single finding back through the chain. **Two minutes of video, criterion #5 won.**

---

## Criterion 6 - Usability and Documentation

> *Can another practitioner deploy and build on this?*

### What SIFTics has

- Compliance README (this submission) with every Devpost item directly linked.
- Flask + vanilla JS web UI: `/dashboard`, `/gates`, `/audit`, `/chat`, `/setup`, `/report`, `/intel`, `/findings`.
 - **Block-level markdown rendering** of agent output (tables, lists, headings rendered natively).
 - **Transcript persistence** - agent output survives page navigation without a server round-trip.
 - **`/intel` page** - IOC generation UI backed by `intel.jsonl` (STIX/YARA/Sigma outputs from `mcp_intel`).
 - **`/findings` page** - evidence chain traceability; each finding links back to the tool execution events in `findings.jsonl`.
 - **`/report` page** - structured case report generated from the completed investigation.
- Setup wizard supports **5 LLM backends** - Claude Code, Anthropic API, OpenAI API, Ollama (local), Codex. Including Ollama is a fully-offline option Valhuntir does not have.
- Quickstart that goes from `git clone` to *first finding* in 30 seconds.
- Tested install on stock SIFT OVA *and* WSL-SIFT (per Rob's Slack 2026-05-13).

### What Valhuntir has

- Browser Examiner Portal for review/approval.
- Multi-examiner workflow with case export/merge.
- Distributed deployment story (3 VMs).
- Generally more polished documentation surface.

### Verdict

**Valhuntir ahead, gap narrowing.** Valhuntir's portal is more polished overall, but SIFTics now has multiple purpose-built analyst pages (findings traceability, IOC publishing UI, structured report view) that cover the most important investigation workflows. The remaining gap is polish and multi-examiner support, not feature coverage. Mitigation: nail the compliance README (done), ship a fresh-VM install script that works without intervention (in progress), do a 30-second "from clone to first finding" segment in the demo (planned). Don't try to match the portal - substitute substance.

---

## Where SIFTics structurally exceeds Valhuntir (regardless of polish)

These are architectural capabilities that exist in SIFTics and do not exist in Valhuntir:

1. **Active Velociraptor hunt orchestration.** SIFTics generates a typed `HuntPackage` object, surfaces it as an Authority Gate, signs it with HMAC, executes it across the fleet, and ingests the results back into the case. Valhuntir uses Velociraptor only as a JSON/JSONL parser of *already-collected* data.
2. **Phase 18 self-correction.** Cross-artifact contradiction detection with three-iteration re-run loop. Valhuntir does not describe a mid-investigation self-correction mechanism.
3. **Hypothesis Engine.** Mechanical confidence scoring with signal weights - no LLM-estimated probabilities. Avoids the anchoring bias common in LLM-driven investigations.
4. **T1–T8 bypass test harness.** Measured architectural-guardrail evidence.
5. **Budget circuit breaker.** Architectural cost ceiling - agent cannot exhaust API credits beyond the configured per-case budget.
6. **Multi-runtime LLM backend.** Setup wizard supports Claude Code, Anthropic API, OpenAI API, Ollama (fully local), Codex - *including* offline operation. Valhuntir requires an external MCP client and does not ship a fully-local mode.

## Where Valhuntir structurally exceeds SIFTics

Equally honest:

1. **OpenSearch-indexed evidence at scale.** SIFTics's per-phase JSONL outputs don't scale to "search across 50 cases simultaneously" the way OpenSearch does.
2. **Browser Examiner Portal.** More polished multi-examiner UI vs. SIFTics's analyst-focused dashboard.
3. **Multi-examiner workflow.** Distributed teams with case export/merge are documented for Valhuntir; SIFTics is single-IC in v1.
4. **Ed25519-class examiner identity.** Valhuntir's HMAC-signed approvals are mature; SIFTics's are equivalent at v1 (HMAC-SHA256) but the Ed25519 public/private split is planned for v2.

---

## How a third-party reviewer can verify these claims

| Claim | How to verify in 5 minutes or less |
|---|---|
| Self-correction is real | `cat phases/run_self_correct.sh && grep -A 5 'iter' phases/run_self_correct.sh` |
| Bypass tests pass | `python -m pytest tests/test_constraints.py -v` - 14 lines of green |
| Hash chain works | `siftics/audit.py:verify_chain()` runs in <1 s on any sample case |
| Budget breaker is real | Test T7 specifically - `pytest tests/test_constraints.py::test_t7_budget_circuit_breaker -v` |
| Multi-runtime is real | Open `/setup` in the Flask UI - 5 backend cards, with live detection |
| Velociraptor active hunt is real | `mcp_broker/server.py` exposes `create_hunt`, `start_hunt`, `wait_for_hunt`, `get_hunt_results` - none of which exist in Valhuntir's parser model |

If any of these fail to verify against the repo, that is a bug. Open an issue.
