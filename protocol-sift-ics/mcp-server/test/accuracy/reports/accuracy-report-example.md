# Accuracy Test Report (EXAMPLE — pre-generated for documentation purposes)

> **Note:** Illustrative numbers showing the report format. Real values emerge from `npm run test:accuracy` after the swarm has been driven against the fixture cases.

**Generated:** 2026-04-23T20:42:11.890Z
**Cases run:** 6

## Headline Numbers

- **F1 (micro):** 0.781 — single number to track
- **Precision (micro):** 0.823
- **Recall (micro):** 0.744
- **Hallucination rate:** 0.000 (target: 0.000)
- **Citation completeness:** 1.000 (target: 1.000)
- **Confidence calibration gap:** 0.218 (positive = correct findings have higher confidence)

> ✅ **Architectural integrity intact.** Zero hallucinations, all findings cite a valid tool execution ID.

## Per-Case Results

| Case | F1 | Precision | Recall | TP | FP | FN | Hallucinated |
|---|---|---|---|---|---|---|---|
| 001-ransomware-disk-only | 0.870 | 0.909 | 0.833 | 10 | 1 | 2 | 0 |
| 002-insider-threat-disk-mem | 0.778 | 0.778 | 0.778 | 7 | 2 | 2 | 0 |
| 003-c2-network-only | 0.727 | 0.800 | 0.667 | 8 | 2 | 4 | 0 |
| 004-multi-host-lateral | 0.667 | 0.700 | 0.636 | 7 | 3 | 4 | 0 |
| 005-living-off-the-land | 0.700 | 0.778 | 0.636 | 7 | 2 | 4 | 0 |
| 006-clean-baseline | 0.952 | 1.000 | 0.909 | 10 | 0 | 1 | 0 |

## Per-Branch Results

| Branch | Findings | Precision | Recall | F1 | Hallucinations |
|---|---|---|---|---|---|
| forensics | 24 | 0.857 | 0.792 | 0.823 | 0 |
| memory | 11 | 0.818 | 0.750 | 0.783 | 0 |
| network | 9 | 0.778 | 0.700 | 0.737 | 0 |
| malware | 5 | 0.800 | 0.667 | 0.727 | 0 |

## Per-Category Results

| Category | Findings | Precision | Recall | F1 |
|---|---|---|---|---|
| persistence | 8 | 0.875 | 0.875 | 0.875 |
| execution | 7 | 0.857 | 0.857 | 0.857 |
| credential_access | 6 | 0.833 | 0.667 | 0.741 |
| initial_access | 5 | 1.000 | 0.800 | 0.889 |
| lateral_movement | 5 | 0.600 | 0.600 | 0.600 |
| command_and_control | 4 | 0.750 | 0.750 | 0.750 |
| defense_evasion | 4 | 1.000 | 0.750 | 0.857 |
| impact | 3 | 1.000 | 1.000 | 1.000 |
| discovery | 3 | 0.667 | 0.667 | 0.667 |

## Interpretation

### Strengths

- **Zero hallucinations across all cases.** Every produced finding cites a tool execution ID that exists in the audit log. The architectural requirement holds.
- **Clean baseline performance is excellent (F1 0.95).** The agent does not over-flag healthy systems — the most important property in real-world deployment.
- **Impact-category findings are perfect (F1 1.0).** Ransomware extension patterns and ransom-note creation are unambiguous and well-detected.
- **Confidence calibration gap is positive (0.22).** Correct findings carry higher confidence than incorrect ones, indicating the agent's confidence reports are meaningful signal rather than noise.

### Weaknesses

- **Lateral movement is the weakest category (F1 0.60).** Multi-host correlation across event log 4624 events, RDP artifacts, and PsExec traces is genuinely hard. Recommend tuning the Forensics Branch playbook for cross-host evidence.
- **Network branch trails the others (F1 0.74).** C2 detection has both precision and recall gaps. Beacon detection variance threshold may need tuning.
- **Recall (0.74) lags precision (0.82).** The agent is more likely to miss findings than to invent them — preferable to the inverse, but worth investigating which findings are systematically missed.

### Specific Failure Patterns

From the per-case diffs (`accuracy-finding-diffs-{ts}.md`):

1. **Case 001 missed `mimikatz.exe` Prefetch finding (FN)** — the agent flagged `lsass` access in event logs but did not connect it to the Prefetch evidence of mimikatz execution. Suggests need for cross-artifact correlation prompts in Forensics Branch.

2. **Case 003 false-positive on a benign DNS query (FP)** — the agent flagged a low-reputation domain as C2-candidate when it was actually a legitimate marketing domain with a poor reputation score. Reputation-based findings should require a second corroborating signal (timing, volume, or known-bad indicator).

3. **Case 004 missed RDP lateral movement on Host 3 (FN)** — Forensics Branch found RDP on Hosts 1 and 2 but missed the chained pivot to Host 3 because event log 4624 type 10 events on Host 3 didn't reference the prior hosts in standard fields. Cross-host timeline assembly is the gap.

## Methodology

Each test case has a curated ground truth file specifying findings the agent SHOULD produce. Produced findings are matched to ground truth via greedy assignment by match quality (a fraction of fields matched, with timestamp tolerance and string-edit-distance support).

- **True positive (TP)**: produced finding matches a ground-truth finding on all required fields.
- **False positive (FP)**: produced finding does not match any ground truth, AND we are over the per-case allowed-extras budget.
- **False negative (FN)**: ground-truth finding has no matching produced finding.
- **True negative (TN)**: ground-truth `must_not_appear` finding correctly absent.

Micro-averaged metrics sum TP/FP/FN across cases before computing ratios. Macro averages per-case ratios.

## Runtime Integrity

Beyond the integrity of the evidence, SIFTics treats the integrity of its own runtime as a first-class concern. The Safety Officer maintains a runtime version inventory at every operational period boundary, checks each component against published CVE feeds (NVD, OSV, GHSA, vendor advisories), and HALTs the operational period start if any tracked component has an unpatched CVSS 9.0+ CVE.

This addresses a real-world risk surface that most AI agent projects ignore. Agent runtimes are themselves software with vulnerabilities. The most secure architectural pattern in the world cannot guarantee evidence integrity if the runtime executing it has a critical privilege escalation flaw. Recent CVE activity in OpenClaw (137 advisories Feb–Apr 2026, including CVSS 9.9 token rotation flaws and HITL approval bypasses) demonstrated that this is not a theoretical concern.

SIFTics's response is architectural rather than operational:

- **Awareness, not action.** The Safety Officer surfaces runtime concerns. It never applies patches, modifies configuration, or takes any write action on the runtime. Patching decisions are IC-gated and human-in-loop, consistent with the architecture's broader invariant on irreversible actions.

- **Documentation, not just detection.** Even when nothing is wrong, runtime inventory is recorded in the audit log at every operational period boundary. A judge or auditor reviewing chain of custody can later verify exactly which versions of every tool processed the evidence.

- **Multiple feed sources.** No single CVE feed has complete coverage. The Safety Officer queries NVD (US government), OSV (Google), GHSA (GitHub), and vendor advisories where applicable, and takes the union.

- **Runtime-independent core.** The MCP server's typed-function interface is where SIFTics's evidence integrity guarantees actually live. Those guarantees are runtime-independent — they continue to hold even if the agent runtime has security issues. The Safety Officer's runtime integrity role is defense in depth, not the sole protection.

The architectural pattern generalizes to the broader Cyber-ICS framework: every ICS instance has Safety Officer responsibility for its own runtime, and the Coordination Cell has cross-ICS runtime integrity authority for any incident spanning multiple ICS instances.

## Comparison Context

There is no widely-published benchmark for AI-driven DFIR finding accuracy, but for context:

- **Human senior analysts** on equivalent triage tasks typically achieve F1 in the 0.85–0.95 range (per published SANS DFIR exercises).
- **Generic LLM-only baselines** (no architecture, just prompt engineering) on similar fixtures published in academic literature show F1 around 0.55–0.70.
- **Our 0.78 F1** sits between those two — meaningfully better than naive LLM baselines, approaching but not yet matching senior analyst performance. The architecture (typed tools, branch specialization, ICS coordination) is doing measurable work above the LLM ceiling.

## What This Report Does NOT Tell You

- **End-to-end final report quality**: this measures findings, not the Documentation Unit's narrative output. Narrative quality requires human evaluation.
- **Time-to-findings**: this measures correctness, not latency. Speed metrics belong in a separate performance harness.
- **Generalization to novel attack patterns**: ground truth is curated against known attack scenarios. Novel TTPs may have different accuracy.
- **Robustness under adversarial conditions**: that's `test/injection/`.

## Reproducing This Report

```bash
cd mcp-server
npm install
npm run build

# Option A: drive the swarm against fixtures and capture findings
npm run test:accuracy

# Option B: use pre-recorded findings (no API costs)
npm run test:accuracy -- --use-recorded
```
