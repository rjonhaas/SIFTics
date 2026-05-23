---
name: triage-methodology
description: Phase sequencing + decision engine. Replaces a static run_all.sh with ITQ-driven phase selection.
---

# Triage Methodology

The classic "run all phases in order" approach (`run_all.sh`) is wrong for IR.
Cases differ wildly — a ransomware incident needs different phases first than a
credential-dumping incident or a webshell. This skill encodes which phase to
run, when, based on the Initial Triage Questionnaire (ITQ).

## The map — ITQ category → phase script

| ITQ category (questions) | Phase scripts in priority order |
|---|---|
| `scope` (ITQ-001..005) | answered by IC; agent records into case header |
| `platform` (ITQ-010..016) | (no script — derived from evidence file types and case header) |
| `logs` (ITQ-020..026) | `run_eventlogs.sh` · `run_anti_forensics.sh` (specifically for log clearing) |
| `ownership` (ITQ-030..035) | IC-driven |
| `tooling` (ITQ-040..043) | agent surveys what's installed; reports gaps |
| `business_impact` (ITQ-050..053) | informed by ASR / CET findings as the case progresses |
| `containment` (ITQ-060..064) | `run_artifacts.sh` · `run_execution.sh` · `run_credaccess.sh` |
| `communication` (ITQ-070..074) | IC-driven |

## Hot-path-first ordering

When you start a case:

1. **`fast_evtx_attack_filter`** (HOT) — < 30 s for the last 24h of EVTX.
   Identifies obvious attack indicators (process creation, service install,
   credential access).
2. **`fast_persistence_scan`** (HOT) — < 10 s. Diff registry persistence
   keys + services + scheduled tasks against `mcp_baseline`. Anything not in
   baseline becomes a candidate.
3. **`fast_execution_timeline`** (HOT) — last 4 hours of MFT + Prefetch +
   Amcache + Sysmon-1 events, deduplicated.
4. **`classify_binary` fan-out** on each surface binary — Rathbun baseline,
   imphash via abuse.ch MalwareBazaar, capa behavioural tags, RAG matches to
   ATT&CK.

Only after HOT findings stabilise should you reach for WARM (targeted EZ
Tools usage) or COLD (full Plaso super-timeline, Volatility full image).

## Escalation rules — when to move from HOT → WARM → COLD

- HOT confirms persistence + execution → WARM on identified hosts: pull
  full process tree, full PowerShell transcripts, registry hive snapshot.
- WARM disagrees with HOT (e.g., Sysmon shows a process, but MFT doesn't
  show the binary on disk) → **automatic Phase 18 escalation**. Run
  `run_anomaly_check.sh`; if contradictions remain, surface to IC.
- IC declares "legal hold" or "regulatory hold" → COLD on every affected
  host regardless. Document the declaration in the case header.

## When to propose an Authority Gate

You should request IC approval (`ic_request_approval`) when you reach one
of these decision points:

1. **Fleet-wide hunt for IOCs you found locally.** This is the
   `execute_hunt_package` gate. The IC's question is: "do you have enough
   confidence to ask 50+ other hosts about these IOCs?"
2. **Cold-path on a specific host.** This is the `escalate_to_cold` gate.
   The IC's question is: "is this host important enough to spend hours of
   compute on?"
3. **Network isolation of a host.** This is the `isolate_host` gate. The
   IC's question is: "are we sure enough to interrupt user activity?"

When in doubt, **propose the gate**. The cost of an over-cautious
proposal is one extra IC click. The cost of an over-bold action is
unbounded.

## When to stop

You stop a case when one of these is true:

- All ITQ questions are answered (`itq_progress()['answered'] == total`)
  AND no ASR row is `not_safe` AND no CET row is `pending`.
- The IC explicitly says "close" via `case_update_header({"status": "closed"})`.
- The Hypothesis Engine reports `confidence > 0.9` on a single theory AND
  all related ITQ questions are answered.

Do not stop just because findings have plateaued for 30 minutes. The Hypothesis
Engine's signal scoring should drive that decision — not the absence of new
findings, which often just means you're not looking in the right place yet.
