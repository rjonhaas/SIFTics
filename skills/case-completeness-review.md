---
name: case-completeness-review
description: Pre-close completeness critic — catch investigation gaps before the final report renders. Run before any final briefing or ASR-row safe transition.
---

# Case Completeness Review

The main investigation loop is **deep and narrow** — it follows evidence one
hop at a time, prosecutes the working hypothesis, and produces a clean
finding chain. That depth is the right call, but it leaves predictable
gaps: tools the loop didn't think to run because the working theory didn't
need them.

This skill closes those gaps before the final report renders.

## When to invoke

Call `case_completeness_check()` at every one of these moments:

- **Before the final/closing briefing.** Specifically: before any briefing
  whose title or summary contains "final", "closing", "report", or any
  ASR row transitioning from `pending_verification` to `safe`.
- **Before calling `case_set_motivation()`.** Convergence on motive is a
  signal you think you understand the case — that's exactly when the
  critic should challenge you.
- **Whenever the Incident Commander asks "is the case ready?"** Run the
  critic, surface the result, then answer the question with evidence.
- **Optionally periodically** during a long investigation (every ~30 min),
  as a reorientation pass — gaps caught early are cheaper than gaps
  caught at close.

## How to invoke

```python
case_completeness_check()
```

Returns a list of gap dicts:

```json
[
  {
    "rule": "antiforensics_scope_data_files",
    "severity": "high",
    "triggered_by": ["ASR-1", "ASR-2"],
    "suggestion": "Re-run /anti-forensics-detection with scope expanded to..."
  },
  ...
]
```

Writes a `case_completeness_check_run` audit event so a reviewer replaying
the chain sees the moment of pre-close review and what gaps were surfaced.

## How to act on each severity

| Severity | Required action |
|---|---|
| **high** | Close the gap, OR write an explicit briefing note documenting the policy decision that makes it out of scope. Do not produce the final report with an unaddressed `high` gap. |
| **medium** | Strongly recommend close. If you skip, write a briefing acknowledging the gap by name and explaining why. |
| **low** | Informational. Mention in the final report's "limitations" section. |

## Rules in v1

> **Anti-forensics removed from this rule set.** Earlier versions of this
> skill carried two anti-forensics rules; both were keyword-pattern
> matchers that satisfied the moment the agent ran the textbook check on
> the implant binary, with the same CTF-bias as the agent they were
> supposed to catch. Anti-forensics is open-ended adversarial work and
> cannot be enumerated as bounded yes/no checks. Use
> **`/anti-forensics-review`** (and its `anti_forensics_review()` MCP
> tool) at the same pre-close checkpoint — that skill does generative
> reasoning over the attacker actions actually recorded in the case,
> not keyword matching.

| Rule name | Triggers when… | Expects… | Severity if missing |
|---|---|---|---|
| `registry_persistence_when_service_persistence` | Service-based persistence found (7045 / SERVICE_AUTO_START / T1543.003) | Registry Run / RunOnce / IFEO checked | **high** |
| `browser_history_when_remote_entry_vector` | Entry vector is RDP / SSH / interactive remote session | Browser history parsed (WebCacheV01, Chrome History, Firefox places) | medium |
| `timezone_registry_read_for_windows` | Any Windows host in ASR | SYSTEM hive timezone key read | medium |
| `cti_lookup_for_external_ips` | Any non-RFC1918 IP in ASR / findings | At least one explicit CTI feed query per IP (AbuseIPDB / Greynoise / ThreatFox / etc.) | medium |
| `credential_dump_on_dc_compromise` | Critical-impact ASR row tagged as domain controller | NTDS.dit / SAM / LSASS dump check actually run (tool-invocation correlation in v1.1) | **high** |
| `archive_carving_for_exfil_with_encrypted_c2` | ASR notes mention exfil + encrypted C2 (TLS / 443 / Meterpreter) | $LogFile / USN journal / unallocated carving attempted in attacker-context dirs (photorec, tsk_recover, bulk_extractor) | medium |
| `mft_recyclebin_for_filename_recovery` | ASR notes mention file deletion / replacement / "original filename" / Recycle Bin | MFT inactive-entry recovery + $Recycle.Bin parsing (analyzeMFT --include-inactive, rifiuti2) | medium |
| `bruteforce_tool_fingerprint` | Brute-force entry vector confirmed | PCAP / TLS handshake / connection-cadence analysis to identify the tool (Hydra / Crowbar / Patator / ncrack / Medusa) | low |

Add a rule by writing `rule_<name>(state)` in `siftics/completeness_rules.py`
and appending it to the `RULES` list. Each rule is a pure function over
the `CaseState` dataclass — easy to test, easy to extend.

## Anti-pattern: silencing the critic

Do **not** mark a gap "acknowledged" without either closing it or writing
the briefing note. If you write "out of scope" as a reason, name the
**SIFTics policy** that makes it out of scope — e.g. "credential cracking
is out of scope per SIFTics policy decision recorded 2026-06-10; see
briefing 2026-06-10T15:00:00Z." A silent skip reads as a miss to any
reviewer replaying the chain.

## Anti-pattern: running the critic once and forgetting

The critic returns gaps based on case state at the moment of the call. As
new findings land, **rerun the critic** before the next major checkpoint.
A gap that was a `medium` an hour ago can promote to `high` when a critical
ASR row appears.

## Limitations of the current rule set

- **Tool-invocation correlation is partial.** v1 rules used fuzzy text matching
  against finding_record claims and output excerpts; v1.1 added a `_ran_tool`
  helper that reads the `tool` and `command` fields directly, and the
  `credential_dump_on_dc_compromise` rule is now correlation-based. Other rules
  still mix the two — fuzzy match where it makes sense (scope-of-analysis
  claims aren't a tool), tool-invocation where execution is what matters.
- **No rule for hypothesis-engine convergence quality.** The critic doesn't
  check whether you opened enough null-alternative hypotheses or whether
  the winning hypothesis has at least N supporting finding records. That's
  the Hypothesis Engine's job (`/hypothesis-engine`).
- **No rule for evidence-chain integrity.** That's the audit verifier's
  job (`audit_verify.sh`). Run both before close — completeness + chain
  verify is the full pre-close suite.
