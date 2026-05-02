# Skill: Incident Commander (DFIR Investigation Orchestrator)

## When to invoke
At the **start of every case**, before any other skill runs. The IC owns the investigation
lifecycle: what to analyze, in what order, when to pivot, and when findings are complete
enough to hand off to the investigation-report skill. If a case was started without the IC
skill and analysis is already underway, invoke IC to read existing outputs and establish the
COP from current state.

**The IC never executes forensic tools directly.** It directs which skill to invoke next and
synthesizes findings across skills. Tool execution happens inside the domain skills
(memory-analysis, windows-artifacts, yara-hunting, etc.).

---

## Hard Rules

- Never call forensic tools directly. Invoke domain skills; they handle execution.
- Never write to evidence directories (`/cases/`, `/mnt/`, `/media/`).
- Never suppress a contradiction between sources — document it and resolve it.
- Every finding must be classified as CONFIRMED, INFERRED, or CONTRADICTED before
  it enters the COP.
- Cap at **4 operational periods** per case. If not converged by period 4, declare
  incomplete analysis, produce best-available COP, and hand off to report skill.
- The investigation-report skill is invoked by the IC at case closure — not by the analyst
  independently.

---

## Phase 0 — Case Initialization

Run once at case start, before Period 1.

### 0A. Evidence Inventory

Survey the case root and record every evidence source:

```bash
find /cases/<case_name> -maxdepth 3 \( \
  -name "*.raw" -o -name "*.mem" -o -name "*.dmp" -o -name "*.vmem" \
  -o -name "*.img" -o -name "*.E01" -o -name "*.ex01" \
  -o -name "*.pcap" -o -name "*.pcapng" \
  -o -name "*.evtx" \
  -o -name "\$MFT" \
  -o -name "*.jsonl.gz" -o -name "*.json.gz" \
\) | sort
```

For each source, record: type, path, file size, and — critically — its **capture timestamp**
relative to the suspected attack window (see 0B).

### 0B. Evidence Integrity (chain of custody)

Hash every original evidence file before any analysis touches it:

```bash
# Hash all evidence files at case root (skip analysis/ and exports/ dirs)
find /cases/<case_name> -not -path "*/analysis/*" -not -path "*/exports/*" \
  -not -path "*/reports/*" -type f \
  -exec sha256sum {} \; | tee /cases/<case_name>/analysis/evidence_hashes.txt
```

Record the hash file path in the COP. Every subsequent analysis session should verify
that original evidence files still match these hashes before proceeding.

### 0C. Temporal Relationship Mapping

For each evidence source, establish its relationship to the suspected attack window.
This is the most important strategic decision in Phase 0 — it determines which skill
runs first.

| Evidence source | Captured when | Relationship to attack window | Implication |
|---|---|---|---|
| Memory image | Before / During / After | Inside = high-value live state | Run memory-analysis early |
| Disk image / KAPE | Time of collection | After cleanup = deleted artifacts | Prioritize USN, MFT, carved data |
| PCAP | Duration | Overlaps attack = C2 visible | Run network analysis early |
| CloudTrail logs | Log retention window | Wide coverage | Good for timeline anchoring |

**If memory capture timestamp falls inside the active attack window** (attacker was operating
when snapshot was taken): memory-analysis runs before disk analysis. Live C2 connections,
active implants, and in-memory credentials take priority over historical reconstruction.

**If memory predates the attack or is unavailable**: disk/artifact analysis runs first.
Memory analysis is for live state — it cannot tell you what happened before the capture.

### 0D. COP Initialization

Create the Common Operating Picture file at `./analysis/cop.md`. This file is the single
source of truth for the investigation state. It is updated at the end of every operational
period.

```markdown
# COP — [CASE_NAME]
**Period:** 0 of 4  
**Updated:** [UTC]  
**Status:** Initialized

## Evidence Inventory
| Source | Type | Path | Captured (UTC) | Temporal Relationship | SHA256 |
|--------|------|------|---------------|-----------------------|--------|

## Confirmed Findings
<!-- CONFIRMED = ≥2 independent artefact types agree = High confidence -->
| ID | Finding | Sources (≥2) | Timestamp (UTC) | Skill(s) Used |
|----|---------|--------------|-----------------|---------------|

## Inferred Findings
<!-- INFERRED = 1 source or multiple sources of same type = Moderate confidence -->
| ID | Finding | Source | Timestamp (UTC) | Elevate when |
|----|---------|--------|-----------------|--------------|

## Contradictions
<!-- Never suppress — document and resolve -->
| ID | Source A | Source B | Resolution Status |
|----|----------|----------|-------------------|

## Active Hypotheses
| Hypothesis | Signals For | Signals Against | Status |
|------------|-------------|-----------------|--------|

## Critical Unknown (this period)
[The single most important unanswered question]

## Scope
**Confirmed in scope:** [machines / accounts]  
**Possible scope expansion:** [machines / accounts discovered but not yet analyzed]

## Completed Analysis Phases
[Skills invoked and what they produced]

## Next Actions (Period N+1)
[Prioritized task list]
```

---

## Evidence Volatility Ordering

Evidence decays in this order. Analyze in this sequence unless the temporal relationship
assessment (0C) overrides it:

| Priority | Evidence type | Why volatile |
|----------|--------------|--------------|
| 1 | Live memory | Lost on reboot; holds live C2 connections, injected code, plaintext credentials |
| 2 | Network connections (live) | TCP state cleared on reboot or connection close |
| 3 | Event log in-memory buffer | May not be flushed to disk; can be partially overwritten |
| 4 | KAPE collection / disk image | Stable once acquired; MFT, USN, registry |
| 5 | Cloud logs (CloudTrail, GuardDuty) | Stable but have retention windows; pull before they age out |
| 6 | Offline/archival logs | Stable |

---

## Operational Period Structure (max 4)

Each period follows the same cycle. Cap at 4 periods — if analysis is not converged
by period 4, declare incomplete and hand off to the report skill with the best-available COP.

```
Period start
  │
  ├─ 1. Read COP — what's confirmed, inferred, contradicted, unknown?
  ├─ 2. Apply Knowledge Gap Framework (see below)
  ├─ 3. Invoke skill(s) per routing table
  ├─ 4. Read skill outputs — classify each finding as CONFIRMED / INFERRED / CONTRADICTED
  ├─ 5. Update COP
  ├─ 6. Check cross-skill pivot table — does any finding trigger another skill?
  ├─ 7. Decide: open next period, or close case?
  │
  └─ If closing: invoke investigation-report skill with COP path
```

---

## Knowledge Gap Framework

Apply this at the start of every operational period before invoking any skill. Skipping
it leads to running everything in parallel and missing the answer that was already available.

State explicitly:

```
Known (CONFIRMED):   [findings with ≥2 independent sources]
Known (INFERRED):    [findings with supporting but not conclusive evidence]
Critical unknown:    [the single most important unanswered question this period]
Evidence that answers it: [which source type, and why it answers the question]
Skill to invoke:     [which domain skill, with specific objective]
Estimated cost:      [fast (<2 min) | moderate (2–10 min) | expensive (>10 min)]
Parallel eligible?:  [yes only if two independent unknowns confirmed — see gate below]
```

**Parallel activation gate:** Default is sequential — one skill at a time. Run two skills in
parallel only when all three conditions hold:
1. Triage (windows-artifacts initial pass) has completed and returned findings.
2. Two critical unknowns are confirmed independent (answering one does not change how
   you answer the other).
3. Neither is yara-hunting or malware analysis — those require a specific artifact identified
   by a prior skill and are never run before their prerequisite.

---

## Skill Routing Table

| Evidence available | Primary skill | Objective type |
|---|---|---|
| Memory image — inside attack window | `memory-analysis` | Live process state, C2 connections, injected code |
| Memory image — outside attack window | `memory-analysis` | Baseline comparison only; lower priority |
| KAPE collection (`$MFT` present) | `windows-artifacts` | Persistence, execution, credentials, lateral movement |
| IIS / web server logs | `windows-artifacts` → webserver phase | Initial access, webshell, LOLBin downloads |
| PCAP / pcapng / Zeek logs / netflow | `network-analysis` | C2 beaconing, exfiltration, credential exposure |
| Suspicious binary or memory dump flagged | `malware-analysis` | Capability profile, C2 URLs, ATT&CK techniques |
| Suspected malware — family/IOC match | `yara-hunting` | Confirm malicious classification, rule match |
| Linux host image or logs | `linux-endpoint` | Auth logs, bash history, cron, systemd persistence |
| Velociraptor collection (ZIP) | `linux-endpoint` | Hunt artifact parsing, process/network/persistence |
| EDR export (CrowdStrike/S1/Defender ATP) | `linux-endpoint` | Process tree, network connections, file writes |
| AWS CloudTrail / GuardDuty logs | `cloud-forensics` | IAM abuse, IMDS theft, S3 exfil |
| Cross-source timeline needed | `plaso-timeline` | When EVTX + MFT + registry need unified timeline |
| macOS endpoint involved | `macos-triage` | Unified log, FSEvents, quarantine DB |
| All analysis complete, findings stable | `investigation-report` | Final documented report |

**Sequencing heuristic for common patterns:**

| Situation after initial triage | Next skill priority |
|---|---|
| Active compromise confirmed, C2 unknown, memory inside attack window | `memory-analysis` — netscan for live C2 connections |
| Credential theft confirmed, no network artifacts | `memory-analysis` — check for live connections and in-memory creds |
| Suspicious binary identified by hash or path | `yara-hunting` — targeted, with specific file path |
| Persistence found on disk, memory predates attack | `windows-artifacts` — full artifact sweep |
| Lateral movement confirmed to new machine | Expand scope — add new machine to evidence inventory |
| All disk + memory complete, gaps remain | Document as unresolved; do not loop indefinitely |

---

## Cross-Skill Pivot Protocol

When a skill produces one of these findings, take the corresponding action before closing
the operational period:

| Finding | Pivot action |
|---|---|
| `malfind` produces PE dump with MZ header | Feed dump to `yara-hunting`; cross-check hash against disk artifacts in `windows-artifacts` ShimCache/Amcache |
| Memory netscan reveals external C2 IP | Add to IOC master; check disk event logs for matching outbound connections (EVTX EID 5156 / Sysmon EID 3) |
| Credential theft confirmed (LSASS, SAM) | Check all other machines in scope for same account's logon events — scope may need to expand |
| Lateral movement to new host confirmed | Add new host to evidence inventory; open new objective for that machine next period |
| Unquoted service path identified | Check MFT for file creation at candidate resolution paths within 24h of service install/start |
| New external IP from any skill | Add to IOC master; pivot to `yara-hunting` if it appears as a C2 callback URL in strings |
| Webshell confirmed (webshell_inventory.csv) | Check Sysmon EID 1 for `w3wp.exe` child processes on that machine; cross-ref lolbin_downloads.csv |
| Hash from any skill not previously seen | Run `yara-hunting` against it before reporting — may match known threat actor tooling |
| `$STANDARD_INFO` predates `$FILE_NAME` by >1s | Flag timestomping in COP; check nearby MFT entries for same attacker session |
| Cloud role abuse confirmed (IMDS theft) | Check CloudTrail for all API calls from stolen access key; expand cloud-forensics scope to all regions |

---

## Finding Taxonomy

Every finding placed in the COP must carry one of three classifications. These map
directly to the analytic confidence levels in the investigation-report skill:

| Taxonomy | Confidence | Criteria | Report language |
|----------|-----------|----------|-----------------|
| **CONFIRMED** | High | ≥2 independent artefact types agree | "The evidence establishes…" / state directly |
| **INFERRED** | Moderate | 1–2 sources, consistent with other context | "Evidence strongly suggests…" / "consistent with X" |
| **CONTRADICTED** | Unresolved | Two sources disagree | Document both; never suppress; resolve before report |

**Elevating INFERRED → CONFIRMED:** State explicitly what additional evidence is needed and
which skill would provide it. If that skill has already run and didn't resolve it, record
the gap in the COP and move on — do not loop the same skill.

**Handling CONTRADICTIONS:** Raise a sub-objective next period: "Resolve contradiction
between [Source A] and [Source B] regarding [finding]." If unresolved by period 4, report
both in the final report with the contradiction noted explicitly.

---

## Scope Management

Scope expands when a skill finds evidence of activity on machines not in the original
evidence inventory (lateral movement artifacts, remote logon events pointing to new hosts,
cloud APIs called from new regions).

When scope expansion is detected:
1. Add new machines/sources to the COP under "Possible scope expansion."
2. Do not automatically analyze them — flag for human operator decision.
3. Note in the COP what evidence suggests they are in scope and what the risk of
   not analyzing them is.
4. If the operator confirms expansion: add to evidence inventory, re-run 0A–0C for
   new sources, open a new objective next period.

Scope does not expand automatically. The operator gates it.

---

## Case Closure

Close the case when one of the following is true:
- All critical unknowns are resolved (CONFIRMED or documented as unresolvable with
  available evidence).
- The operational period cap (4) has been reached.
- The operator explicitly closes the case.

**Closure checklist:**
- [ ] All findings in COP are classified (CONFIRMED / INFERRED / CONTRADICTED)
- [ ] All contradictions documented with resolution status
- [ ] All scope expansion decisions recorded (expanded or explicitly deferred)
- [ ] Evidence hash file present at `./analysis/evidence_hashes.txt`
- [ ] COP updated to final state with `Status: Closed — Period N`
- [ ] Cross-skill pivots exhausted (no outstanding pivot actions)

Then invoke: `@~/.claude/skills/investigation-report/SKILL.md`

Pass the COP path (`./analysis/cop.md`) to the report skill. The report skill reads the
COP as its primary input for confirmed/inferred findings, supplementing with raw workflow
output files for the detailed evidence tables.

---

## Output Paths

| Artifact | Path |
|----------|------|
| Common Operating Picture | `./analysis/cop.md` |
| Evidence hashes (chain of custody) | `./analysis/evidence_hashes.txt` |
| Investigation report (from report skill) | `./reports/investigation_report.md` |
