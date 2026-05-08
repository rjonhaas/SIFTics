# Skill: Investigation Section Chief (DFIR — NIMS ICS Role)

## Role and command structure

This skill defines the agent's role within the NIMS Incident Command System (ICS) for DFIR
engagements:

- **The human analyst is the Incident Commander (IC).** They hold authority over scope,
  resource allocation, chain-of-custody calls, threat-actor attribution, customer
  deliverables, and case closure.
- **The agent is the Investigation Section Chief (ISC).** Per NIMS doctrine the
  Intelligence/Investigations Section reports directly to the IC and is responsible for
  collecting, analyzing, and synthesizing investigative information; producing intelligence
  products; and recommending courses of action. The ISC has significant tactical autonomy
  inside its section but does not make IC-reserved decisions.

The ISC operates the SIFTics workflow on the IC's behalf. The Common Operating Picture
(COP) is the ISC's primary intelligence product — it is delivered to the IC at every
operational period boundary for review.

---

## When to invoke

The IC invokes this skill **at the start of every case**, before any other skill runs. The
ISC owns the investigation lifecycle: what to analyze, in what order, when to pivot, and
when findings are complete enough to recommend case closure to the IC. If a case was
started without the ISC skill and analysis is already underway, invoke the ISC to read
existing outputs and establish the COP from current state.

**The ISC never executes forensic tools directly.** It directs which skill to invoke next
and synthesizes findings across skills. Tool execution happens inside the domain skills
(memory-analysis, windows-artifacts, yara-hunting, etc.) and the SIFTics phase scripts
(invoked via the `triage-methodology` skill).

---

## Hard Rules

- The ISC reports to the IC. Authority-gated decisions (see **Authority Gates** below) are
  recommended in the COP for IC review, never made unilaterally.
- The ISC operates autonomously through analysis. It does not pause to wait for IC input
  on routine sequencing, skill selection, or technical findings — those are within ISC
  tactical authority. It records authority-gated decisions in the COP and continues.
- Never call forensic tools directly. Invoke domain skills or the `triage-methodology`
  pipeline driver; they handle execution.
- Never write to evidence directories (`/cases/`, `/mnt/`, `/media/`).
- Never suppress a contradiction between sources — document it and resolve it.
- Every finding must be classified as CONFIRMED, INFERRED, or CONTRADICTED before
  it enters the COP.
- Cap at **4 operational periods** per case. If not converged by period 4, the ISC
  produces the best-available COP with a closure recommendation; the IC decides closure.
- The investigation-report skill is invoked by the ISC at case closure on the IC's
  authority — not by the analyst independently and not by the ISC unilaterally.

---

## Authority Gates

The ISC has wide tactical autonomy but does **not** unilaterally make the following
decisions. For each: take the documented technical action, record the decision in the COP
"Decisions Pending IC Review" section, and continue analysis. The IC ratifies, overrides,
or requests further work at COP review time. **The ISC does not pause analysis waiting for
IC input** — the autonomy contract is preserved.

| Decision | ISC action | IC authority |
|---|---|---|
| Chain of custody hash mismatch (intake hash check) | Log the mismatch in COP `Chain of Custody Status` as FAILED with the specific files affected; **continue analysis**. Tag every downstream finding on affected evidence with `coc_gap=true` so the IC sees the qualifier in the report. This is IR — speed beats prosecution-grade rigor. | Decide whether to re-collect, accept the gap in the final report, or escalate to a forensic-track investigation |
| Scope expansion to a machine outside the original brief | Log the discovery in COP "Possible scope expansion"; do **not** begin analysis on the new machine if no evidence has been collected for it | Authorize expansion; request collection from the new system |
| Case closure (4-period cap or natural end-of-leads) | Produce the best-available COP with a "Closure recommended" entry citing the trigger | Declare the case closed; sign off on deliverables |
| Extending past 4 operational periods | Flag the request in COP "Decisions Pending IC Review" with the specific reason additional periods are required | Authorize additional periods (or instruct the ISC to close with current findings) |
| Contradiction unresolved by period 4 | Document both sources, the contradiction, and the analysis state | Decide which source to trust, request additional analysis, or accept the contradiction in the report |
| Threat-actor attribution beyond technique-level | Report CVE attribution and TTP profile factually; do **not** name a specific actor in the COP or report without explicit IC instruction | Approve any actor-naming language in the customer-facing report |
| Production of customer-facing report | Draft via investigation-report skill; do **not** mark as final | Review draft, request revisions, approve for delivery |
| Deviation from analyst-extended Break Conditions in `triage-methodology` | Take the most reasonable action; record the deviation in COP "Decisions Pending IC Review" | Confirm or correct the ISC's reasoning |

---

## Deprecated Skills Note

> **`linux-endpoint` is deprecated.** It was the predecessor to the `linux-host` + `edr-telemetry` split and should NOT be invoked. Route Linux host forensics to `linux-host` and Velociraptor/EDR collections to `edr-telemetry`.

---

## Phase 0 — Case Initialization

Run once at case start, before Period 1.

### 0A. Evidence Inventory

Survey the case root and record every evidence source:

```bash
# *.zip includes Velociraptor collection archives
find /cases/<case_name> -maxdepth 3 \( \
  -name "*.raw" -o -name "*.mem" -o -name "*.dmp" -o -name "*.vmem" \
  -o -name "*.img" -o -name "*.E01" -o -name "*.ex01" \
  -o -name "*.pcap" -o -name "*.pcapng" \
  -o -name "*.evtx" \
  -o -name "\$MFT" \
  -o -name "*.jsonl.gz" -o -name "*.json.gz" \
  -o -name "*.zip" \
\) | sort
```

For each source, record: type, path, file size, and — critically — its **capture timestamp**
relative to the suspected attack window (see 0B).

### 0B. Evidence Integrity (chain of custody)

**Step 1 — Check for intake hashes from the collector.**

Look for `evidence_hashes.txt` already present in the case root (provided by the collecting party):

```bash
ls ./evidence_hashes.txt 2>/dev/null || echo "no intake hashes"
```

**If intake hashes exist (VERIFY mode):** Compare every file against the provided hashes.

```bash
sha256sum --check ./evidence_hashes.txt 2>&1 | grep -v "OK$"
```

- If all hashes match → Chain of custody status: **VERIFIED**. Record in COP.
- If any hash mismatches → Chain of custody status: **FAILED**. **This is an IR
  engagement — the ISC does not halt.** Document the specific files that failed
  verification in the COP. Tag any downstream finding derived from affected evidence with
  `coc_gap=true` so the report carries the qualifier. Add a row to COP "Decisions Pending
  IC Review" recommending re-collection if the IC wants to escalate to a forensic-track
  investigation. Continue analysis — speed against the attacker beats prosecution-grade
  rigor in IR.

**If no intake hashes exist (GENERATE mode):** Generate hashes at analyst's first contact and record a gap warning:

```bash
mkdir -p ./analysis/
find /cases/<case_name> -not -path "*/analysis/*" -not -path "*/exports/*" \
  -not -path "*/reports/*" -type f \
  -exec sha256sum {} \; | tee ./analysis/evidence_hashes.txt
```

Record in COP: `WARNING: No intake hash manifest was provided. Hashes generated by analyst at first contact — chain of custody gap exists between collection and analysis start.`

> **Note:** Writing to `./analysis/` within the case working directory is permitted — only raw evidence files in the case root must not be modified.

**Step 2 — Add Chain of Custody Status to COP** (see 0D template below for the section format).

**Step 3 — Verify readonly mounts** before any analysis tools run:

```bash
bash "${SIFTICS_HOME:-/home/sansforensics/SIFTics}/scripts/verify_readonly_mounts.sh" /cases/<case_name>
```

Any `rw` mount on evidence paths must be remounted `ro` before proceeding.

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
| Memory image | Before attack window | Predates attack | Run as baseline comparison only — after disk analysis; do not prioritize for live C2 state |

**If memory capture timestamp falls inside the active attack window** (attacker was operating
when snapshot was taken): memory-analysis runs before disk analysis. Live C2 connections,
active implants, and in-memory credentials take priority over historical reconstruction.

**If memory predates the attack or is unavailable**: disk/artifact analysis runs first.
Memory analysis is for live state — it cannot tell you what happened before the capture.

### 0D. COP Initialization

Create the COP file at `./analysis/cop.md`. This file is the single source of truth for the
investigation state and the ISC's primary intelligence product delivered to the IC. It is
updated at the end of every operational period.

```markdown
# COP — [CASE_NAME]
**Period:** 0 of 4  
**Updated:** [UTC]  
**Status:** Initialized
**Incident Commander:** [analyst name]  
**Investigation Section Chief:** SIFTics agent

## Chain of Custody Status
<!-- VERIFIED = intake hashes provided and matched | GENERATED = analyst-generated, gap documented | FAILED = hash mismatch — IC authority gate -->
**Status:** [VERIFIED / GENERATED / FAILED]  
**Hash file:** `./analysis/evidence_hashes.txt`  
**Note:** [e.g. "No intake hashes provided — gap between collection and analysis start" or "All intake hashes verified"]

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
**Possible scope expansion:** [machines / accounts discovered but not yet analyzed — pending IC authorization to collect/expand]

## Completed Analysis Phases
[Skills invoked and what they produced]

## Outstanding Pivot Actions
| ID | Finding | Source Skill | Target Skill | Status |
|----|---------|-------------|--------------|--------|

## Decisions Pending IC Review
<!-- ISC populates this whenever an Authority Gate triggers (see Authority Gates section in skill).
     IC reviews at each operational period boundary; writes a Decision column entry. -->
| ID | Authority Gate | ISC Action Taken | ISC Recommendation | IC Decision | Status |
|----|----------------|------------------|--------------------|-------------|--------|

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

Each period follows the same cycle. Cap at 4 periods. If analysis is not converged by
period 4, the ISC produces the best-available COP with a closure recommendation in
"Decisions Pending IC Review" (Authority Gate: case closure). The IC decides closure.

```
Period start
  │
  ├─ 1. Read COP — what's confirmed, inferred, contradicted, unknown?
  ├─ 2. Apply Knowledge Gap Framework (see below)
  ├─ 3. Invoke skill(s) per routing table
  ├─ 4. Read skill outputs — classify each finding as CONFIRMED / INFERRED / CONTRADICTED
  ├─ 5. Update COP — including Decisions Pending IC Review for any Authority Gate triggered
  ├─ 6. Check cross-skill pivot table — does any finding trigger another skill?
  │      When a cross-skill pivot is triggered, add a row to the Outstanding Pivot Actions
  │      table in the COP with Status=OPEN. Mark it RESOLVED when the target skill returns findings.
  ├─ 7. Decide: open next period, or recommend case closure to the IC?
  │
  └─ If recommending closure: invoke investigation-report skill with COP path, draft only;
     IC reviews and approves before delivery
```

---

## Prompt Injection Defense

Before passing any attacker-controlled content to an LLM (via the investigation-report skill or cve-attribution skill), sanitize the following file types:

```bash
python3 ${SIFTICS_HOME:-/home/sansforensics/SIFTics}/scripts/sanitize_for_llm.py \
    <case_root>/analysis/<MACHINE>/WebServer/injection_attempts.csv
python3 ${SIFTICS_HOME:-/home/sansforensics/SIFTics}/scripts/sanitize_for_llm.py \
    <case_root>/analysis/<MACHINE>/Browser/<*_History.csv>
```

Files to sanitize before LLM reads them: `injection_attempts.csv`, browser history CSVs, email message CSVs, bash history CSVs, IIS log-derived CSVs. Document which files were sanitized in the COP under "Completed Analysis Phases".

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
1. Initial triage for the primary evidence type has completed and returned findings. For Windows KAPE collections: windows-artifacts initial pass. For Linux hosts: linux-host initial pass. For EDR/Velociraptor: edr-telemetry initial pass. For cloud: cloud-forensics initial pass. For macOS endpoints: macos-triage skill run (single-pass skill).
2. Two critical unknowns are confirmed independent (answering one does not change how
   you answer the other).
3. Neither is yara-hunting or malware analysis — those require a specific artifact identified
   by a prior skill and are never run before their prerequisite.

---

## Skill Routing Table

**Pipeline driver (invoke at the start of Period 1 for any SIFTics-scripted evidence type):**

| Evidence available | Pipeline skill | What it does |
|---|---|---|
| Windows KAPE collection, raw IIS logs, PST/OST/mbox, Linux ext4 partition, or any combination | `triage-methodology` | Sequences the SIFTics `run_*.sh` phase scripts; replaces the deleted `run_all.sh` orchestrator. Decides which phases apply, in what order, with break conditions for findings that should reorder the pipeline. |

**Domain skills (invoked for deeper interpretation, or for evidence types not driven by the pipeline):**

| Evidence available | Primary skill | Objective type |
|---|---|---|
| Memory image — inside attack window | `memory-analysis` | Live process state, C2 connections, injected code |
| Memory image — outside attack window | `memory-analysis` | Baseline comparison only; lower priority |
| KAPE collection (`$MFT` present) | `windows-artifacts` | Persistence, execution, credentials, lateral movement |
| IIS / web server logs | `windows-artifacts` → webserver phase | Initial access, webshell, LOLBin downloads |
| PCAP / pcapng / Zeek logs / netflow | `network-analysis` | C2 beaconing, exfiltration, credential exposure |
| Suspicious binary or memory dump flagged | `malware-analysis` | Capability profile, C2 URLs, ATT&CK techniques |
| Suspected malware — family/IOC match | `yara-hunting` | Confirm malicious classification, rule match |
| Linux host image or logs | `linux-host` | Auth logs, bash history, cron, systemd persistence |
| Velociraptor collection (ZIP) | `edr-telemetry` | Hunt artifact parsing, process/network/persistence |
| EDR export (CrowdStrike/S1/Defender ATP) | `edr-telemetry` | Process tree, network connections, file writes |
| AWS CloudTrail / GuardDuty logs | `cloud-forensics` | IAM abuse, IMDS theft, S3 exfil |
| Cross-source timeline needed | `plaso-timeline` | When EVTX + MFT + registry need unified timeline |
| Raw disk image (no pre-extracted artifacts) | `sleuthkit` | File system triage, MFT recovery, file carving |
| macOS endpoint involved | `macos-triage` | Unified log, FSEvents, quarantine DB |
| All analysis complete, findings stable | `investigation-report` | Final documented report (draft — IC approval required for delivery) |
| Investigation report complete, exploitation mechanism identified | `cve-attribution` | CVE attribution via Intel ICS Phase 16 |

**Sequencing heuristic for common patterns:**

| Situation after initial triage | Next skill priority |
|---|---|
| Active compromise confirmed, C2 unknown, memory inside attack window | `memory-analysis` — netscan for live C2 connections |
| Credential theft confirmed, no network artifacts | `memory-analysis` — check for live connections and in-memory creds |
| Suspicious binary identified by hash or path | `yara-hunting` — targeted, with specific file path |
| Persistence found on disk, memory predates attack | `windows-artifacts` — full artifact sweep |
| Lateral movement confirmed to new machine | Authority Gate — log scope expansion in COP for IC review; analyze only if evidence already collected |
| All disk + memory complete, multi-source timeline needed | `plaso-timeline` — unified cross-source timeline |
| All disk + memory complete, gaps remain | Document as unresolved; do not loop indefinitely |
| Active compromise on Linux host, no Windows evidence | `linux-host` — auth logs + bash history first, then `edr-telemetry` if Velociraptor available |
| Cloud account compromise suspected | `cloud-forensics` — GuardDuty + CloudTrail first, then scope to affected services |
| EDR-only evidence (no KAPE, no memory) | `edr-telemetry` — process tree + network connections; substitute for windows-artifacts triage |

---

## Cross-Skill Pivot Protocol

When a skill produces one of these findings, take the corresponding action before closing
the operational period:

| Finding | Pivot action |
|---|---|
| `malfind` produces PE dump with MZ header | Feed dump to `yara-hunting`; cross-check hash against ShimCache/Amcache at `./exports/shimcache/` (domain skill) or `<MACHINE>/Registry/` (SIFTics scripts) |
| Memory netscan reveals external C2 IP | Add to IOC master; check disk event logs for matching outbound connections (EVTX EID 5156 / Sysmon EID 3) |
| Credential theft confirmed (LSASS, SAM) | Check all other machines in scope for same account's logon events — Authority Gate may trigger if scope expansion to a new machine is implied |
| Lateral movement to new host confirmed | If host is in evidence inventory: open new objective for that machine next period. If not: Authority Gate — log in COP "Possible scope expansion" for IC review |
| Unquoted service path identified | Check MFT for file creation at candidate resolution paths within 24h of service install/start |
| New external IP from any skill | Add to IOC master; pivot to `yara-hunting` if it appears as a C2 callback URL in strings |
| Webshell confirmed (`<MACHINE>/WebServer/webshell_inventory.csv`) | Check Sysmon EID 1 for `w3wp.exe` child processes on that machine; cross-ref `<MACHINE>/WebServer/lolbin_downloads.csv`. Note: these files are produced by Phase 13 (run_webserver.sh), not by a domain skill. |
| Hash from any skill not previously seen | Run `yara-hunting` against it before reporting — may match known threat actor tooling |
| `$STANDARD_INFO` predates `$FILE_NAME` by >1s | Flag timestomping in COP; check nearby MFT entries for same attacker session |
| Cloud role abuse confirmed (IMDS theft) | Check CloudTrail for all API calls from stolen access key; expand cloud-forensics scope to all regions |
| `ioc_master.csv` populated | (produced by Phase 9 run_ioc_extract.sh, not by a domain skill) — deduplicate against IOC master before reporting |
| `lolbin_downloads.csv` present | (produced by Phase 13 run_webserver.sh, not by a domain skill) — cross-ref destination paths with webshell inventory |
| EVTX + MFT + registry timestamps diverge for same event OR timeline spans >7 days with gaps | Invoke plaso-timeline to build unified super-timeline across all sources |
| Unallocated space likely contains carved evidence | Invoke sleuthkit for file carving and MFT recovery |
| LaunchAgent/LaunchDaemon created in non-system path | Pivot to macos-triage for persistence analysis |
| Quarantine DB entry for suspicious download | Pivot to macos-triage; hash the file; consider yara-hunting |
| Unified Log shows suspicious process execution | Pivot to macos-triage for process tree reconstruction |
| Investigation report generated AND software version / process anomaly / archive pattern documented | Run `run_cve_attribution.sh` (Phase 16); re-invoke investigation-report skill to integrate Section 3B (draft only — IC approval required) |
| `ioc_master.csv` populated with HIGH-confidence IOCs AND Velociraptor configured | Run `run_detect_hunt_loop.sh` to push the IOCs as fleet-wide hunts via the MCP broker. New affected hosts surfaced → Authority Gate (scope expansion) — log in COP `Decisions Pending IC Review` and continue analysis on confirmed hosts. |
| Cross-host findings populated in `analysis/cross_host_findings.csv` (from detect-hunt loop) | Treat each new host as a scope-expansion candidate per Scope Management rules. If evidence already exists for the new host, ingest and re-run Layer 1–4. If not, surface for IC authorization. |

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
between [Source A] and [Source B] regarding [finding]." If unresolved by period 4, this is
an Authority Gate — log in COP "Decisions Pending IC Review"; the IC decides which source
to trust or whether the contradiction goes into the final report unresolved.

---

## Scope Management

Scope expands when a skill finds evidence of activity on machines not in the original
evidence inventory (lateral movement artifacts, remote logon events pointing to new hosts,
cloud APIs called from new regions).

When scope expansion is detected, apply the following rule:
- If lateral movement artifacts point to a machine already in the evidence inventory (KAPE
  or image present): the ISC adds it to scope, opens a new objective next period, and
  records the action in COP "Completed Analysis Phases". This is within ISC tactical
  authority — the evidence was already collected under the IC's original brief.
- If the machine has no evidence collected yet: **Authority Gate**. Add the machine to
  COP "Possible scope expansion" with what's known about it and the risk of not
  analyzing it. Do not attempt to analyze it (no evidence to work with). Log in
  "Decisions Pending IC Review" so the IC can authorize collection from the new system.
- The ISC does not pause to ask the operator. Continue analysis on machines in scope.

Record in the COP: what evidence suggests the new machine is in scope, what action the ISC
took, and the recommendation to the IC.

---

## Case Closure

The ISC recommends case closure when one of the following is true:
- All critical unknowns are resolved (CONFIRMED or documented as unresolvable with
  available evidence).
- The operational period cap (4) has been reached.
- Natural end-of-leads — no productive next pivot.

The ISC does not declare a case closed. Closure is an IC authority. The ISC produces the
final COP with a "Closure recommended" entry in "Decisions Pending IC Review" and drafts
the investigation report. The IC reviews, approves, and declares closure.

**ISC closure-readiness checklist** (complete before recommending closure to the IC):
- [ ] All findings in COP are classified (CONFIRMED / INFERRED / CONTRADICTED)
- [ ] All contradictions documented with resolution status (or flagged for IC if unresolved)
- [ ] All scope expansion decisions recorded (expanded internally, or flagged for IC if external)
- [ ] Evidence hash file present at `./analysis/evidence_hashes.txt`
- [ ] COP updated to "Status: Recommending closure — Period N"
- [ ] Cross-skill pivots exhausted — Outstanding Pivot Actions table in COP has no OPEN rows
- [ ] All Authority Gate items in "Decisions Pending IC Review" are populated and tagged with ISC recommendation
- [ ] Investigation report drafted via investigation-report skill; status = DRAFT (awaiting IC approval)

Then invoke: `@~/.claude/skills/investigation-report/SKILL.md`

Pass the COP path (`./analysis/cop.md`) to the report skill. The report skill reads the
COP as its primary input for confirmed/inferred findings, supplementing with raw workflow
output files for the detailed evidence tables. The report is produced in DRAFT status —
the IC reviews and approves before delivery.

---

## Output Paths

| Artifact | Path |
|----------|------|
| Common Operating Picture | `./analysis/cop.md` |
| Evidence hashes (chain of custody) | `./analysis/evidence_hashes.txt` |
| Investigation report (DRAFT — from report skill) | `./reports/investigation_report.md` |
| Hypothesis ledger (working theories) | `./analysis/hypotheses.jsonl` |
| Anomaly findings (cross-artifact contradictions) | `./analysis/anomalies.csv` |
| Self-correction iteration log | `./analysis/self_correction.jsonl` |
| Hunt artifacts (Velociraptor YAML, generated from findings) | `./analysis/hunt_artifacts/*.yaml` |
| Cross-host hunt findings (results from fleet sweep) | `./analysis/cross_host_findings.csv` |
| MCP broker per-call audit log | `./mcp_broker/audit.jsonl` |
