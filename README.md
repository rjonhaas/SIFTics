# SIFTics

DFIR triage workflow for the SANS SIFT Workstation. Claude Code orchestrates analysis; shell scripts extract and parse artifacts; skill files guide tool execution and reporting.

---

## Workflow Overview

```
Step 0  — Case setup: create CLAUDE.md at the case root
Step 1  — Extract evidence (KAPE ZIPs, memory images, PCAPs, cloud logs)
Step 2  — Open the case directory in Claude Code and invoke
          /investigation-section-chief. The agent (NIMS ICS Investigation Section
          Chief — your "Intel Section") reads the triage-methodology skill,
          decides which phase scripts apply, and sequences them. You (the human
          analyst) are the Incident Commander; the agent reports to you.
Step 3  — ISC invokes domain skills as findings dictate (memory-analysis,
          network-analysis, yara-hunting, etc.) and writes the
          Common Operating Picture (COP) at every operational period boundary.
          Authority-gated decisions (scope expansion, chain-of-custody issues,
          case closure) are surfaced in the COP for IC review without blocking
          analysis.
Step 4  — ISC drafts the investigation-report at recommended closure;
          IC reviews and approves before delivery.
Step 5  — (optional) Run Phase 16 CVE attribution; regenerate report.
Step 6  — (optional) Generate HTML deliverable:
          python3 scripts/gen_html_package.py /cases/<case_name>
```

There is no `run_all.sh` anymore. The agent **is** the orchestrator. For deterministic
re-execution (benchmark scenarios), invoke each `run_*.sh` script directly in numerical
order from the [Phase Catalog](skills/triage-methodology/SKILL.md#phase-catalog) — the
phase scripts' self-skip guards make this idempotent.

---

## Step 0 — Case CLAUDE.md (Do This First)

Before running any scripts or analysis, create a `CLAUDE.md` at the case root. This file is loaded automatically by Claude Code when you open the case directory and grounds every analysis decision in the facts you know going in.

```bash
cp "${SIFTICS_HOME:-/home/sansforensics/SIFTics}/templates/case_claude.md" /cases/<case_name>/CLAUDE.md
```

Then open it and fill in what you know:

| Section | What to capture |
|---------|----------------|
| **Case Identification** | Case name, type, analyst, case root path |
| **Attack Window** | Earliest compromise and latest known activity (UTC) with confidence level |
| **Machines in Scope** | Hostname, role, evidence path, collection type for each machine |
| **Known IOCs** | Any IPs, domains, hashes, accounts, or file paths known before analysis |
| **Investigator Context** | What the client reported, suspected threat actor, containment already done |
| **Evidence Inventory** | Source, type, path, capture timestamp, SHA256 for each evidence file |

**You do not need to know everything.** Partial information is better than nothing. Leave unknowns blank — Claude will fill gaps through analysis and update the COP accordingly.

The attack window is the most critical field. Even a rough estimate ("sometime in the week of 2025-03-03") anchors temporal analysis and prevents Claude from treating every artifact as equally relevant.

---

## Triage Scripts (`scripts/`)

Each script accepts the case root as a positional argument. Each is independently
runnable, idempotent, and self-skipping (re-running on a fully-analyzed case is a no-op).
Each sources `audit_log.sh` automatically and writes hash-chained entries to
`<case_root>/analysis/forensic_audit.jsonl`.

The agent invokes these via the [`triage-methodology`](skills/triage-methodology/SKILL.md)
skill, which encodes the sequencing logic, break conditions, and skip rules. Manual
invocation is also supported:

```bash
# Run a single phase
bash scripts/run_ntfs.sh /cases/<case_name>

# Run a sequence by hand (deterministic re-execution / benchmark mode)
for s in run_ntfs run_registry run_eventlogs run_artifacts run_execution \
         run_hunting run_credaccess run_antiforensics run_browser run_ransomware \
         run_webserver run_email run_linux run_ioc_extract run_c2_beacon \
         run_attack_path; do
    bash "scripts/${s}.sh" /cases/<case_name>
done
```

### Core Windows Triage (Phases 1–13)

Output lands in `<case_root>/analysis/<MACHINE>/<Category>/`.

| Script | Phase | What it does |
|--------|-------|-------------|
| `run_ntfs.sh` | 1 | MFT, Boot, LogFile, USN Journal |
| `run_registry.sh` | 2 | System/user hives, Amcache, ShimCache, ShellBags, RegBack |
| `run_eventlogs.sh` | 3 | All EVTX (EvtxECmd + Maps) |
| `run_artifacts.sh` | 4 | LNK, Jump Lists, Recycle Bin, Windows Timeline, Prefetch |
| `run_execution.sh` | 5 | IIS logs, HTTPERR, PowerShell history, Scheduled Tasks |
| `run_hunting.sh` | 6 | PrivEsc / Lateral Movement hunting over EVTX CSVs |
| `run_credaccess.sh` | 7 | DCSync, LSASS, Kerberoasting, WMI, timestomping |
| `run_antiforensics.sh` | 8 | Log clearing, VSS deletion, Defender tampering |
| `run_ioc_extract.sh` | 9 | IOC extraction (IPs/URLs/hashes/paths) across all CSVs |
| `run_c2_beacon.sh` | 10 | C2 beacon detection via IIS log interval analysis |
| `run_browser.sh` | 11 | Zone.Identifier/MotW, Chrome/Edge/Firefox/IE history |
| `run_ransomware.sh` | 12 | Ransom notes, suspicious extensions, archive staging |
| `run_webserver.sh` | 13 | IIS injection detection, LOLBIN downloads, webshell inventory |

### Extended / Specialist Phases (14–16)

| Script | Phase | What it does |
|--------|-------|-------------|
| `run_email.sh` | 14 | PST/OST/mbox parsing via readpst; message and attachment extraction |
| `run_linux.sh` | 15 | Linux partition analysis (ext4 via losetup); auth logs, bash history, cron, SSH keys |
| `run_cve_attribution.sh` | 16 | CVE attribution — reads completed report + COP, invokes Claude CLI, writes `analysis/cve_attribution.md` |

### Utility Scripts

| Script | What it does |
|--------|-------------|
| `run_mftecmd.sh` | Standalone MFT parser — parses `$MFT`, `$Boot`, `$LogFile`, `$J` for every machine under the case root |
| `daedalus_fingerprint.sh` | Artifact discovery — probes mounted evidence for all known artifact classes; outputs a run-plan manifest |
| `report_to_html.py` | Converts `reports/investigation_report.md` to a standalone dark-theme HTML report with sidebar TOC |
| `gen_html_package.py` | Produces a customer-ready ZIP: CISO dashboard, full report, analyst evidence hub, sortable CSV tables |
| `parse_apache_log.py` | Parses Apache combined/common access log format |
| `parse_bash_history.py` | Categorises bash history entries with IOC extraction |
| `parse_email.py` | Phase 14 email artifact parser (called by `run_email.sh`) |
| `install_tools.sh` | Pre-flight dependency checker; verifies required EZ Tools are present |

---

## Skills (`skills/`)

Domain skill files that Claude Code reads to guide tool execution. Invoke via the investigation-section-chief skill at the start of every case.

> **Roles (NIMS ICS):** You — the human analyst — are the **Incident Commander (IC)**.
> The agent runs as the **Investigation Section Chief (ISC)**, the role NIMS defines for
> the section that conducts the investigation under the IC's authority. The ISC has
> tactical autonomy inside its section but surfaces authority-gated decisions in the COP
> for the IC's review. See `investigation-section-chief/SKILL.md` for the full
> Authority Gates table.

| Skill | Domain |
|-------|--------|
| `investigation-section-chief` | The agent's NIMS ICS role — investigation lifecycle, COP, finding taxonomy, Authority Gates. Invoke first. |
| `triage-methodology` | Phase sequencing & decision engine — invoked by ISC at Period 1 (replaces `run_all.sh`) |
| `daedalus` | Adaptive artifact discovery and handler generation |
| `windows-artifacts` | EZ Tools, Event Logs, Registry |
| `memory-analysis` | Volatility 3, Memory Baseliner |
| `linux-host` | Auth logs, bash history, cron, SUID |
| `edr-telemetry` | Velociraptor, CrowdStrike, SentinelOne, MDE |
| `network-analysis` | PCAP, Zeek, tshark |
| `malware-analysis` | Static analysis, capa, strings |
| `yara-hunting` | YARA rules, IOC sweeps |
| `cloud-forensics` | AWS GuardDuty, CloudTrail, S3 |
| `macos-triage` | Unified Log, FSEvents, Quarantine DB |
| `plaso-timeline` | Cross-source super-timeline |
| `sleuthkit` | File system triage, MFT recovery, file carving |
| `investigation-report` | Final report generation — drafted by ISC at case closure; IC reviews and approves before delivery |
| `hypothesis-engine` | Working-theory ledger; signal scoring at each operational period (replaces "anchoring on first plausible explanation") |
| `cve-attribution` | Intel ICS Phase 16 — CVE attribution from completed report |

---

## Try It Out (judges, this section is for you)

This section is the reproducibility and Try-It-Out instructions required by the
hackathon submission rules. It assumes you have a fresh SANS SIFT Workstation
and Claude Code installed.

### 1. Install SIFTics

```bash
git clone https://github.com/rjonhaas/SIFTics.git ~/SIFTics
export SIFTICS_HOME=~/SIFTics

# Symlink skills into Claude Code's skill directory
mkdir -p ~/.claude/skills
for skill in ~/SIFTics/skills/*/; do
    ln -sf "$skill" ~/.claude/skills/$(basename "$skill")
done

# Verify dependencies
bash ~/SIFTics/scripts/install_tools.sh --check-only
```

### 2. Verify the architectural guardrails (no evidence required)

```bash
python3 ~/SIFTics/scripts/test_constraints.py
# Reads: nothing (uses temp dir)
# Writes: ~/SIFTics/reports/bypass_test_report.md + bypass_test_results.json
# Tests T1–T7 architectural / prompt-based boundaries
```

Expected outcome: T2 BLOCKED, T3 DETECTED (4/4), T4 DETECTED, T5 VERIFIED-PRESENT,
T6 DETECTED, T7 FULL-COVERAGE. T1 ALLOWED-OS-level (intentional — see report).

### 3. Run the accuracy benchmark against public CTF evidence

If you want to verify SIFTics' accuracy against documented ground truth, the repo
ships two benchmark manifests for public CTF cases:

| Case | Public source | Ground-truth checks |
|---|---|---|
| DEF CON 2019 DFIR CTF | DFA 2019 (publicly downloadable) | 21 checks across 10 phases |
| CyberDefenders Case 166 (SpottedInTheWild) | cyberdefenders.org | 16 checks across 7 phases |

Download the evidence to `/cases/<case_name>/`, then:

```bash
# Drive the pipeline (skill-driven, agent-orchestrated):
#   Open the case directory in Claude Code and invoke /investigation-section-chief.
#   The agent reads triage-methodology and runs phases 1-17 + 19 + 20 as evidence dictates.

# Or — for deterministic re-execution against the benchmark, drive manually:
for s in run_ntfs run_registry run_eventlogs run_artifacts run_execution \
         run_hunting run_credaccess run_antiforensics run_browser run_ransomware \
         run_webserver run_email run_linux run_ioc_extract run_c2_beacon \
         run_attack_path run_anomaly_check run_memory run_pcap; do
    bash ~/SIFTics/scripts/${s}.sh /cases/defcon2019_dfir
done

# Score against ground truth
python3 ~/SIFTics/scripts/score_benchmark.py \
    --case-dir /cases/defcon2019_dfir \
    --ground-truth ~/SIFTics/benchmark/ground_truth/defcon2019.json
```

Expected outcome: 21/21 (100% recall) on DEF CON 2019, 16/16 (100% recall) on
SpottedInTheWild. Phases 18/19/20 are new and not yet in the benchmark manifests
(scoring infrastructure is the same; ground truth needs to be added).

### 4. Demonstrate the self-correction loop

The killer-demo sequence the hackathon prompt requires (at least one self-correction
in the demo video). After the pipeline has run on a case with anti-forensic
indicators (DEF CON 2019 has VSS deletion + log clearing, ideal):

```bash
# Phase 18 detects contradictions across artifacts
bash ~/SIFTics/scripts/run_anomaly_check.sh /cases/defcon2019_dfir

# Self-correction loop reads anomalies.csv, picks first HIGH, re-runs
# the upstream phase, re-checks anomalies, iterates (max 3)
bash ~/SIFTics/scripts/run_self_correct.sh /cases/defcon2019_dfir

# Read the iteration trace
cat /cases/defcon2019_dfir/analysis/self_correction.jsonl
cat /cases/defcon2019_dfir/analysis/self_correction_report.md
```

Each iteration is recorded with timestamp, target anomaly, corrective action,
HIGH-anomaly count delta, and success/no-change/worse outcome.

### 5. Inspect the audit trail

Every command run by every phase script is hash-chained:

```bash
# Verify the chain has no breaks
bash ~/SIFTics/scripts/audit_verify.sh /cases/defcon2019_dfir/analysis/forensic_audit.jsonl

# Search by tool, machine, or keyword
bash ~/SIFTics/scripts/audit_query.sh \
    --tool MFTECmd /cases/defcon2019_dfir/analysis/forensic_audit.jsonl
```

Any finding in the COP or report can be traced back to the exact command that
produced it — meets the hackathon's Audit Trail Quality criterion.

### 6. Read the architecture diagram

See [`docs/architecture.md`](docs/architecture.md) for the full Mermaid diagram
showing IC/ISC roles, phase scripts, evidence sources, output pipeline, and the
explicit architectural-vs-prompt-based guardrail classification.

---

## Phase 16 — CVE Attribution

After the investigation report is complete, run Phase 16 to attribute exploitation patterns to known CVEs:

```bash
bash scripts/run_cve_attribution.sh /cases/<case_name>
```

The script reads `reports/investigation_report.md` and `analysis/cop.md`, calls the `claude` CLI with a focused CVE attribution prompt, and writes `analysis/cve_attribution.md`. Then re-run the investigation-report skill to integrate the output as Section 3B of the report.

**Requirements:** `claude` CLI in PATH (or set `CLAUDE_BIN=/path/to/claude`). Override the model with `CVE_MODEL=<model-id>`.

---

## HTML Deliverables

### Analyst report

Converts the markdown investigation report to a standalone HTML file with a dark theme and sidebar TOC:

```bash
python3 scripts/report_to_html.py /cases/<case_name>
# Output: reports/investigation_report.html
```

### Customer package

Produces a self-contained ZIP suitable for client delivery. No server required — customer unzips and opens `index.html`:

```bash
python3 scripts/gen_html_package.py /cases/<case_name>
# Output: reports/<case_name>_package.zip
```

The package contains:
- `index.html` — CISO executive dashboard (severity, findings, timeline, actions)
- `report.html` — Full rendered investigation report
- `analyst.html` — Analyst evidence hub (phase-ordered investigation journey)
- `csv/*.html` — Individual CSV artifact tables (sortable, searchable, paginated)

---

## Templates (`templates/`)

| File | Purpose |
|------|---------|
| `case_claude.md` | Case CLAUDE.md template — copy to case root and fill in at Step 0 |
