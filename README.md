# SIFTics

DFIR triage workflow for the SANS SIFT Workstation. Claude Code orchestrates analysis; shell scripts extract and parse artifacts; skill files guide tool execution and reporting.

---

## Workflow Overview

```
Step 0  — Case setup: create CLAUDE.md at the case root
Step 1  — Extract evidence (KAPE ZIPs, memory images, PCAPs, cloud logs)
Step 2  — Run triage scripts: bash scripts/run_all.sh /cases/<case_name>
Step 3  — Invoke Claude Code: /incident-commander → domain skills → report
Step 4  — (optional) Run Phase 16 CVE attribution and regenerate report
Step 5  — (optional) Generate HTML deliverable: python3 scripts/gen_html_package.py /cases/<case_name>
```

---

## Step 0 — Case CLAUDE.md (Do This First)

Before running any scripts or analysis, create a `CLAUDE.md` at the case root. This file is loaded automatically by Claude Code when you open the case directory and grounds every analysis decision in the facts you know going in.

```bash
cp /home/sansforensics/projects/SIFTics/templates/case_claude.md /cases/<case_name>/CLAUDE.md
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

Scripts accept the case root as a positional argument. `run_all.sh` exports `CASE_ROOT` so child scripts inherit it automatically. Each script is also runnable standalone.

```bash
# Run full pipeline
bash scripts/run_all.sh /cases/<case_name>

# Run individual phase
bash scripts/run_ntfs.sh /cases/<case_name>
```

### Core Windows Triage (Phases 1–13)

Output lands in `<case_root>/analysis/<MACHINE>/<Category>/`.

| Script | Phase | What it does |
|--------|-------|-------------|
| `run_all.sh` | Orchestrator | Runs all phases in order; skips completed phases |
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

Domain skill files that Claude Code reads to guide tool execution. Invoke via the incident-commander skill at the start of every case.

| Skill | Domain |
|-------|--------|
| `incident-commander` | Investigation orchestration — invoke first |
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
| `investigation-report` | Final report generation (invoked by IC at case close) |
| `cve-attribution` | Intel ICS Phase 16 — CVE attribution from completed report |

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
