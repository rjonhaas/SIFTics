# SKILL: Investigation Report Generation

## When to invoke
When the analyst requests an investigation report, case summary, or findings document after a triage workflow has run. The workflow output must exist before this skill runs — do not attempt to generate a report if analysis directories are empty.

---

## Constraints (non-negotiable)

- **No hallucinations.** Every IP, hash, username, path, timestamp, and event ID must be read directly from a workflow output file. If a fact is not in a file, it does not appear in the report.
- **Every claim cites a source.** Each finding must be traceable to a specific CSV, txt, or log file under the analysis directory.
- **All timestamps UTC.**
- **Do not infer tools, TTPs, or actor attribution** beyond what the artefact record directly supports. Use "consistent with" language, not declarative attribution.
- **Write to `./reports/`** — never to evidence directories or `/`.

---

## Phase 1 — Discovery

Before writing anything, survey the analysis directory completely.

### 1A. Identify completed workflow phases
Check which output subdirectories and files exist and contain data:

```
<analysis_root>/
  ioc_master.csv              → Phase 9 complete
  ioc_summary.txt             → Phase 9 complete
  antiforensics_timeline.csv  → Phase 8 complete
  hunting_timeline.csv        → Phase 6 complete
  credaccess_timeline.csv     → Phase 7 complete
  <MACHINE>/EventLogs/        → Phase 3 complete
  <MACHINE>/Registry/         → Phase 2 complete
  <MACHINE>/Artifacts/        → Phase 4 complete
  <MACHINE>/Execution/        → Phase 5 complete
  <MACHINE>/AntiForensics/    → Phase 8 complete
  <MACHINE>/Hunting/          → Phase 6 complete
  <MACHINE>/Browser/          → Phase 11 complete
  <MACHINE>/Execution/IIS/c2_beacon.csv → Phase 10 complete
```

List every machine present. Note which phases are missing — this affects what sections can be written.

### 1B. Identify available special artefacts
Check for:
- Memory dumps (`.7z`, `.raw`, `.mem`, `.dmp`) under the case root
- KAPE collections (presence of `$MFT` per machine)
- IIS log files
- Browser history CSVs
- Recycle Bin CSVs
- Scheduled task CSVs

### 1C. Note any workflow gaps
If a phase did not run (e.g., no `hunting_timeline.csv`), note it in the report under a "Workflow Coverage" callout. Do not omit sections silently.

---

## Phase 2 — Case Type Inference

Read the following files before classifying:
1. `ioc_summary.txt` — IOC volume and type distribution
2. `antiforensics_timeline.csv` — first 50 rows
3. `hunting_timeline.csv` — first 50 rows and last 50 rows (for dwell time)
4. Any `c2_beacon.csv` files

Classify the case into **one primary type** (and optionally a secondary):

| Type | Key Signals |
|------|-------------|
| **Ransomware** | VSS deletion + mass file modification in MFT + log clearing + possible ransom note path in file artefacts |
| **APT / Targeted Intrusion** | Long dwell time (weeks/months) + C2 beaconing + credential theft + lateral movement + deliberate anti-forensics |
| **Insider Threat** | Anomalous user activity during business hours + unusual data staging + browser searches inconsistent with role + off-hours access |
| **Business Email Compromise** | Email artefacts + access to financial/HR systems + external domain activity |
| **Malware / Commodity** | Known-bad hashes + no lateral movement + single-machine scope |
| **General IR** | Mixed or unclear signals |

The classified type controls:
- Which sections appear first in the report
- Which IOC types are emphasised
- The framing of the executive summary

---

## Phase 3 — Evidence Harvest

Read files in this priority order. Use the Explore agent for large directories. Do not fabricate row counts — read actual values.

### Always read
| File | Purpose |
|------|---------|
| `ioc_summary.txt` | Overall IOC picture, top/least frequent per type |
| `antiforensics_timeline.csv` | Full file — evidence destruction timeline |
| `credaccess_timeline.csv` | Full file — credential theft events |
| `hunting_timeline.csv` | Full file — PrivEsc, LM, remote execution event counts |
| Per-machine `Execution/` CSVs | Scheduled tasks, PS history, IIS logs, HTTPERR |
| Per-machine `AntiForensics/` CSVs | Log clearing, VSS deletion, Defender tampering, tools |
| Per-machine `Artifacts/` CSVs | LNK, Jump Lists, Recycle Bin, Prefetch |
| Per-machine `Registry/` CSVs | Autoruns, ShimCache, Amcache, ShellBags |

### Read if present
| File | Condition |
|------|-----------|
| `<MACHINE>/Execution/IIS/c2_beacon.csv` | IIS machine exists |
| `<MACHINE>/Browser/` CSVs | Browser phase ran |
| `<MACHINE>/Hunting/` CSVs | Hunting phase ran |
| `ioc_master.csv` (top 100 rows) | IOC phase ran |
| `ransomware_summary.txt` | Phase 12 ran |
| `<MACHINE>/Ransomware/*_ransom_notes.csv` | Phase 12 ran — per machine |
| `<MACHINE>/Ransomware/*_archives.csv` | Phase 12 ran — per machine |
| `<MACHINE>/Ransomware/*_suspicious_extensions.csv` | Phase 12 ran — per machine |
| `<MACHINE>/WebServer/injection_attempts.csv` | Phase 13 ran |
| `<MACHINE>/WebServer/lolbin_downloads.csv` | Phase 13 ran |
| `<MACHINE>/WebServer/operator_sessions.csv` | Phase 13 ran |
| `<MACHINE>/WebServer/webshell_inventory.csv` | Phase 13 ran |
| `webserver_summary.txt` | Phase 13 ran |

### Harvest format
For each file read, record:
- Source file path
- Key fields extracted (timestamps, usernames, IPs, hashes, paths, event IDs)
- Row counts where relevant

### Web Server / Initial Access Analysis (Phase 13)

When Phase 13 output is present (`webserver_summary.txt`), apply these additional guidelines:

**Webshell identification:**
- A webshell is a file created in the web root (`wwwroot`, `inetpub`, web application paths) with process-execution capability.
- Two-parameter authentication pattern: auth key (`p=`) + command (`cmd=`) — common in custom shells.
- Standard code signatures: `cmd.exe`, `powershell.exe`, or `System.Diagnostics.Process` inside `.aspx`/`.php`/`.jsp` files.
- Check `<MACHINE>/WebServer/webshell_inventory.csv` for files created in the web root during the incident window.
- Runtime signal: `w3wp.exe` spawning unexpected child processes (cmd.exe, powershell.exe, certutil.exe).

**OS Command Injection (CWE-78):**
- GET parameters passed to a shell without sanitisation appear in IIS W3C logs as URL-encoded payloads.
- Common vulnerable parameters: `url=` (download cradle), `cmd=` (execution).
- `injection_attempts.csv` contains URL-decoded payloads — read all rows to reconstruct the exploitation sequence.
- Classify by HTTP response code and response size: `200` with non-trivial body = likely executed.

**LOLBIN download cradles:**
- `certutil.exe -urlcache -f <url> <dest>`: arbitrary file download; common AV bypass.
- `bitsadmin /transfer`: background download, survives reboots.
- `powershell.exe -ep bypass -c (New-Object Net.WebClient).DownloadFile(...)`: PowerShell download.
- `lolbin_downloads.csv` records these events — cross-reference dest path with `webshell_inventory.csv` to confirm delivery.

**Operator vs automated traffic:**
- Interactive operator: browser User-Agent, irregular inter-request intervals, recon-style URIs (directory listing, `/whoami`, error-probing).
- Automated C2 / scanner: `curl`, `python-requests`, or custom UA; regular beacon intervals; fixed URI set.
- Webshell interaction: tool UA (e.g. `curl/8.5.0`) + `cmd=` or `url=` parameters in GET or POST.
- `operator_sessions.csv` groups by source IP + User-Agent + time window — use it to distinguish operator phases from automated phases.

**Transient scheduled task pattern:**
- Ransomware/lateral-movement scripts may create a task, fire it once, then delete it — total lifetime < 2 seconds.
- Task name often matches the temp output file prefix (random alphanumeric string).
- Event lifecycle: EID 4698 (task registered) → TaskScheduler/Operational EID 129 (task launched) → EID 4699 (Security, task deleted) → TaskScheduler/Operational EID 141 (task runner deleted).
- Parent of spawned process: `svchost.exe -k netsvcs -p -s Schedule` (Task Scheduler service host).
- Sysmon EID 1 captures full parent command line where Security EID 4688 `ProcessCommandLine` auditing is absent.
- If TaskScheduler/Operational.evtx was not in the initial parse, re-run EvtxECmd against it explicitly — it is a separate log from Security.evtx.

**Process tree reconstruction:**
- Build the chain bottom-up: start from the suspicious leaf process, find its PID as `ParentPID` in prior creation events.
- Sysmon EID 1 is authoritative for parent command line; Security EID 4688 only captures the parent image name unless `ProcessCommandLine` auditing is enabled.
- SYSVOL-delivered binaries (`\Device\Mup\<DC>\SYSVOL\...`): the binary never touches local disk — expect no Prefetch or ShimCache hit. Confirm via EID 4688 or Sysmon EID 1 `CommandLine` field.
- Document the tree as a freeform block in Section 6 of the report (see template).

---

## Phase 4 — Report Generation

Load `~/.claude/skills/investigation-report/template.md`. Fill each section using only harvested evidence. Apply the conditional logic defined in the template to include or exclude sections.

### Section ordering by case type

**Ransomware:** Executive Summary → Environment → Encryption Timeline → Anti-Forensics → Persistence → IOCs → Recommendations

**APT / Targeted Intrusion:** Executive Summary → Environment → Attack Timeline → Initial Access (Web Server Triage) → C2 Infrastructure → Credential Access → Lateral Movement → Anti-Forensics → IOCs → Recommendations

**Insider Threat:** Executive Summary → Environment → User Activity Timeline → Data Staging → Browser Artefacts → Anti-Forensics → IOCs → Recommendations

**All others:** Follow template default order.

### Ransomware case — encryption timing analysis

When the case type is Ransomware and Phase 12 output exists, distinguish two timestamps that investigators often conflate:

**1. First ransom note observed** — read directly from `ransomware_summary.txt` ("First indicator" line). This is a scripted, reliable value: the earliest timestamp of a ransom note filename appearing in 3+ distinct parent directories (the scatter pattern that proves ransomware ran). Use this as the confirmed lower bound on attacker presence.

**2. Estimated first file encrypted** — derived by the LLM from `*_suspicious_extensions.csv`:
- Read all rows with `assessment = BULK_UNKNOWN` across all machines.
- Filter to rows where `first_modified` falls within the incident window (use `ransomware_summary.txt` "First indicator" as the upper bound; work backwards).
- The earliest `first_modified` among those rows — provided it is within approximately 24 hours before the ransom note drop — is the estimated encryption start.
- If the earliest BULK_UNKNOWN `first_modified` is months before the ransom note, it likely represents pre-existing unknown files, not encrypted data. In that case, state "encryption start could not be isolated from pre-existing unknown extensions" and fall back to the ransom note timestamp as the best available lower bound.
- Qualify the estimate explicitly: "estimated encryption start" rather than "first file encrypted."

Include both timestamps in report Section 8D. The gap between them (typically seconds to minutes for fast encryptors, up to hours for slow/targeted ones) can indicate the encryptor type.

### Writing rules
- Lead each timeline section with the **earliest artefact timestamp**, not the most dramatic finding
- Use a table for any list of 3+ items (IPs, hashes, accounts, events)
- Qualify uncertainty: "consistent with credential harvesting" not "credential harvesting occurred"
- Flag gaps: if a phase did not run, write `[WORKFLOW GAP: Phase N not run — <section> findings may be incomplete]`
- Never pad. If a section has no findings, write "No artefacts recovered for this category" and move on

### Output
Write the completed report to `<case_root>/reports/investigation_report.md`. If a report already exists, write to `investigation_report_<YYYYMMDD_HHMM>.md` to avoid overwriting.

---

## Mandatory report sections (always present)

1. Executive Summary
2. Environment (machines, roles, users, subnet)
3. Attack / Incident Timeline (chronological, UTC)
4. Indicators of Compromise (tables: IPs, hashes, domains, accounts, artefacts)
5. Conclusions
6. Recommended Next Steps

## Conditional report sections

| Section | Include when |
|---------|-------------|
| C2 Infrastructure | `c2_beacon.csv` exists with ≥1 row |
| Memory Analysis | Memory dump present under case root |
| Anti-Forensics | `antiforensics_timeline.csv` has data |
| Credential Access | `credaccess_timeline.csv` has data |
| Privilege Escalation & Lateral Movement | `hunting_timeline.csv` has data |
| Browser & User Behaviour | Browser CSVs exist with data |
| IIS / Web Server Activity | IIS machine KAPE collection present |
| Ransomware & Exfiltration Indicators | Any `<MACHINE>/Ransomware/` CSV exists with data (Phase 12) |
| Ransomware Encryption Timeline | MFT shows mass file modification + VSS deletion |
| Initial Access — Web Server Triage | `webserver_summary.txt` exists with data (Phase 13) |
| Workflow Coverage Gaps | Any phase output is missing |
