# SKILL: Investigation Report Generation

## When to invoke
Invoked by the **Incident Commander skill** at case closure, after all operational periods are
complete and the COP has been finalized. Do not invoke this skill directly to drive an
investigation — the IC skill owns investigation sequencing and pivot decisions. Invoke this
skill directly only if the IC skill was not used and workflow outputs already exist.

This skill is the **Documentation Unit**: it consumes completed analysis outputs and a
finalized COP and formats them into the written report. It does not decide what to analyze
or in what order.

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

**Script workflow background:** The phase completion signals (Phase 1–13) correspond to the SIFTics triage scripts:

| Phase | Script | Primary Output |
|-------|--------|----------------|
| 1 | run_ntfs.sh | MFT and filesystem timeline artifacts |
| 2 | run_registry.sh | `<MACHINE>/Registry/` CSVs |
| 3 | run_eventlogs.sh | `<MACHINE>/EventLogs/` CSVs |
| 4 | run_artifacts.sh | `<MACHINE>/Artifacts/` CSVs |
| 5 | run_execution.sh | `<MACHINE>/Execution/` CSVs |
| 6 | run_hunting.sh | `<MACHINE>/Hunting/` CSVs + `hunting_timeline.csv` |
| 7 | run_credaccess.sh | `credaccess_timeline.csv` |
| 8 | run_antiforensics.sh | `<MACHINE>/AntiForensics/` + `antiforensics_timeline.csv` |
| 9 | run_ioc_extract.sh | `ioc_master.csv`, `ioc_summary.txt` |
| 10 | run_c2_beacon.sh | `<MACHINE>/Execution/IIS/c2_beacon.csv` |
| 11 | run_browser.sh | `<MACHINE>/Browser/` CSVs |
| 12 | run_ransomware.sh | `<MACHINE>/Ransomware/` CSVs + `ransomware_summary.txt` |
| 13 | run_webserver.sh | `<MACHINE>/WebServer/` CSVs + `webserver_summary.txt` |

**Machine-namespaced paths:** The `<MACHINE>/` prefix in all paths refers to machine-named subdirectories under the case analysis root. For example: `/cases/jackofallhacks/analysis/DC01/Registry/`. List every machine present by enumerating these subdirectories.

**Domain skill output paths:** If domain skills were run instead of (or in addition to) the scripts, their outputs land in the following paths:

| Domain Skill | Output Directory |
|---|---|
| windows-artifacts | `./exports/evtx/parsed/`, `./exports/shimcache/`, `./exports/amcache/`, `./exports/registry/`, `./exports/mft/`, `./exports/shellbags/` |
| memory-analysis | `./analysis/memory/`, `./exports/malfind/`, `./exports/dumpfiles/`, `./exports/memdump/` |
| network-analysis | `./analysis/network/`, `./exports/network/` |
| malware-analysis | `./analysis/malware/`, `./exports/malware/` |
| yara-hunting | `./exports/yara_hits/`, `./exports/yara/case_rules/` |
| cloud-forensics | `./analysis/cloud/`, `./exports/cloud/` |
| linux-host | `./analysis/linux/`, `./exports/linux/` |
| edr-telemetry | `./analysis/velociraptor/`, `./analysis/edr/` |
| plaso-timeline | `./analysis/<CASE_ID>.plaso`, `./exports/<CASE_ID>_timeline.csv` |
| sleuthkit | `./analysis/bodyfile.txt`, `./exports/files/`, `./exports/tsk_recover/` |
| macos-triage | `$CASE/analysis/` (see macos-triage SKILL.md for subdirectory names) |

When domain skills were the primary analysis path, substitute these paths wherever `<MACHINE>/` script paths are referenced in Phase 3.

Check which output subdirectories and files exist and contain data:

```
<analysis_root>/
  ioc_master.csv              → Phase 9 complete (run_ioc_extract.sh)
  ioc_summary.txt             → Phase 9 complete (run_ioc_extract.sh)
  antiforensics_timeline.csv  → Phase 8 complete (run_antiforensics.sh)
  hunting_timeline.csv        → Phase 6 complete (run_hunting.sh)
  credaccess_timeline.csv     → Phase 7 complete (run_credaccess.sh)
  <MACHINE>/EventLogs/        → Phase 3 complete (run_eventlogs.sh)
  <MACHINE>/Registry/         → Phase 2 complete (run_registry.sh)
  <MACHINE>/Artifacts/        → Phase 4 complete (run_artifacts.sh)
  <MACHINE>/Execution/        → Phase 5 complete (run_execution.sh)
  <MACHINE>/AntiForensics/    → Phase 8 complete (run_antiforensics.sh)
  <MACHINE>/Hunting/          → Phase 6 complete (run_hunting.sh)
  <MACHINE>/Browser/          → Phase 11 complete (run_browser.sh)
  <MACHINE>/Execution/IIS/c2_beacon.csv → Phase 10 complete (run_c2_beacon.sh)
```

**Phase 1 startup check — evidence_hashes.txt:** Check for `./analysis/evidence_hashes.txt`. If absent: run the Phase 0B hash command now before proceeding to Phase 2. Do not skip Section 2A — it is mandatory regardless of whether the IC skill ran:

```bash
find . -not -path "*/analysis/*" -not -path "*/exports/*" \
  -not -path "*/reports/*" -type f \
  -exec sha256sum {} \; | tee ./analysis/evidence_hashes.txt
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

## Phase 2 — COP Review

If the Incident Commander skill was used, read the COP first:

```
./analysis/cop.md
```

The COP contains the IC's classified findings (CONFIRMED / INFERRED / CONTRADICTED),
active hypotheses, scope decisions, and any unresolved contradictions. Use it to:
- Pre-populate the Confirmed and Inferred Findings sections of the report
- Understand which machines are in scope and which are noted as possible expansions
- Know which contradictions require explicit discussion in the report body
- Identify which case type classification the IC reached (carry it into Phase 3 scoring)

If no COP exists (IC skill was not used), proceed directly to Phase 3 and run the
Case Type Classification subsection at the end before writing the report.

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
| Per-machine `Registry/Autoruns/*.csv` | Attacker-installed run keys — populate Section 9A |
| Per-machine `Registry/Services/*.csv` | Attacker-installed services — populate Section 9C |
| Per-machine `Execution/ScheduledTasks/*.csv` | Attacker-scheduled tasks — populate Section 9B |
| Per-machine `Registry/` CSVs | ShimCache, Amcache, ShellBags |
| Per-machine `Registry/ShellBags/<USER>/*.csv` | Folder browsing (File Explorer) — `FirstInteracted`, `LastInteracted`, `AbsolutePath` per user |
| Per-machine `Browser/*_Downloads.csv` | Tools/files the attacker downloaded via browser — `StartTime_UTC`, `TargetPath`, `SourceURL`, `State` |
| `./analysis/evidence_hashes.txt` | Chain of custody — SHA256 for all evidence files (Section 2A) |

### Scope-of-Compromise Reconstruction

Before writing Section 2, classify every machine in the evidence inventory using only harvested data:

| Status | Criteria |
|--------|----------|
| **CONFIRMED COMPROMISED** | ≥1 of: attacker account logon (EID 4624/4648), webshell execution (`w3wp.exe` child), lateral movement destination (remote execution event where this machine = target), credential theft event, attacker-installed persistence, anti-forensics activity |
| **POSSIBLE COMPROMISE** | Lateral movement artifact points *to* this machine (EID 4624 from known-attacker source IP) but no execution or persistence confirmed on this machine yet |
| **NOT ANALYZED** | Machine is in evidence inventory but no analysis workflow has run yet (e.g., KAPE present but no output in analysis dir) |
| **CONFIRMED CLEAN** | Analysis ran, no attacker indicators found. Only use this if analysis was complete — do not default to "clean" when not analyzed |

Document the scope table in Section 2. If a machine is POSSIBLE COMPROMISE, add it to Recommended Next Steps (Section 15) as a scope expansion candidate.

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
| `<MACHINE>/WebServer/injection_attempts.csv` | Phase 13 ran (run_webserver.sh) |
| `<MACHINE>/WebServer/lolbin_downloads.csv` | Phase 13 ran (run_webserver.sh) — produced by script, not domain skill |
| `<MACHINE>/WebServer/operator_sessions.csv` | Phase 13 ran (run_webserver.sh) |
| `<MACHINE>/WebServer/webshell_inventory.csv` | Phase 13 ran (run_webserver.sh) — produced by script, not domain skill |
| `webserver_summary.txt` | Phase 13 ran (run_webserver.sh) |
| `./analysis/cloud/gd_high_severity.csv` | Cloud-forensics skill ran (GuardDuty high severity ≥7) |
| `./analysis/cloud/ct_high_signal.csv` | Cloud-forensics skill ran (CloudTrail high-signal events) |
| `./analysis/cloud/ct_policy_changes.csv` | Cloud-forensics skill ran (IAM policy changes) |
| `./analysis/cloud/ct_s3_getobject.csv` | Cloud-forensics skill ran (S3 GetObject / exfil) |
| `./analysis/cloud/ct_external_role_use.csv` | Cloud-forensics skill ran (IMDS / external role use) |
| `./analysis/memory/svcscan.txt` | Memory dump analyzed with memory-analysis skill — populate Section 9C (Services) |

### Harvest format
For each file read, record:
- Source file path
- Key fields extracted (timestamps, usernames, IPs, hashes, paths, event IDs)
- Row counts where relevant

### Temporal Integrity Check (per machine)

Run this for every machine before writing any timeline findings. Document the results in the
Environment section of the report. Do not assume clocks are correct.

**Step 1 — Cross-source timestamp comparison:**
Compare timestamps for the same event across different artefact types on the same host:
- **Domain auth skew:** Find a logon session common to both the target machine (Security EID
  4624) and the DC (Kerberos EID 4768/4769). The delta between the two timestamps is the
  observed clock offset for that machine vs. the DC. Typical domain-joined machines: ±30 sec.
- **Process creation cross-check:** For key attacker processes, compare Sysmon EID 1
  `TimeCreated` against MFT `$STANDARD_INFO` `Created` or `LastModified` for the same executable.
- **File write cross-check:** Compare Sysmon EID 11 or Security EID 4663 timestamps against
  MFT `$STANDARD_INFO Created` for the same file path.

**Step 2 — Flag timestomping:**
Compare `$STANDARD_INFO Created` against `$FILE_NAME Created` for newly created files.
If `$STANDARD_INFO Created` predates `$FILE_NAME Created` by >1 second, timestomping is
likely — the attacker used SetFileTime to backdate the file. `$FILE_NAME` timestamps are
updated by the kernel and are significantly harder to forge without a driver.
Also check for System EID 4616 (system time changed) — an attacker may have shifted the
clock before or after activity to confuse timeline reconstruction.

**Step 3 — Document per machine:**
Record one Temporal Integrity block for each machine in the report's Environment section:

> **[MACHINE] — Temporal Integrity:** Clock offset vs. DC: [±N sec/min] (measured via
> EID 4624 / EID 4768 on [date]). [Timestamps used as-is / All timestamps for this machine
> shifted by N minutes in the report timeline.] [Timestomping suspected on: list files, if any.]
> [EID 4616 clock-change event observed at HH:MM UTC, if present.]

**Step 4 — Apply skew notation in timeline:**
When skew is ≥2 minutes, append `(±N min)` to every timestamp from that machine in the
chronological timeline. When skew is >10 minutes or when clock manipulation is suspected,
add a section-level callout:
> ⚠ Timestamps from [MACHINE] have an observed [N-minute] offset vs. the domain controller
> and should be interpreted with that uncertainty in mind.

### Attacker Activity Reconstruction

After harvesting process creation and browser artefacts, reconstruct the attacker's on-host activity in two categories:

**Attacker tool staging (browser downloads):**
- Read all `<MACHINE>/Browser/*_Downloads.csv` files. Flag rows where `TargetPath` or `SourceURL` contains tools inconsistent with the machine's role: network scanners (Advanced IP Scanner, Nmap, Angry IP), exploitation frameworks (Mimikatz, Cobalt Strike, Metasploit), remote admin tools (AnyDesk, PsExec), archiving tools used for exfiltration staging.
- Record `StartTime_UTC` (download time), `TargetPath`, `SourceURL`, `TotalBytes`, and `State` (Complete/Cancelled).
- Cross-reference the download `TargetPath` with Prefetch (`Artifacts/Prefetch/`) and Amcache/ShimCache (`Registry/`) to establish the **download-to-first-execution gap** — a key indicator of attacker operational tempo.

**File Explorer browsing (ShellBags):**
- Read `Registry/ShellBags/<USER>/*.csv` for every user on every machine. Extract `AbsolutePath`, `FirstInteracted`, `LastInteracted`, `ShellType`.
- Flag paths that match attacker-relevant locations:
  - Network shares on other machines (`\\<DC>\SYSVOL`, `\\<HOST>\C$`, `\\<HOST>\admin$`)
  - Staging directories (`Desktop`, `Downloads`, `%TEMP%`, `ProgramData`)
  - Sensitive server paths (SYSVOL, NETLOGON, backup directories, database folders)
- The `FirstInteracted` timestamp = when the folder was first opened in File Explorer. This can establish "attacker saw ransomware binary / staging directory" even when no file was executed from that location.
- ShellBags persist after file deletion and across reboots — they are high-value evidence of browsing activity that may not appear anywhere else.
- `UsrClass.dat` ShellBags (Explorer windows) are typically more complete than `NTUSER.DAT` ShellBags (open/save dialogs) — read both; prefer `UsrClass` for Explorer activity.

**Reconnaissance commands (post-exploitation):**
- Extract from Sysmon EID 1 or Security EID 4688 all process creation events where the parent chain leads to the attacker's entry point (webshell `w3wp.exe`, RDP session, lateral movement process).
- Enumerate common recon commands: `whoami`, `hostname`, `ipconfig`, `tasklist`, `netstat`, `nltest /dclist:`, `net group`, `net user`, `systeminfo`, `arp -a`, `nslookup`, `ping`, `dsquery`, `wmic`.
- Where IIS log `sc-bytes` is available, rank commands by response size — the largest response is the command that returned the most data to the attacker (highest intelligence value).
- Document the full sequence chronologically in Section 5A of the report.

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

**RDP lateral movement — session reconnect vs new logon:**

This is one of the most commonly missed lateral movement patterns. When an attacker uses stolen credentials to access a machine where the legitimate user already has a *disconnected* RDP session, Windows reconnects them into that existing session rather than creating a new one. The event signature is completely different from a fresh login:

| Scenario | Events generated | Log source |
|---|---|---|
| Fresh RDP login | EID 21 (session logon) + EID 22 (shell started) | LocalSessionManager/Operational |
| Reconnect to disconnected session | **EID 25 only** (session reconnection succeeded) | LocalSessionManager/Operational |
| Any inbound TCP on port 3389 | EID 261 (listener received connection) | RemoteConnectionManager/Operational |
| Successful auth (network level) | EID 1149 (network connection established) | RemoteConnectionManager/Operational |

**Detection methodology:**
1. Parse `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` with EvtxECmd — do not rely on Security.evtx alone for RDP; type-10 logon events (EID 4624) are only generated for new sessions, not reconnects.
2. Look for EID 25 events outside normal business hours or from accounts not expected to be active on that machine. The `UserName` field identifies the account; `Address` field is `LOCAL` for same-network connections (not the attacker's external IP).
3. Cross-reference with `RemoteConnectionManager%4Operational.evtx` EID 261 clusters — a burst of EID 261 events with no following EID 1149 = failed authentication attempts (credential spray). The first EID 25 after such a cluster = first successful lateral move.
4. The `Address: LOCAL` value in EID 25 does NOT mean the session originated from the local console — it means the connection came from within the same network segment. Always cross-reference with EID 261 source IPs and Security EID 4624 `IpAddress` fields to confirm the originating host.
5. Attacker operational tempo signal: measure the gap between the first EID 261 cluster (credential attempts) and the first EID 25 (success) — this indicates how long it took to identify the correct credential pair.
6. **Always calculate RDP session duration for every session found.** Session lifecycle events in LocalSessionManager:
   - **Session start:** EID 25 (reconnect) or EID 21 (fresh logon) → `Address` field contains source IP
   - **Session end:** EID 24 (client disconnected / session disconnected) → immediately follows EID 40
   - Duration = EID 24 `TimeCreated` − preceding EID 25/21 `TimeCreated` for the same Session ID and user
   - Report as `mm:ss` or `hh:mm:ss` depending on length
   - Multiple sessions (connect → disconnect → reconnect) should each be timed separately and summed for total dwell time on that machine

**Log files to parse explicitly (not covered by standard Phase 3 event log parse):**
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`

### Case Type Classification

Run this subsection **after completing all Phase 3 reads above.** Score every type using only
evidence found in the harvest — not the Phase 2 pre-scan.

For each signal present in the harvested data, mark which types it supports:

| Signal found in harvest | Ransomware | APT/Targeted | Insider | BEC | Commodity |
|------------------------|:----------:|:------------:|:-------:|:---:|:---------:|
| VSS deletion | ✓ | | | | |
| Mass file modification (MFT / bulk unknown extensions) | ✓ | | | | |
| Ransom note files present | ✓ | | | | |
| Log clearing | ✓ | ✓ | | | |
| Long dwell time (>7 days gap between first and last event) | | ✓ | ✓ | | |
| C2 beaconing / periodic outbound connection | ✓ | ✓ | | | ✓ |
| Credential theft (LSASS, SAM, credential files) | | ✓ | | ✓ | |
| Lateral movement (remote execution, PsExec, WMI, RDP) | ✓ | ✓ | | | |
| Data staging or archiving tools | | ✓ | ✓ | ✓ | |
| Anomalous user activity vs. inferred role baseline | | | ✓ | ✓ | |
| Browser-downloaded attacker tools | | ✓ | ✓ | | |
| Single-machine scope confirmed | | | | | ✓ |
| Known-bad hash match (no novel malware indicators) | | | | | ✓ |
| Email artefacts + financial/HR system access | | | | ✓ | |

**Scoring rules:**
- **Primary type** — the type with the most signals checked.
- **Secondary type** — any other type with ≥2 signals checked. If none qualify, omit.
- If two types tie, list both as co-primary.
- **Confidence:** High = ≥4 distinct signals; Medium = 2–3; Low = ≤1 or inferred only.

**When multiple types have ≥2 signals**, the Executive Summary **must** include:

> "Evidence is primarily consistent with [PRIMARY TYPE] ([N] signals). Signals consistent with
> [SECONDARY TYPE] were also observed: [list the specific signals found]."

Do not suppress secondary signals to keep the narrative clean. A case that presents as
commodity malware but with lateral movement is an APT candidate — report both. The section
ordering in Phase 4 must include sections for every type with ≥2 signals, not just the primary.

---

## Phase 4 — Report Generation

Load `~/.claude/skills/investigation-report/template.md`. Fill each section using only harvested evidence. Apply the conditional logic defined in the template to include or exclude sections.

### Section ordering

Ordering is driven by your Phase 3 classification scores, not by a single rigid type.

**Step 1 — Lead with the primary type's section order:**

| Primary Type | Sections after Environment / Evidence Integrity |
|---|---|
| Ransomware | Timeline → Initial Access → Attacker Tooling & Recon → Persistence → Lateral Movement → Anti-Forensics → Memory (if present) → Cloud (if present) → Ransomware Indicators → IOCs → Recommendations |
| APT / Targeted Intrusion | Timeline → Initial Access → Attacker Tooling & Recon → C2 Infrastructure → Credential Access → Persistence → Lateral Movement → Anti-Forensics → Memory (if present) → Cloud (if present) → IOCs → Recommendations |
| Insider Threat | Timeline → Attacker Tooling & Recon → Data Staging → Persistence → Browser Artefacts → Anti-Forensics → Cloud (if present) → IOCs → Recommendations |
| General IR / mixed | Timeline → Initial Access (if present) → Credential Access → Persistence → Lateral Movement → Anti-Forensics → Memory (if present) → Cloud (if present) → Browser & User Behaviour → IOCs → Conclusions → Recommendations |

**Step 2 — Append secondary-type sections that aren't already included:**
For every type with ≥2 signals that is not the primary, include its characteristic sections
(Lateral Movement, Credential Access, Data Staging, etc.) before Recommendations. Head each
with a callout: `> **Note:** The following section addresses [SECONDARY TYPE] indicators also
> present in this case.`

**Step 3 — Never omit a section because it doesn't fit the primary type.**
If Lateral Movement evidence exists, the Lateral Movement section is in the report — regardless
of whether the primary classification is "Commodity Malware." Missing evidence that is in the
artefact record is the failure mode this ordering is designed to prevent.

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

### Analytic Confidence Framework

Every factual claim must carry a confidence level based on the number of **independent**
corroborating artefact sources. "Independent" means different artefact *types* — two EVTX
logs describing the same event count as one source, not two.

| Level | Independent sources | Required language | Example |
|-------|--------------------|--------------------|---------|
| **High** | ≥4 artefact types agree | "The evidence establishes…" / state the fact directly | EID 4624 + Sysmon EID 1 + Prefetch hit + MFT entry all agree on execution time and path |
| **Moderate** | 2–3 artefact types agree | "Evidence strongly suggests…" / "consistent with X" | Two log sources agree; no contradictory artefacts present |
| **Low** | 1 source, or multiple sources of the same type | "A single artefact is consistent with…" / "cannot be confirmed from available evidence" | Only one log entry; no corroboration from a different artefact class |

**Rules:**
- Do not use High-confidence language for a finding supported by a single uncorroborated
  log entry — that is Low confidence regardless of how clear the log looks.
- Do not use Low-confidence language ("consistent with") for a finding corroborated by four
  independent artefact types — that undersells the evidence and weakens the report.
- When confidence is Low, state explicitly what additional evidence would elevate it
  (e.g., "Memory analysis or endpoint telemetry would confirm whether X executed").
- Contradictory artefacts — e.g., EVTX shows process A, Sysmon shows process B at the same
  time — require explicit discussion. Do not silently prefer one source.
- "Consistent with" as a blanket hedge throughout the report is incorrect usage of this
  framework. Apply the right tier to each finding individually.

### Writing rules
- Lead each timeline section with the **earliest artefact timestamp**, not the most dramatic finding
- Use a table for any list of 3+ items (IPs, hashes, accounts, events)
- Apply the Analytic Confidence Framework above — do not default every finding to "consistent with"
- Flag gaps: if a phase did not run, write `[WORKFLOW GAP: Phase N not run — <section> findings may be incomplete]`
- Never pad. If a section has no findings, write "No artefacts recovered for this category" and move on

### Output
Write the completed report to `<case_root>/reports/investigation_report.md`. If a report already exists, write to `investigation_report_<YYYYMMDD_HHMM>.md` to avoid overwriting.

---

## Mandatory report sections (always present)

1. Executive Summary
2. Environment (machines, roles, users, subnet, **Scope of Compromise table**, **Temporal Integrity per machine**)
2A. Evidence Integrity (chain of custody — SHA256 hashes of all evidence files)
3. Attack / Incident Timeline (chronological, UTC; skew notations applied where applicable)
12. Indicators of Compromise (tables: IPs, hashes, domains, accounts, artefacts)
13. Conclusions
14. Recommended Next Steps

## Conditional report sections

| Section | Include when |
|---------|-------------|
| Initial Access — Web Server Triage (3A) | `webserver_summary.txt` exists with data (Phase 13) |
| C2 Infrastructure (4) | `c2_beacon.csv` exists with ≥1 row |
| Credential Access (5) | `credaccess_timeline.csv` has data |
| Attacker Tooling & Reconnaissance (5A) | Browser `*_Downloads.csv` has data OR Sysmon/4688 events show recon commands in attacker process chain |
| Privilege Escalation & Lateral Movement (6) | `hunting_timeline.csv` has data |
| Anti-Forensics (7) | `antiforensics_timeline.csv` has data |
| Ransomware & Exfiltration Indicators (8) | Any `<MACHINE>/Ransomware/` CSV exists with data (Phase 12) |
| Persistence Mechanisms (9) | Any Registry/Autoruns, Execution/ScheduledTasks, or Registry/Services CSV has attacker-created entries OR `./analysis/memory/svcscan.txt` contains non-baseline service entries |
| Memory Analysis (10) | Memory dump present under case root |
| Cloud Infrastructure (10A) | GuardDuty `.jsonl.gz` or CloudTrail `.json.gz` present under case root |
| Browser & User Behaviour (11) | Browser CSVs exist with data |
| File Explorer Browsing / ShellBags (subsection of §5A and §11) | `Registry/ShellBags/<USER>/*.csv` has rows with attacker-relevant paths |
| Ransomware Encryption Timeline (§8D subsection) | MFT shows mass file modification + VSS deletion |
| Workflow Coverage Gaps (15) | Any phase output is missing |
