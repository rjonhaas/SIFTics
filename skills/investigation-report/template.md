# Investigation Report — {{CASE_NAME}}
<!-- Fill {{CASE_NAME}} from the case directory name -->

**Classification:** FOR OFFICIAL USE ONLY  
**Analyst:** {{ANALYST_EMAIL}}  
**Workstation:** SANS SIFT (Ubuntu x86-64)  
**Report Generated:** {{YYYY-MM-DD UTC}}  
**Evidence Root:** `{{CASE_ROOT}}`  
**Workflow Output:** `{{ANALYSIS_ROOT}}`  
**Case Type:** {{CASE_TYPE}} <!-- Ransomware | APT/Targeted Intrusion | Insider Threat | BEC | Malware/Commodity | General IR -->

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- MANDATORY: Always include                          -->
<!-- ═══════════════════════════════════════════════════ -->

## 1. Executive Summary

<!--
2–4 sentences covering:
  - What happened (case type, scope)
  - When it happened (earliest artefact → last observed activity, UTC)
  - What machines/accounts were involved
  - The most significant single finding
Do not list every finding here — that is what the body is for.
-->

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- MANDATORY                                          -->
<!-- ═══════════════════════════════════════════════════ -->

## 2. Environment

<!--
List every machine present in the case. Source: directory names under case root with $MFT present.
-->

| Machine | Role | Drive | Key Users Observed |
|---------|------|-------|--------------------|
| <!-- from KAPE dirs --> | | | |

**Domain:** <!-- from event log artefacts -->  
**Internal subnet:** <!-- from IOC top IPs -->  
**Known IP assignments:** <!-- from IOC data, if determinable -->

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- MANDATORY                                          -->
<!-- ═══════════════════════════════════════════════════ -->

## 3. {{TIMELINE_SECTION_TITLE}}
<!-- 
Default title: "Attack Timeline"
Ransomware: "Incident Timeline"
Insider Threat: "User Activity Timeline"

Organise chronologically by UTC timestamp. Group into named phases if the
evidence supports distinct phases (initial access, escalation, etc.).
Only create a phase if ≥2 artefacts support it — do not invent phases.

For each event row: source file must be noted either inline or in a footnote.
-->

### Phase 1 — {{PHASE_NAME}} ({{EARLIEST_TS}} – {{LATEST_TS}} UTC)

| Time (UTC) | Machine | Event ID | Detail | Source |
|------------|---------|----------|--------|--------|
| | | | | |

<!-- Repeat phase blocks as supported by evidence. -->

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- CONDITIONAL: include if webserver_summary.txt      -->
<!--             exists with data (Phase 13)            -->
<!-- ═══════════════════════════════════════════════════ -->

## 3A. Initial Access — Web Server Triage

<!--
Source: webserver_summary.txt + per-machine WebServer/ CSVs (Phase 13)
Describes how the attacker gained their initial foothold — typically via exploitation
of a public-facing web application (IIS, Apache) leading to webshell deployment.
-->

### Webshell Inventory

<!--
Source: <MACHINE>/WebServer/webshell_inventory.csv
List files created/modified in the web root during the incident window.
Even one webshell in wwwroot is HIGH severity.
-->

| Machine | Path | Filename | Size | Created (UTC) | Modified (UTC) | Assessment |
|---------|------|----------|------|--------------|----------------|-----------|
| | | | | | | |

### Exploitation Activity (OS Command Injection)

<!--
Source: <MACHINE>/WebServer/injection_attempts.csv
List GET/POST requests containing URL-decoded shell commands or download cradles.
Classify each by outcome (HTTP 200 + non-trivial response = likely executed).
-->

| Time (UTC) | Source IP | Method | URI | Decoded Payload | Status | Source |
|------------|-----------|--------|-----|-----------------|--------|--------|
| | | | | | | |

### LOLBIN Downloads via Web Server

<!--
Source: <MACHINE>/WebServer/lolbin_downloads.csv
Document files pulled from attacker-controlled infrastructure via certutil, bitsadmin,
PowerShell WebClient, or similar. Cross-reference dest path with webshell_inventory.csv
to confirm staged payload delivery.
-->

| Time (UTC) | Machine | LOLBIN | Source URL | Destination Path | Source |
|------------|---------|--------|-----------|-----------------|--------|
| | | | | | |

### Operator Sessions

<!--
Source: <MACHINE>/WebServer/operator_sessions.csv
Group by source IP + User-Agent. Distinguish interactive operator phases (browser UA,
irregular intervals, recon URIs) from automated tool phases (curl/custom UA, fixed URIs).
-->

| Source IP | User Agent | Request Count | Session Start (UTC) | Session End (UTC) | Phase |
|-----------|-----------|--------------|--------------------|--------------------|-------|
| | | | | | |

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- CONDITIONAL: include if c2_beacon.csv exists       -->
<!--             with ≥1 data row                       -->
<!-- ═══════════════════════════════════════════════════ -->

## 4. C2 Infrastructure

<!--
Source: <MACHINE>/Execution/IIS/c2_beacon.csv
Fields: source IP, request count, unique URIs, user agent, mean/median interval, beacon score, time range
-->

| External IP | Requests | Top URI | User Agent (truncated) | Mean Interval | Beacon Score | Time Range (UTC) |
|-------------|----------|---------|----------------------|---------------|-------------|-----------------|
| | | | | | | |

<!--
Narrative: describe what the beacon pattern suggests (automated vs operator-driven).
Note any URIs that suggest webshell or C2 framework (e.g. /CheckStatus.aspx, /upload.php).
-->

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- CONDITIONAL: include if credaccess_timeline.csv    -->
<!--             has data                               -->
<!-- ═══════════════════════════════════════════════════ -->

## 5. Credential Access

<!--
Source: credaccess_timeline.csv
Note: event IDs 4656/4663 (LSASS/SAM/NTDS), crash dumps, DCSync indicators, Kerberoasting (4769)
-->

| Time (UTC) | Machine | Technique | Account | Process | Source |
|------------|---------|-----------|---------|---------|--------|
| | | | | | |

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- CONDITIONAL: include if hunting_timeline.csv       -->
<!--             has data                               -->
<!-- ═══════════════════════════════════════════════════ -->

## 6. Privilege Escalation & Lateral Movement

<!--
Source: hunting_timeline.csv
Summarise event counts per machine per category, then call out the most significant individual events.
-->

**Event counts by machine:**

| Machine | PrivEsc Events | Lateral Movement Events | Remote Execution Events |
|---------|---------------|------------------------|------------------------|
| | | | |

**Notable events:**

| Time (UTC) | Machine | Event ID | Detail | Source |
|------------|---------|----------|--------|--------|
| | | | | |

**Execution chain (process tree):**

<!--
Reconstruct from Security EID 4688 + Sysmon EID 1. Show the full parent-child chain for
any significant remote/lateral execution event. Use freeform text — do not force into a table.
Format: indented block with timestamps.

Example:
  2026-03-08 22:09:42 svchost.exe -k netsvcs -p -s Schedule  [PID 1864, EID 4688 / Sysmon 1]
    └─ 2026-03-08 22:09:46 cmd.exe /c \\DC02\SYSVOL\sysAV.bat  [PID 7320, Security EID 4688]
         └─ 2026-03-08 22:09:46 \\DC02\SYSVOL\IamBatman.exe encrypt C:\  [PID 4444, Security EID 4688]

Notes:
- SYSVOL-delivered binaries never touch local disk: no Prefetch/ShimCache hit expected.
- Sysmon EID 1 captures parent CommandLine; Security EID 4688 captures parent image name only.
- Transient scheduled tasks (create → fire → delete < 2 s): confirm via TaskScheduler/Operational
  EIDs 106/129/141 alongside Security EIDs 4698/4699.
-->

```
[paste execution chain here]
```

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- CONDITIONAL: include if antiforensics_timeline.csv -->
<!--             has data                               -->
<!-- ═══════════════════════════════════════════════════ -->

## 7. Anti-Forensics

<!--
Source: antiforensics_timeline.csv + per-machine AntiForensics/ CSVs
Summarise by category, then timeline the most significant events.
-->

**Summary:**

| Category | Count | Machines Affected |
|----------|-------|------------------|
| Event log clearing (IDs 1102/104) | | |
| VSS shadow copy deletion | | |
| Windows Defender tampering | | |
| Timestomping | | |
| Anti-forensic tools detected | | |

**Key events:**

| Time (UTC) | Machine | Category | Detail | Source |
|------------|---------|----------|--------|--------|
| | | | | |

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- CONDITIONAL: include if any <MACHINE>/Ransomware/  -->
<!--             CSV exists with data                   -->
<!-- ═══════════════════════════════════════════════════ -->

## 8. Ransomware & Exfiltration Indicators

<!--
Source: ransomware_summary.txt + per-machine Ransomware/ CSVs (Phase 12)
Three sub-sections — only include rows that exist in the output files.
If ransom_notes count = 0 across all machines, omit sub-section B.
If suspicious_extensions count = 0, omit sub-section C.
-->

### A. Archive Files (Exfiltration Staging)

<!--
Source: <MACHINE>/Ransomware/<MACHINE>_<DRIVE>_archives.csv
Flag archives in unusual paths (Temp, AppData, ProgramData, Desktop, user home)
or with anomalous timestamps (created during incident window).
-->

| Machine | Path | Filename | Extension | Size | Created (UTC) | Modified (UTC) |
|---------|------|----------|-----------|------|--------------|----------------|
| | | | | | | |

### B. Ransom Note Candidates

<!--
Source: <MACHINE>/Ransomware/<MACHINE>_<DRIVE>_ransom_notes.csv
List all hits. Even one ransom note is HIGH severity.
Note the directory — ransom notes dropped in every folder indicate full encryption.
-->

| Machine | Path | Filename | Size | Created (UTC) |
|---------|------|----------|------|--------------|
| | | | | |

### C. Suspicious / Encrypted File Extensions

<!--
Source: <MACHINE>/Ransomware/<MACHINE>_<DRIVE>_suspicious_extensions.csv
KNOWN_RANSOMWARE_EXT = confirmed ransomware family extension (HIGH)
BULK_UNKNOWN = ≥20 files with an extension not in the known-benign list (MEDIUM)
Note first/last modified timestamps — a tight window indicates mass encryption event.
-->

| Machine | Extension | Count | Assessment | First Modified (UTC) | Last Modified (UTC) |
|---------|-----------|-------|-----------|---------------------|---------------------|
| | | | | | |

### D. Encryption Timing Estimate

<!--
This sub-section is an LLM-derived analytical finding — it is NOT a direct script output.

Two timestamps must be clearly distinguished:

  "First ransom note observed"   — scripted, from ransomware_summary.txt "First indicator" line.
                                   Reliable: scatter pattern (same filename in 3+ directories).

  "Estimated encryption start"   — derived here by the LLM from suspicious_extensions.csv.
                                   Methodology:
                                     1. Read all BULK_UNKNOWN rows from every machine's
                                        *_suspicious_extensions.csv.
                                     2. Filter to rows where first_modified is within the incident
                                        window (i.e., within ~24 h before the ransom note timestamp).
                                     3. The earliest such first_modified is the estimated start.
                                     4. If the earliest BULK_UNKNOWN first_modified is months before
                                        the note drop, it likely represents pre-existing unknown files,
                                        not encrypted data — state the estimate cannot be isolated and
                                        fall back to the ransom note timestamp as the lower bound.

Always qualify: write "estimated" — do not state it as a confirmed fact.
The gap between encryption start and note drop indicates encryptor speed
(seconds–minutes = fast bulk encryptor; hours = slow/targeted).

Omit this sub-section entirely if Phase 12 did not run.
-->

| | |
|---|---|
| **First ransom note observed** | <!-- from ransomware_summary.txt --> UTC on <!-- machine --> |
| **Estimated encryption start** | <!-- earliest BULK_UNKNOWN first_modified within incident window --> UTC on <!-- machine --> |
| **Note drop lag** | <!-- gap between the two timestamps --> |
| **Basis** | <!-- cite specific extension(s) and file count that anchor the estimate --> |

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- CONDITIONAL: include if memory dump present under  -->
<!--             case root                              -->
<!-- ═══════════════════════════════════════════════════ -->

## 10. Memory Analysis

<!--
Source: Volatility 3 / Memory Baseliner output (if run)
If memory was NOT analysed: write "[WORKFLOW GAP: memory dump present but not yet analysed — 
run memory-analysis skill]" and leave section stub.
Note: process list, network connections, injected code, credentials in memory.
-->

[WORKFLOW GAP: memory dump present but not yet analysed — run memory-analysis skill]

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- CONDITIONAL: include if Browser/ CSVs exist        -->
<!--             with data                              -->
<!-- ═══════════════════════════════════════════════════ -->

## 11. Browser & User Behaviour

<!--
Source: per-machine Browser/ CSVs
Highlight: downloads, searches, external domains visited, MotW/Zone.Identifier hits
Flag any searches that are inconsistent with the user's role (e.g. attacker research, exfil tooling)
-->

| Time (UTC) | Machine | User | Activity | Detail | Source |
|------------|---------|------|----------|--------|--------|
| | | | | | |

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- MANDATORY                                          -->
<!-- ═══════════════════════════════════════════════════ -->

## 12. Indicators of Compromise

<!--
Source: ioc_summary.txt, ioc_master.csv, per-machine CSVs
Only list IOCs that appear in workflow output. Do not add IOCs from memory or external sources.
Remove any IOC that is clearly benign infrastructure (Windows Update, Microsoft CDN, etc.) 
unless it appears in an anomalous context.
-->

### External IPs

| IP | Occurrences | Machines | Assessment |
|----|-------------|----------|-----------|
| | | | |

### Hashes

| Type | Hash | Occurrences | Machines |
|------|------|-------------|----------|
| | | | |

### Domains

| Domain | Occurrences | Machines | Assessment |
|--------|-------------|----------|-----------|
| | | | |

### Accounts of Interest

| Account | Domain | Observed Activity |
|---------|--------|------------------|
| | | |

### Persistence Artefacts

| Type | Name / Path | Machine | Created (UTC) |
|------|------------|---------|--------------|
| | | | |

### Files of Interest

| Path | Size | Action | Time (UTC) | Machine |
|------|------|--------|-----------|---------|
| | | | | |

### LOLBIN Downloads

<!--
Source: <MACHINE>/WebServer/lolbin_downloads.csv (Phase 13)
Include only if Phase 13 ran. Lists files pulled from attacker-controlled infrastructure
via living-off-the-land binaries (certutil, bitsadmin, powershell, curl, etc.).
-->

| Time (UTC) | Machine | LOLBIN | Source URL | Destination Path |
|------------|---------|--------|-----------|-----------------|
| | | | | |

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- MANDATORY                                          -->
<!-- ═══════════════════════════════════════════════════ -->

## 13. Conclusions

<!--
3–6 bullet points. Each must be directly supported by at least one artefact cited above.
Do not introduce new facts here. Do not make attribution statements beyond what the evidence supports.
Format: bold claim → supporting evidence reference.
-->

1. **{{Claim}}** — supported by {{artefact reference}}.

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- MANDATORY                                          -->
<!-- ═══════════════════════════════════════════════════ -->

## 14. Recommended Next Steps

<!--
Actionable items only. Each item should be specific (name the tool, file, or account).
Format as a checklist. Group into: Immediate (hours), Short-term (days), Ongoing.
-->

### Immediate
- [ ] 

### Short-term
- [ ] 

### Ongoing
- [ ] 

---

<!-- ═══════════════════════════════════════════════════ -->
<!-- CONDITIONAL: include if any phase output is        -->
<!--             missing                                -->
<!-- ═══════════════════════════════════════════════════ -->

## 15. Workflow Coverage

<!--
List any phases that did not run or produced no output.
Explain what forensic questions remain unanswered as a result.
-->

| Phase | Script | Status | Impact on Report |
|-------|--------|--------|-----------------|
| | | NOT RUN | |

---

*All timestamps UTC. All findings sourced from workflow output under `{{ANALYSIS_ROOT}}`. No conclusions extend beyond the artefact record.*
