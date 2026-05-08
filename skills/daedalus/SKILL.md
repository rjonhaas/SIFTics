# Skill: Daedalus — Adaptive Artifact Handler

> *"He constructed wings for himself and his son, made of feathers and wax."*
> Daedalus doesn't wait to be given tools. It builds the ones that are missing.

---

## Purpose

Daedalus is the evidence-adaptive layer that sits between raw artifact discovery and script
execution. Every case contains artifact types that weren't anticipated when the standard
SIFTics phases were written. Daedalus finds those gaps and closes them — either by routing
to an existing handler or by writing a new one on the spot.

It solves three problems simultaneously:

1. **Determinism**: don't run web server analysis when there is no web server; don't skip
   email analysis when a PST is sitting in the evidence. Run exactly what the evidence
   warrants, nothing more.

2. **Domain extension**: when the evidence contains a log or artifact that belongs to an
   existing phase's domain but isn't listed in its `HANDLES` header (an HFS log alongside
   IIS logs, a Tomcat log on a Java server, a custom nginx path), Daedalus adds a new
   section to the existing script rather than creating a redundant one. The handler grows
   to cover the variant; the taxonomy self-updates.

3. **Gap creation**: when the evidence contains an artifact type with no handler and no
   related domain (a SRUM database, a Docker layer tarball, an AWS CloudTrail corpus),
   Daedalus generates a brand-new SIFTics-compatible phase script on the spot, validates
   it, and integrates it into the run plan.

---

## When to Invoke

Invoked by the **Investigation Section Chief skill** after Phase 0 (evidence inventory, hashing,
temporal mapping) and **before** any analysis scripts run. The ISC passes the case root path
and the mounted evidence path; Daedalus returns a validated run plan.

Also invoke Daedalus:
- When adding a new evidence source mid-investigation (new USB image, second machine)
- When a standard phase produces zero results and you suspect the evidence contains a
  non-standard variant of that artifact type (e.g., a non-IIS web server log)
- When the analyst says "there's something here I don't have a script for"

**Daedalus never executes analysis scripts directly.** It produces a run plan; the ISC then
sequences the indicated phases via the `triage-methodology` skill, which invokes the
individual `run_*.sh` scripts.

---

## Artifact Taxonomy

This is the complete registry of artifact classes Daedalus knows about. Each row defines:
- **Class**: the canonical artifact identifier used throughout this skill
- **Detection**: the shell probe that determines presence (run from the mounted evidence root)
- **SIFT Tools**: tools available on the SIFT workstation that handle this artifact
- **Known Handler**: the SIFTics script that already covers this class (if any)

When `Known Handler` is `—`, a gap exists and Phase D4 applies.

### Windows Filesystem & System

| Class | Detection probe | SIFT Tools | Known Handler |
|-------|----------------|-----------|---------------|
| `win_evtx` | `find $MNT -path "*/winevt/Logs/*.evtx" \| head -1` | EvtxECmd | `run_eventlogs.sh` |
| `win_registry` | `find $MNT -path "*/System32/config/SYSTEM" \| head -1` | RECmd, hivexsh | `run_registry.sh` |
| `win_mft` | `find $MNT -name '$MFT' \| head -1` | MFTECmd | `run_ntfs.sh` |
| `win_prefetch` | `find $MNT -path "*/Windows/Prefetch/*.pf" \| head -1` | PECmd | `run_artifacts.sh` |
| `win_lnk` | `find $MNT -name "*.lnk" -path "*/Recent/*" \| head -1` | LECmd | `run_artifacts.sh` |
| `win_jumplist` | `find $MNT -path "*/AutomaticDestinations/*.automaticDestinations-ms" \| head -1` | JLECmd | `run_artifacts.sh` |
| `win_shellbags` | `find $MNT -name "UsrClass.dat" \| head -1` | SBECmd | `run_registry.sh` |
| `win_recyclebin` | `find $MNT -path "*RECYCLE.BIN*" -name "\$I*" \| head -1` | RBCmd | `run_artifacts.sh` |
| `win_sched_tasks` | `find $MNT -path "*/System32/Tasks/*" ! -type d \| head -1` | dotnet TaskScheduler libs | `run_execution.sh` |
| `win_ps_history` | `find $MNT -name "ConsoleHost_history.txt" \| head -1` | cat / Python | `run_execution.sh` |
| `win_wmi_repo` | `find $MNT -name "OBJECTS.DATA" -path "*/wbem/*" \| head -1` | python-cim, strings | — |
| `win_srum` | `find $MNT -name "SRUDB.dat" \| head -1` | srum-dump, ese2csv | — |
| `win_ntds` | `find $MNT -name "ntds.dit" \| head -1` | impacket secretsdump, ntdsextract | — |
| `win_thumbcache` | `find $MNT -name "thumbcache_*.db" \| head -1` | thumbcache_viewer (CLI) | — |
| `win_bam_dam` | `find $MNT -path "*/SYSTEM" \| xargs strings 2>/dev/null \| grep -q BAM && echo found` | RECmd / hivexsh | — |
| `win_amcache` | `find $MNT -name "Amcache.hve" \| head -1` | AmcacheParser | `run_registry.sh` |
| `win_shimcache` | `find $MNT -path "*/System32/config/SYSTEM" \| head -1` | AppCompatCacheParser | `run_registry.sh` |
| `win_userassist` | `find $MNT -name "NTUSER.DAT" \| head -1` | RECmd | `run_registry.sh` |

### Browser & User Activity

| Class | Detection probe | SIFT Tools | Known Handler |
|-------|----------------|-----------|---------------|
| `browser_chrome` | `find $MNT -path "*/Google/Chrome/User Data/*/History" \| head -1` | dotnet BrowserHistoryAnalyzer, sqlite3 | `run_browser.sh` |
| `browser_edge` | `find $MNT -path "*/Microsoft/Edge/User Data/*/History" \| head -1` | dotnet BrowserHistoryAnalyzer, sqlite3 | `run_browser.sh` |
| `browser_firefox` | `find $MNT -path "*/Firefox/Profiles/*/places.sqlite" \| head -1` | sqlite3, dumpzilla | `run_browser.sh` |
| `browser_ie_legacy` | `find $MNT -name "WebCacheV01.dat" \| head -1` | ESEDatabaseView (CLI) | `run_browser.sh` |
| `browser_downloads` | *(derived from browser_chrome / browser_edge)* | — | `run_browser.sh` |

### Email & Messaging

| Class | Detection probe | SIFT Tools | Known Handler |
|-------|----------------|-----------|---------------|
| `email_ost` | `find $MNT -name "*.ost" \| head -1` | readpst, libpst | `run_email.sh` |
| `email_pst` | `find $MNT -name "*.pst" \| head -1` | readpst, libpst | `run_email.sh` |
| `email_mbox` | `find $MNT -name "*.mbox" -o -name "*.mbx" \| head -1` | Python mailbox | `run_email.sh` |
| `email_eml` | `find $MNT -name "*.eml" \| head -1` | Python email.message | — |
| `email_thunderbird` | `find $MNT -path "*/Thunderbird/Profiles/*" -name "*.msf" \| head -1` | sqlite3, Python mailbox | — |
| `slack_workspace` | `find $MNT -path "*/Slack/storage/*.db" \| head -1` | sqlite3 | — |
| `teams_db` | `find $MNT -path "*/Microsoft/Teams/databases/*.db" \| head -1` | sqlite3 | — |

### Web & Application Server Logs

| Class | Detection probe | SIFT Tools | Known Handler |
|-------|----------------|-----------|---------------|
| `log_iis` | `find $MNT -path "*/LogFiles/W3SVC*/*.log" \| head -1` | Python / grep / awk | `run_webserver.sh` |
| `log_apache` | `find $MNT \( -name "access.log" -o -name "access_log" \) -path "*/apache*" \| head -1` | Python / grep | `run_webserver.sh` |
| `log_nginx` | `find $MNT \( -name "access.log" -o -name "access_log" \) -path "*/nginx*" \| head -1` | Python / grep | `run_webserver.sh` |
| `log_hfs` | `find $MNT -name "*.log" -path "*hfs*" \| head -1` | strings + Python | — |
| `log_tomcat` | `find $MNT -name "localhost_access_log*.txt" \| head -1` | Python | — |
| `log_iis_httperr` | `find $MNT -path "*/HTTPERR/*.log" \| head -1` | Python / grep | `run_webserver.sh` |

### Linux & Unix

| Class | Detection probe | SIFT Tools | Known Handler |
|-------|----------------|-----------|---------------|
| `linux_ext_partition` | `mmls "$IMAGE" 2>/dev/null \| grep -iE "Linux\|0x83\| 83 " \| head -1` | mount, losetup, find | `run_linux.sh` |
| `linux_lvm` | `mmls "$IMAGE" 2>/dev/null \| grep -iE "LVM\|0x8e\| 8e " \| head -1` | vgscan, lvscan, mount | — |
| `linux_bash_history` | `find $MNT_LINUX -name ".bash_history" \| head -1` | cat / Python | `run_linux.sh` |
| `linux_auth_log` | `find $MNT_LINUX -name "auth.log" -o -name "secure" \| head -1` | Python / grep | `run_linux.sh` |
| `linux_cron` | `find $MNT_LINUX -path "*/cron*" -type f \| head -1` | cat / Python | `run_linux.sh` |
| `linux_systemd_journal` | `find $MNT_LINUX -name "*.journal" -path "*/systemd/journal/*" \| head -1` | journalctl --file | — |
| `linux_docker_layers` | `find $MNT_LINUX -path "*/docker/overlay2/*/diff" -type d \| head -1` | find, strings, sha256sum | — |
| `linux_ssh_keys` | `find $MNT_LINUX -name "authorized_keys" -o -name "id_rsa" \| head -1` | cat, strings | `run_linux.sh` |

### Memory

| Class | Detection probe | SIFT Tools | Known Handler |
|-------|----------------|-----------|---------------|
| `memory_raw` | `find "$CASE_ROOT" -name "*.mem" -o -name "*.raw" -o -name "*.vmem" \| head -1` | Volatility 3, Memory Baseliner, YARA | `run_memory.sh` (Phase 19) |
| `memory_dump` | `find "$CASE_ROOT" -name "*.dmp" \| head -1` | Volatility 3 | `run_memory.sh` (Phase 19) |
| `memory_hibernation` | `find $MNT -name "hiberfil.sys" \| head -1` | Volatility 3 hibr2bin | — |
| `memory_pagefile` | `find $MNT -name "pagefile.sys" \| head -1` | strings, bulk_extractor | — |

### Network

| Class | Detection probe | SIFT Tools | Known Handler |
|-------|----------------|-----------|---------------|
| `pcap` | `find "$CASE_ROOT" -name "*.pcap" -o -name "*.pcapng" \| head -1` | tshark, zeek, tcpdump | `run_pcap.sh` (Phase 20) |
| `zeek_logs` | `find "$CASE_ROOT" -name "conn.log" -path "*/zeek*" \| head -1` | Python, grep, jq | `run_pcap.sh` (Phase 20, Section N6) |
| `netflow_nfcapd` | `find "$CASE_ROOT" -name "nfcapd.*" \| head -1` | nfdump | — |

### Database & Specialized

| Class | Detection probe | SIFT Tools | Known Handler |
|-------|----------------|-----------|---------------|
| `sqlite_generic` | `find $MNT -name "*.sqlite" -o -name "*.sqlite3" \| head -1` | sqlite3, Python sqlite3 | — |
| `ese_database` | `find $MNT -name "*.edb" -o -name "*.dit" \| head -1` | libesedb, ese2csv | — |
| `chrome_leveldb` | `find $MNT -path "*/LevelDB/MANIFEST-*" \| head -1` | leveldb Python bindings | — |

### Cloud & EDR Collections

| Class | Detection probe | SIFT Tools | Known Handler |
|-------|----------------|-----------|---------------|
| `aws_cloudtrail` | `find "$CASE_ROOT" -name "*.json.gz" -path "*cloudtrail*" -o -name "*.json" -path "*cloudtrail*" \| head -1` | Python, jq | *(cloud-forensics skill)* |
| `aws_guardduty` | `find "$CASE_ROOT" -name "*.json" -path "*guardduty*" \| head -1` | Python, jq | *(cloud-forensics skill)* |
| `velociraptor_zip` | `find "$CASE_ROOT" -name "*.zip" \| xargs -I{} unzip -l {} 2>/dev/null \| grep -q "Windows.KapeFiles" && echo found` | *(edr-telemetry skill)* | *(edr-telemetry skill)* |

---

## Domain Taxonomy

Every artifact class belongs to exactly one domain. Domains are the mechanism for
**Phase D3.5 (Extend vs Create)**: if a gap artifact's domain matches an existing script's
`DAEDALUS:DOMAIN`, Daedalus extends that script rather than creating a new one.

| Domain | Description | Owning Script(s) | Member Artifact Classes |
|--------|-------------|-----------------|------------------------|
| `web_server_logs` | HTTP server access, error, and application logs — any format | `run_webserver.sh` | `log_iis`, `log_apache`, `log_nginx`, `log_iis_httperr`, `log_hfs`, `log_tomcat` + any newly discovered HTTP log format |
| `windows_event_logs` | Windows EVTX logs from any channel | `run_eventlogs.sh` | `win_evtx` + any `*.evtx` from non-standard channels |
| `windows_registry` | Registry hives and artifacts derived from them | `run_registry.sh` | `win_registry`, `win_shimcache`, `win_amcache`, `win_userassist`, `win_shellbags` |
| `windows_filesystem` | NTFS metadata and MFT artifacts | `run_ntfs.sh`, `run_mftecmd.sh` | `win_mft` |
| `windows_artifacts` | User-activity artifacts stored as discrete files | `run_artifacts.sh` | `win_lnk`, `win_jumplist`, `win_prefetch`, `win_recyclebin`, `win_thumbcache` |
| `windows_execution` | Evidence of program execution | `run_execution.sh` | `win_sched_tasks`, `win_ps_history`, `win_bam_dam` |
| `windows_credential_access` | Credential access and privilege escalation indicators | `run_credaccess.sh` | `win_wmi_repo`, `win_ntds`, `win_srum` |
| `windows_anti_forensics` | Evidence destruction, log clearing, timestomping | `run_antiforensics.sh` | *(derived from event logs and registry)* |
| `windows_hunting` | Lateral movement, privilege escalation, remote execution | `run_hunting.sh` | *(derived from event logs)* |
| `browser` | Web browser history, downloads, and cached data | `run_browser.sh` | `browser_chrome`, `browser_edge`, `browser_firefox`, `browser_ie_legacy` |
| `email` | Email client archives and message stores — any format | `run_email.sh` | `email_ost`, `email_pst`, `email_mbox`, `email_eml`, `email_thunderbird` |
| `messaging` | Non-email communication platforms | *(gap — no script yet)* | `slack_workspace`, `teams_db` |
| `linux_host` | Linux host artifacts — filesystem, logs, history, cron | `run_linux.sh` | `linux_ext_partition`, `linux_bash_history`, `linux_auth_log`, `linux_cron`, `linux_ssh_keys`, `linux_systemd_journal`, `linux_docker_layers` |
| `memory_forensics` | Volatile memory captures | `run_memory.sh` (Phase 19) | `memory_raw`, `memory_dump`, `memory_hibernation`, `memory_pagefile` |
| `network_captures` | Packet captures and flow records | `run_pcap.sh` (Phase 20) | `pcap`, `zeek_logs`, `netflow_nfcapd` |
| `cross_artifact_anomaly` | Synthesizes contradictions across all prior phase outputs | `run_anomaly_check.sh` (Phase 18) | *(meta — depends on Phase 1–13 + 19 + 20 outputs)* |
| `velociraptor_offline_collection` | Velociraptor offline collector zips and live-agent triage retrieval | `mcp_broker/tools/velociraptor.py` (typed-function gateway) + `scripts/run_detect_hunt_loop.sh` (orchestrator) | `velociraptor_zip` |
| `ransomware` | Ransomware indicators — notes, extensions, staging | `run_ransomware.sh` | *(derived from MFT and event logs)* |
| `c2_beacon` | Command-and-control beacon detection | `run_c2_beacon.sh` | `log_iis` *(beacon patterns in web logs)* |
| `ioc_aggregation` | Cross-phase IOC consolidation | `run_ioc_extract.sh` | *(meta — no direct evidence dependency)* |
| `cloud_telemetry` | Cloud provider logs and telemetry | *(cloud-forensics skill)* | `aws_cloudtrail`, `aws_guardduty` |
| `edr_collection` | EDR and live-triage collection archives | *(edr-telemetry skill)* | `velociraptor_zip` |

### Domain Classification for Unknown Artifacts

When Daedalus encounters a new artifact not in the taxonomy, classify it by answering
these questions in order:

1. **Is it a log produced by a server or service that handles HTTP requests?**
   → domain `web_server_logs`
2. **Is it a Windows binary event log (`.evtx`)?**
   → domain `windows_event_logs`
3. **Is it a registry hive or a file whose primary forensic value comes from the registry?**
   → domain `windows_registry`
4. **Is it evidence of what programs ran, when, or from where?**
   → domain `windows_execution`
5. **Is it a file associated with a user's browsing activity in a web browser?**
   → domain `browser`
6. **Is it an email archive, message store, or export file?**
   → domain `email`
7. **Is it a real-time messaging platform database or export?**
   → domain `messaging`
8. **Is it from a Linux/Unix host's filesystem, log directory, or shell?**
   → domain `linux_host`
9. **None of the above** → create a new domain name (`snake_case`, descriptive) and a new
   script. Document the new domain in this table.

---

## Phase D0 — Initialization

```bash
CASE_ROOT="$1"
MNT_POINT="${2:-}"          # mounted disk image root, e.g. /mnt/evidence
IMAGE_PATH="${3:-}"         # raw/EWF image path for partition probing
MANIFEST="${CASE_ROOT}/analysis/daedalus_manifest.txt"
RUN_PLAN="${CASE_ROOT}/analysis/daedalus_run_plan.txt"
SCRIPTS_DIR="$HOME/projects/SIFTics/scripts"
mkdir -p "${CASE_ROOT}/analysis"
```

If `MNT_POINT` is not provided, check `$CASE_ROOT/analysis/cop.md` for the last-used mount
path. If `IMAGE_PATH` is not provided, search for `.E01`, `.raw`, `.vmem` files at the case
root.

---

## Phase D1 — Artifact Fingerprinting

Run the companion script:

```bash
bash "$SCRIPTS_DIR/daedalus_fingerprint.sh" "$CASE_ROOT" "$MNT_POINT" "$IMAGE_PATH" \
  | tee "$MANIFEST"
```

The fingerprint script probes every artifact class in the taxonomy and writes one line per
class to stdout:

```
PRESENT  win_evtx          142 files   /mnt/evidence/Windows/System32/winevt/Logs
PRESENT  email_ost          1 file     /mnt/evidence/Users/Karen/AppData/Local/.../klovespizza@outlook.com.ost
ABSENT   log_iis            —
ABSENT   log_apache         —
PRESENT  linux_ext_partition 1 partition offset=38687211520
```

Read the manifest. Extract all `PRESENT` lines into a working list: `PRESENT_CLASSES`.

---

## Phase D2 — Handler Discovery

For every script in `$SCRIPTS_DIR/run_*.sh`:

1. Check for a `# DAEDALUS:HANDLES` header:
   ```bash
   grep "^# DAEDALUS:HANDLES" "$script" | sed 's/.*HANDLES //'
   ```
   This returns a space-separated list of artifact classes that script covers.

2. **Fallback for scripts without the header**: use the Known Handler column from the
   Artifact Taxonomy table above. This fallback is read-only — Daedalus never modifies
   existing scripts to add headers unless explicitly asked.

Build a map: `HANDLER_MAP[artifact_class] → script_path`.

---

## Phase D3 — Gap Analysis

```
GAPS = PRESENT_CLASSES - keys(HANDLER_MAP)
```

For each class in `GAPS`, record:
- The artifact class name
- Sample file paths from the manifest (up to 3 paths)
- File count and total size if available

Print the gap report:

```
[DAEDALUS] Gap analysis complete.
  Handled (run these): run_eventlogs.sh  run_registry.sh  run_browser.sh  run_email.sh ...
  GAPS (no handler):   win_wmi_repo  linux_systemd_journal  ...
```

If `GAPS` is empty: skip D3.5 and D4, proceed directly to Phase D5.

If `GAPS` is non-empty: **proceed to Phase D3.5 for each gap, one at a time.**

---

## Phase D3.5 — Extend vs Create Decision

For each artifact class in `GAPS`, decide whether to **extend an existing script** or
**create a new one** before any code is written.

### Step 3.5.1 — Classify the gap artifact's domain

Using the Domain Taxonomy table and the classification questions above, assign a domain
to the unhandled artifact class. Record it:

```
Gap artifact  : log_hfs
Assigned domain: web_server_logs
Evidence      : find $MNT -iname "hfs.exe" returned /mnt/evidence/Users/Bob/hfs.exe
                find $MNT -name "*.log" -path "*hfs*" returned /mnt/evidence/Users/Bob/hfs.log
```

### Step 3.5.2 — Check for a domain-owning script

```bash
grep -rl "^# DAEDALUS:DOMAIN web_server_logs" "$SCRIPTS_DIR/run_*.sh"
```

If a script is returned → **EXTEND** (Step 3.5.3).
If no script is returned → **CREATE** (Phase D4), and assign the new domain in the
`DAEDALUS:DOMAIN` header of the generated script.

### Step 3.5.3 — Extend the owning script

Read the owning script in full. Understand its section structure (comments like
`# ─── Section X: <label> ────`). Then:

**a. Characterise the new log format**

Examine sample lines from the artifact files. Determine:
- Is it combined log format (Apache/nginx)? → the existing parser likely handles it
  with a path tweak
- Is it W3C/IIS format? → existing IIS parser handles it
- Is it a proprietary format? → new parser needed

**b. Write the new section**

Generate a bash section following the owning script's style exactly:

```bash
# ─── Section X: <New Format> logs ────────────────────────────────────────────

for MNT_DIR in "$ANALYSIS_DIR"/*/; do
    MACHINE=$(basename "$MNT_DIR")
    # locate logs for this machine
    LOG_FILES=$(find "$MNT_DIR" -name "<pattern>" 2>/dev/null)
    [[ -z "$LOG_FILES" ]] && continue

    OUT_DIR="${ANALYSIS_DIR}/${MACHINE}/<PhaseFolder>"
    mkdir -p "$OUT_DIR"
    OUT_CSV="${OUT_DIR}/${MACHINE}_X_<artifact>_logs.csv"

    # parse logs → CSV
    python3 - "$LOG_FILES" "$MACHINE" "$OUT_CSV" <<'PYEOF'
# ... parser ...
PYEOF

    RC=$?
    ROW_COUNT=$(tail -n +2 "$OUT_CSV" 2>/dev/null | wc -l)
    log_cmd "$MACHINE" "<tool>" "<cmd>" "<purpose>" "$OUT_CSV" "$RC"
    echo "[Section X] $MACHINE: $ROW_COUNT records → $OUT_CSV"
done
```

**c. Insert the new section**

Append the section immediately before the final `echo "[Phase N] done"` line of the
owning script, preserving the existing structure. Never insert in the middle of an
existing section.

**d. Update the DAEDALUS:HANDLES header**

```bash
sed -i "s|^# DAEDALUS:HANDLES \(.*\)|# DAEDALUS:HANDLES \1 <new_class>|" "$owning_script"
```

**e. Validate**

```bash
bash -n "$owning_script"
```

If syntax check passes → mark the gap as `EXTENDED` in the run plan and proceed to
the next gap.

If syntax check fails → revert the insertion (restore from the pre-edit content held
in memory), document the failure under `DEFERRED` in the run plan, and move on.

### Extension Decision Boundary

Extend when:
- The new artifact is a variant of the same underlying format (different web server,
  different log path, different encoding of the same structure)
- Parsing it reuses ≥50% of the owning script's existing logic
- The new section adds ≤60 lines to the owning script

Create a new script when:
- The new artifact requires a fundamentally different tool chain
- The owning script would need architectural changes (new environment variables,
  new mount paths, new dependencies) to accommodate it
- The new artifact belongs to a domain with no owning script at all

---

## Phase D4 — Script Generation

For each artifact class in `GAPS`, execute this protocol in full before moving to the next.

### Step 4.1 — Artifact Brief

Construct a description of the artifact using this template:

```
Artifact class : <class>
What it is     : <one sentence describing the artifact and what forensic value it holds>
Sample paths   : <up to 3 paths from the manifest>
File count     : <N files, total size M MB>
Available tools: <list SIFT tools from the taxonomy table for this class>
Output goal    : <what CSV columns should the analysis produce>
```

### Step 4.2 — Load Reference Scripts

Read two existing SIFTics scripts that are structurally similar (same artifact domain:
disk, email, browser, Linux, etc.) as examples of style and convention. Use them as
templates — do not copy their analysis logic, only their structure.

### Step 4.3 — Determine Phase Number

```bash
# Find the highest phase number currently in use
NEXT_PHASE=$(grep -h "^# run_.*— Phase" $SCRIPTS_DIR/run_*.sh \
  | grep -oP 'Phase \K[0-9]+' | sort -n | tail -1)
NEXT_PHASE=$((NEXT_PHASE + 1))
```

### Step 4.4 — Generate the Script

Write a new file: `$SCRIPTS_DIR/run_<artifact_class_short>.sh`

The script **must** conform to the SIFTics Script Contract (see below). Specifically:
- First non-shebang comment line: `# DAEDALUS:HANDLES <class> [<class2> ...]`
- Second comment block: `# run_<name>.sh — Phase N: <title>`
- Uses `CASE_ROOT` / `ANALYSIS_DIR` environment variables
- Outputs CSVs to `$ANALYSIS_DIR/$MACHINE/<PhaseFolder>/`
- Appends tool invocations to `$ANALYSIS_DIR/commands.txt`
- Handles missing evidence gracefully (no-op exit 0, not exit 1)
- Prints a summary line: `[Phase N] <N> records written to <path>`

### Step 4.5 — Validate the Script

```bash
bash -n "$new_script"   # syntax check only, never execute against evidence
```

If the syntax check fails, fix the error and re-check before proceeding.

### Step 4.6 — Register in the triage-methodology skill

Add a new row to the **Phase Catalog** table in `skills/triage-methodology/SKILL.md` so the
ISC knows the new phase exists and can invoke it. Required fields:

| # | Script | Domain | Depends on | Completion signal | Cross-machine output |
|---|---|---|---|---|---|
| `${NEXT_PHASE}` | `run_<name>.sh` | `<artifact_class>` | `<phases this depends on>` | `analysis/<MACHINE>/<PhaseFolder>/*_<signal_glob>` | (if any) |

Then add a one-line **skip rule** ("Skip if no `<artifact>` present") and slot the phase
into the **Default Sequence** at the appropriate layer (Layer 1 foundation, Layer 2
domain analysis, Layer 3 consolidation, or Layer 4 synthesis).

If the phase has obvious break conditions (a finding that should reorder later phases),
add them to the matching Break Conditions section under **[ANALYST EXTEND HERE]**.

---

## SIFTics Script Contract

Every script Daedalus generates must satisfy these requirements. Read two existing scripts
before generating to internalize the pattern — do not guess at it.

```bash
#!/usr/bin/env bash
# DAEDALUS:HANDLES <artifact_class> [<artifact_class2> ...]
# run_<name>.sh — Phase N: <Title>
#
# Sections:
#   X. <section label> — <what this section does>
#
# Output : analysis/<MACHINE>/<PhaseFolder>/<MACHINE>_<DRIVE>_<artifact>_*.csv
# Logging: appends to analysis/commands.txt

set -euo pipefail

CASE_ROOT="${1:-${CASE_ROOT:-}}"
if [[ -z "$CASE_ROOT" ]]; then
    read -rp "Case root directory: " CASE_ROOT
fi
[[ -d "$CASE_ROOT" ]] || { echo "ERROR: CASE_ROOT '${CASE_ROOT}' does not exist." >&2; exit 1; }
export CASE_ROOT
ANALYSIS_DIR="${CASE_ROOT}/analysis"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")

# ─── helpers ────────────────────────────────────────────────────────────────

log_cmd() { ... }   # follow pattern from run_eventlogs.sh exactly

# ─── main loop: iterate over machines ───────────────────────────────────────

find "$ANALYSIS_DIR" -mindepth 1 -maxdepth 1 -type d | while read -r MACHINE_DIR; do
    MACHINE=$(basename "$MACHINE_DIR")
    MNT="$MACHINE_DIR/..."   # locate the artifact under the machine's mount point
    
    # Skip gracefully if artifact not present for this machine
    [[ -d "$MNT" ]] || { echo "[Phase N] $MACHINE: no <artifact> found — skip"; continue; }

    OUT_DIR="${ANALYSIS_DIR}/${MACHINE}/<PhaseFolder>"
    mkdir -p "$OUT_DIR"

    # ... analysis logic ...

    echo "[Phase N] $MACHINE: <N> records → ${OUT_DIR}/<filename>.csv"
done
```

**Column naming conventions** — follow the existing phase outputs:
- First column: `Machine`
- Timestamps: `Timestamp_UTC` or `Created_UTC` / `Modified_UTC`
- User context: `Username` or `SID`
- IOC-relevant fields: `SHA256`, `FilePath`, `CommandLine`, `SourceIP`
- Flag column at end: `IOC_Note` or `Flags`

---

## Phase D5 — Run Plan

Write `$CASE_ROOT/analysis/daedalus_run_plan.txt`:

```
# Daedalus Run Plan
# Generated: <UTC>
# Case: <case_name>

RUN      run_ntfs.sh          win_mft               (present: 1 $MFT)
RUN      run_registry.sh      win_registry          (present: 6 hives)
RUN      run_eventlogs.sh     win_evtx              (present: 142 .evtx files)
RUN      run_artifacts.sh     win_lnk,win_prefetch  (present: 847 LNK, 43 PF)
RUN      run_browser.sh       browser_chrome        (present: 1 History db)
RUN      run_email.sh         email_ost             (present: 1 .ost file)
RUN      run_linux.sh         linux_ext_partition   (present: 1 partition)
SKIP     run_webserver.sh     log_iis               (ABSENT — no IIS logs found)
SKIP     run_c2_beacon.sh     log_iis               (ABSENT — no IIS logs found)
SKIP     run_ransomware.sh    win_evtx              (optional — no ransom notes detected)
EXTENDED run_webserver.sh     log_hfs               (domain=web_server_logs — new section added for HFS log parser)
GENERATED run_wmi_triage.sh   win_wmi_repo          (new script — no domain match, gap filled by Daedalus)
```

| Prefix | Meaning |
|--------|---------|
| `RUN` | Script has an existing handler; execute as-is |
| `SKIP` | Artifact absent in evidence; skip with stated reason |
| `EXTENDED` | Owning script was modified to add a new section for the variant |
| `GENERATED` | Entirely new script written by Daedalus for an unmatched domain |
| `DEFERRED` | Extension or generation attempted but validation failed; manual review needed |

---

## Phase D6 — ISC Handoff

Update `$CASE_ROOT/analysis/cop.md`:

1. Add a **Daedalus Run** entry to the Completed Analysis Phases table:
   - Artifacts present: list all `PRESENT` classes
   - Gaps found: list all `GAPS` classes
   - Scripts generated: list new scripts with their phase numbers
   - Scripts skipped: list with reason

2. Add any generated scripts to the Common Operating Picture (COP) as INFERRED findings (the script was written
   based on artifact presence — run results will elevate to CONFIRMED or reveal nothing).

3. Return the run plan path to the ISC for execution.

---

## DAEDALUS:HANDLES Header Convention

Add this header to every SIFTics script — existing and newly generated:

```bash
# DAEDALUS:HANDLES <class1> [<class2> ...]
```

Place it as the **second line** of the script (immediately after the shebang). Use the
canonical class names from the Artifact Taxonomy table above. Multiple classes are
space-separated on a single line.

Examples from existing scripts (to be added):

```bash
# run_eventlogs.sh
# DAEDALUS:HANDLES win_evtx win_sysmon_evtx

# run_registry.sh
# DAEDALUS:HANDLES win_registry win_shimcache win_amcache win_userassist win_shellbags

# run_browser.sh
# DAEDALUS:HANDLES browser_chrome browser_edge browser_firefox browser_ie_legacy

# run_email.sh
# DAEDALUS:HANDLES email_ost email_pst email_mbox

# run_webserver.sh
# DAEDALUS:HANDLES log_iis log_apache log_nginx log_iis_httperr

# run_linux.sh
# DAEDALUS:HANDLES linux_ext_partition linux_bash_history linux_auth_log linux_cron linux_ssh_keys
```

---

## Constraints

- **Never execute scripts against evidence.** Daedalus writes and validates scripts;
  execution is the ISC's responsibility.
- **Never modify evidence files.** All probes are read-only (`find`, `grep`, `strings`,
  `mmls` with no write flags).
- **One gap at a time.** Generate, validate, and register each script fully before
  moving to the next gap. Do not batch-generate multiple scripts at once.
- **If a generated script cannot be validated**, document the failure in the COP under
  Contradictions, note what artifact it covers, and mark it `DEFERRED` in the run plan.
  Do not block the rest of the plan on a single failed generation.
- **Do not fabricate tool invocations.** Before using a tool in a generated script, verify
  it exists: `which <tool> || command -v <tool>`. If unavailable, use a Python fallback
  or document the gap.
