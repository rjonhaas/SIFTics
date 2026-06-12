---
name: anti-forensics-detection
description: Detecting, documenting, and attributing anti-forensics activity — log clearing, timestomping, secure deletion, evidence destruction
---

# Anti-Forensics Detection

Anti-forensics is any deliberate action to hinder, delay, or prevent forensic
investigation. Detecting it serves two purposes: recovering what evidence remains
despite the attempt, and documenting the attempt itself as evidence of consciousness
of guilt. A sophisticated attacker who clears logs has demonstrated intent — that
is independently significant for prosecution regardless of whether the underlying
activity is recoverable.

---

## Log clearing

### Windows Event Log clearing

Run `EvtxECmd` (or `evtx_dump`) over `Security.evtx` and `System.evtx`, then read
the output for evidence of clearing. The events below are starting points for
that reading — not pattern-match endpoints.

| EID | Log | Meaning |
|---|---|---|
| 1102 | Security | Security audit log cleared — includes SubjectUserName (who cleared it) |
| 104 | System | System log cleared |

A 1102/104 event is one strong signal, but absence of those events does not mean
no clearing happened. After parsing the EVTX, evaluate the log holistically:
- Does the RecordID sequence have unexplained jumps or a reset to 1?
- Is there an EID 4608 (audit system starting) immediately after a gap, consistent
  with a service restart following a clear?
- Is the first event timestamp later than expected given the system's install date
  and uptime history?
- Does the log's filesystem `mtime` agree with its last-record timestamp?

Read each of those signals against what you know about the host from baseline.
Sophisticated clearing tools that also remove the 1102 event leave only the
secondary signs — that pattern (clearing-with-no-1102) is itself a finding
about attacker capability and intent, but draw that conclusion from the
combined evidence rather than from any single field value.

**System time changes (EID 4616):**
If parsing turns up time-change events, evaluate each one in context. Who made
the change? Was it a routine NTP sync, a known maintenance action, or a rollback
during the suspected attack window? A backwards jump correlated with the incident
window is consistent with timeline tampering; assess the account, magnitude, and
timing before concluding. After any unexplained rollback, treat downstream
timestamps as suspect until a forward correction restores trust.

### Linux log clearing

Walk the standard log directories and read each log against what you know about
the host's normal activity rhythm. The commands below collect the data; the
analysis is reading that data with judgement.

```bash
# Inventory the relevant logs and their sizes
ls -la /var/log/auth.log /var/log/syslog /var/log/apache2/access.log

# Sample first/last entries to see the time range each log actually covers
awk '{print $1,$2,$3}' /var/log/auth.log | head -5
awk '{print $1,$2,$3}' /var/log/auth.log | tail -5

# Inode metadata — ctime, mtime, size
stat /var/log/auth.log
```

For each log, compare its filesystem metadata against its content. A file with
recent `ctime` but stale internal timestamps is consistent with truncation or
replacement; a file whose first entry is much later than the system's uptime
or the surrounding logs' coverage is consistent with deletion-and-recreation.
Neither pattern is conclusive on its own — combine with rotation policy,
the host's logging configuration, and any related authentication evidence.

---

## Timestomping (T1070.006)

Covered in detail in `timeline-reconstruction.md`.

### Scope — three classes of files to check (all three, not just one)

The most common real-world miss is scoping timestomping detection to the
implant binary only. CTF and training examples timestomp the malware; real
attackers timestomp **the data they stole** to hide *when* it was staged.
Always check all three of these:

1. **Implant binaries** — the canonical case. For each malware binary already
   on the Affected Systems Register, compare `$SI` to:
   - EVTX 7045 service-install time, if the binary registered a service
   - EVTX 4688 first-execution time
   - WMI `Win32_Process` creation time (memory)
   - Volatility `windows.timeliner` for the loaded module

2. **User-data files in attacker-accessed directories.** For every ASR row
   whose `notes` field mentions the attacker accessed a directory
   (`\FileShare\Secret\`, `\Administrator\Documents\`, exfil staging dirs,
   crown-jewel paths), run `analyzeMFT --fnmismatch` or equivalent across
   **every file in that directory**. A timestomped data file means the
   attacker is hiding *when* they staged the exfil archive — extremely
   high-value finding for both the timeline and the intent narrative.

   Trigger: any `finding_record()` whose `claim` contains
   "accessed", "exfiltrated", "staged", "exfil", or "crown-jewel".

3. **Log files themselves.** Windows event logs (`Security.evtx`,
   `System.evtx`, `Application.evtx`) and Linux `wtmp`/`btmp`/`auth.log` can
   be timestomped to hide gaps. Run `$SI` vs `$FN` on the log files, and
   compare each log's "last record timestamp" to its filesystem `mtime`.

If any of these three was not in scope of your anti-forensics phase, the
phase is incomplete — record an explicit "scope: implant-binaries only"
note in the briefing so a reviewer knows what was and wasn't covered.

### Key indicators

- `$SI` timestamps predate `$FN` timestamps for the same file
- `$SI` timestamps set to exactly midnight or another round time
- `$SI` timestamps earlier than OS install date
- PE compile time is later than MFT Created timestamp
- A file's `$FN` create time is later than the FS-level `mtime` of its
  containing directory's `$INDEX_ALLOCATION` entry (only possible if
  the file was created earlier and stomped, or if the directory's index
  was also tampered)

**Document as evidence of intent:** Timestomping requires deliberate tool use
(Metasploit's `timestomp` command, PowerShell, or custom tools). It is not an
accidental artifact. Finding timestomped files demonstrates the attacker took
active steps to conceal their activity.

**Anchor the negative case too:** If you ran the three-scope check and found
no timestomping, write the negative finding explicitly — naming every
directory and file class you checked — so a downstream reviewer can confirm
the scope. "No timestomping observed" without scope is a sin of omission
that reads as "didn't check the right things."

---

## Secure deletion tools

These tools attempt to overwrite file content before deletion to prevent recovery.
Detecting their use is important even if the underlying files cannot be recovered.

### Windows secure deletion tools

| Tool | Registry artifacts | Prefetch | Notes |
|---|---|---|---|
| Eraser | `HKCU\Software\Eraser` or `HKLM\Software\Heidi Computers\Eraser` | `ERASER.EXE-*.pf` | Task scheduler entries may persist; installer package in Downloads |
| CCleaner | `HKCU\Software\Piriform\CCleaner` | `CCLEANER.EXE-*.pf`, `CCLEANER64.EXE-*.pf` | Registry key survives uninstall; last run settings visible |
| SDelete (Sysinternals) | Registry EULA key: `HKCU\Software\Sysinternals\SDelete` | `SDELETE.EXE-*.pf` | Leaves `SDELETE.EXE-*.pf` even after tool is deleted |
| `cipher /w` (Windows built-in) | None | None | No artifact — deduce from command history |
| DBAN / Darik's Boot and Nuke | N/A (wipes entire drive) | N/A | Used to wipe machines before disposal |

**Where to look — sources to pull and read:**
1. Prefetch parsed by `PECmd`; review every entry, not just those whose
   names match a known tool — attackers rename payloads.
2. Registry hives parsed by `RECmd`; many secure-deletion tools leave keys
   that persist past uninstall, and those keys carry execution history.
3. The user's Downloads, Temp, and AppData paths; installer packages and
   tool-specific support files (e.g. Eraser's task list at
   `%AppData%\Eraser 6\Task List.ersx`) survive even if the binary doesn't.
4. The MFT and `$UsnJrnl`; install-then-uninstall sequences leave a
   distinctive creation/deletion pattern that is recoverable even when
   the tool is gone.

**Impact assessment:** Even if the target files were successfully wiped, the
fact that secure deletion was run during the incident window is
independently significant. For each confirmed execution, record the tool,
the execution time, the account, and the correlation with the wider
attacker timeline — that correlation is what supports the intent finding.

### Linux secure deletion

```bash
shred, wipe, srm        # leave no artifacts themselves
# Detect by: bash_history, auth.log (if sudo), audit.log (if auditd was running)
find / -name "shred" -o -name "wipe" -o -name "srm" 2>/dev/null  # tool presence
```

---

## WEVTUTIL and log manipulation

`wevtutil.exe cl <logname>` is the built-in Windows command to clear event logs,
which makes it a natural focus when investigating log tampering. To assess
whether it was used:

- Run `PECmd` over the Prefetch directory and read every entry; for any wevtutil
  prefetch, evaluate the last-run timestamp, run count, and resolved file paths
  against the incident timeline and what the host's administrators would have
  legitimate reason to do.
- Run Volatility's `windows.cmdscan` / `windows.consoles` over any available
  memory image and read the recovered command history — interpret each command
  against its session, parent process, and user.
- Re-examine the cleared logs themselves: parse the EVTX and read the RecordID
  sequence, any 4608 audit-start events, and the timing relative to the
  suspected attacker activity.

When multiple Prefetch entries exist for the same tool with different path hashes,
that is consistent with execution from different working directories (for
example, a webshell-spawned process versus an interactive shell). Read the
resolved paths and timestamps and reason about what session each represents
rather than concluding from the entry count alone.

---

## Anti-forensics tool detection checklist

When investigating any case with confirmed attacker persistence or interactive
access, run each of these passes and read the output with judgement — the
checklist names the data sources, not the answers.

**Execution evidence:**
- [ ] Parse Prefetch with `PECmd`; review every entry for unfamiliar tools,
      tools running from unexpected paths, and execution times that align with
      the incident window.
- [ ] Parse Amcache with `AmcacheParser`; cross-check SHA1s against the
      baseline and against threat-intel sources.
- [ ] Parse UserAssist and MuiCache; evaluate each GUI execution entry against
      the user's normal activity profile.
- [ ] Run `windows.cmdscan` / `windows.consoles` over memory; read the
      reconstructed command history and reason about what each command was
      doing in its session.

**Registry evidence:**
- [ ] Run `RECmd` (Zimmermann batch) over the relevant hives; review the
      output for evidence of secure-deletion tools, log-clearing utilities,
      or other anti-forensics software — both currently installed and
      previously-installed-then-removed.

**Log integrity:**
- [ ] Parse EVTX with `EvtxECmd`; assess RecordID continuity, the presence
      or absence of clearing events, time-change events, and the relationship
      between file `mtime` and last-record timestamp.

**File system evidence:**
- [ ] Parse the MFT with `MFTECmd`; look for deleted entries consistent with
      anti-forensics tools and read each candidate's surrounding context
      (directory, parent process if known, timing).
- [ ] Parse `$UsnJrnl`; review rename/delete events around the incident window.
- [ ] Inspect Downloads, Temp, and other staging directories for installer
      packages or tool binaries that the attacker may have used.

---

## Documenting anti-forensics for prosecution

Anti-forensics activity is evidence of consciousness of guilt. Document it
with the same rigor as the underlying attack artifacts:

1. **What tool was used** — name, version if recoverable
2. **When it was executed** — timestamp from Prefetch, memory, or EVTX
3. **What account ran it** — from Prefetch path, memory, or logon events
4. **What was targeted** — log name, file path, or directory
5. **Whether the attempt succeeded** — is the target evidence recoverable or gone?
6. **Correlation to attack timeline** — does the execution time follow confirmed
   attacker activity? This is the element that connects anti-forensics to intent.

Record each confirmed anti-forensics action as a separate `finding_record()` with
`linked_itq` pointing to the ITQ-026 answer (log clearing / anti-forensics evidence).
