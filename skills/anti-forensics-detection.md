---
name: anti-forensics-detection
description: Detecting, documenting, and attributing anti-forensics activity - log clearing, timestomping, secure deletion, evidence destruction
---

# Anti-Forensics Detection

Anti-forensics is any deliberate action to hinder, delay, or prevent forensic
investigation. Detecting it serves two purposes: recovering what evidence remains
despite the attempt, and documenting the attempt itself as evidence of consciousness
of guilt. A sophisticated attacker who clears logs has demonstrated intent - that
is independently significant for prosecution regardless of whether the underlying
activity is recoverable.

---

## Log clearing

### Windows Event Log clearing

**Primary indicator: EID 1102 and EID 104**

| EID | Log | Meaning |
|---|---|---|
| 1102 | Security | Security audit log cleared - includes SubjectUserName (who cleared it) |
| 104 | System | System log cleared |

If EID 1102 is absent but the Security log appears to have been cleared, check for:
- RecordID reset to 1 (log was cleared and the clearing event itself was deleted)
- EID 4608 (audit system starting) immediately after a gap - indicates service restart after clear
- Large sequential gaps in RecordID values
- First event timestamp that is later than expected given system age

**EID 4616 - System time changed:**
If Security.evtx shows EID 4616 with a timestamp rollback, the attacker changed
the system clock to confuse the log timeline. Document the before/after times and
the account that made the change. All log timestamps after this event are unreliable
until another 4616 shows the time being set forward again.

**Log cleared but no 1102 present:**
This indicates the clearing was done in a way that also deleted the clearing event
(wevtutil cl Security; wevtutil cl System). This is more sophisticated and is itself
a finding. The absence of EID 1102 in a log that shows other signs of clearing
(RecordID reset, gap) is evidence of deliberate evidence destruction.

### Linux log clearing

```bash
# Check for truncated logs (file exists but empty)
ls -la /var/log/auth.log /var/log/syslog /var/log/apache2/access.log

# Check for gaps in log timestamps
awk '{print $1,$2,$3}' /var/log/auth.log | head -5
awk '{print $1,$2,$3}' /var/log/auth.log | tail -5

# Check inode change time vs last log entry time - if ctime is much newer than
# last log entry, the file may have been truncated and rewritten
stat /var/log/auth.log
```

A log file whose `ctime` (inode change time) is significantly newer than the
last log entry within it is consistent with truncation or replacement.

---

## Timestomping (T1070.006)

Covered in detail in `timeline-reconstruction.md`.

### Scope - three classes of files to check (all three, not just one)

The most common real-world miss is scoping timestomping detection to the
implant binary only. CTF and training examples timestomp the malware; real
attackers timestomp **the data they stole** to hide *when* it was staged.
Always check all three of these:

1. **Implant binaries** - the canonical case. For each malware binary already
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
   attacker is hiding *when* they staged the exfil archive - extremely
   high-value finding for both the timeline and the intent narrative.

   Trigger: any `finding_record()` whose `claim` contains
   "accessed", "exfiltrated", "staged", "exfil", or "crown-jewel".

3. **Log files themselves.** Windows event logs (`Security.evtx`,
   `System.evtx`, `Application.evtx`) and Linux `wtmp`/`btmp`/`auth.log` can
   be timestomped to hide gaps. Run `$SI` vs `$FN` on the log files, and
   compare each log's "last record timestamp" to its filesystem `mtime`.

If any of these three was not in scope of your anti-forensics phase, the
phase is incomplete - record an explicit "scope: implant-binaries only"
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
no timestomping, write the negative finding explicitly - naming every
directory and file class you checked - so a downstream reviewer can confirm
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
| `cipher /w` (Windows built-in) | None | None | No artifact - deduce from command history |
| DBAN / Darik's Boot and Nuke | N/A (wipes entire drive) | N/A | Used to wipe machines before disposal |

**What to look for:**
1. Prefetch entries for any of the above tools
2. Registry keys (may survive even after uninstall)
3. Installation packages (`.exe` installers in Downloads or Temp)
4. Eraser's task log: `%AppData%\Eraser 6\Task List.ersx`
5. CCleaner's uninstall entry removing itself: `MFT Created` timestamp for CCleaner
   followed quickly by `MFT Deleted` timestamp

**Impact assessment:** Even if the target files were successfully wiped, the fact
that secure deletion was run during the incident window is independently significant.
Document: tool name, execution time (from Prefetch last run time), account used
(from Prefetch + EVTX), and whether the execution correlates with the attack timeline.

### Linux secure deletion

```bash
shred, wipe, srm        # leave no artifacts themselves
# Detect by: bash_history, auth.log (if sudo), audit.log (if auditd was running)
find / -name "shred" -o -name "wipe" -o -name "srm" 2>/dev/null  # tool presence
```

---

## WEVTUTIL and log manipulation

`wevtutil.exe cl <logname>` is the built-in Windows command to clear event logs.

**Detection:**
- Prefetch: `WEVTUTIL.EXE-*.pf` with last run time correlating to incident window
- Command history: `cmdscan`/`consoles` Volatility plugins
- The cleared log itself: RecordID gap + EID 4608 immediately after

**Multiple wevtutil.exe Prefetch entries** (e.g. `WEVTUTIL.EXE-AABBCCDD.pf` and
`WEVTUTIL.EXE-11223344.pf`) indicate the tool was run from two different paths - 
this is consistent with running from a webshell (different working directory) and
also from an interactive session.

---

## Anti-forensics tool detection checklist

When investigating any case with confirmed attacker persistence or interactive access,
work through this checklist:

**Execution evidence:**
- [ ] Prefetch: search for known anti-forensics tool names
- [ ] Amcache: SHA1 hash lookup for known tools
- [ ] UserAssist / MuiCache: GUI anti-forensics tools
- [ ] cmdscan / consoles (memory): `wevtutil`, `cipher`, `del /f`, `rm -rf`

**Registry evidence:**
- [ ] CCleaner registry keys
- [ ] Eraser registry keys
- [ ] SDelete EULA acceptance key

**Log integrity:**
- [ ] EVTX RecordID continuity check (no gaps)
- [ ] Presence/absence of EID 1102 / 104
- [ ] EVTX file timestamps vs last event timestamps
- [ ] System time change events (EID 4616)

**File system evidence:**
- [ ] MFT: deleted entries for known anti-forensics tools
- [ ] $UsnJrnl: rename/delete events for tool files
- [ ] Installer packages for Eraser/CCleaner in Downloads or Temp

---

## Documenting anti-forensics for prosecution

Anti-forensics activity is evidence of consciousness of guilt. Document it
with the same rigor as the underlying attack artifacts:

1. **What tool was used** - name, version if recoverable
2. **When it was executed** - timestamp from Prefetch, memory, or EVTX
3. **What account ran it** - from Prefetch path, memory, or logon events
4. **What was targeted** - log name, file path, or directory
5. **Whether the attempt succeeded** - is the target evidence recoverable or gone?
6. **Correlation to attack timeline** - does the execution time follow confirmed
   attacker activity? This is the element that connects anti-forensics to intent.

Record each confirmed anti-forensics action as a separate `finding_record()` with
`linked_itq` pointing to the ITQ-026 answer (log clearing / anti-forensics evidence).
