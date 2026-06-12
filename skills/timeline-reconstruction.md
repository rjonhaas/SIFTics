---
name: timeline-reconstruction
description: Building and interpreting investigation timelines — MAC times, artifact correlation, timestomping, super-timeline
---

# Timeline Reconstruction

A timeline is the spine of an investigation. Without it, findings are a list of facts
with no causal order. With it, you can answer: what happened first, what caused what,
and where the gaps are. This skill covers how to build a reliable timeline and how to
interpret what it tells you.

---

## Timestamp fundamentals

### NTFS timestamps (Windows)

Every NTFS file has two timestamp sets:

| Attribute | Abbrev | Modifiable by? | Covers |
|---|---|---|---|
| `$STANDARD_INFORMATION` | SI | Any process with file access | Created, Modified, Accessed, MFT Entry Modified |
| `$FILE_NAME` | FN | Kernel only (on rename/move) | Created, Modified, Accessed, MFT Entry Modified |

**Rule:** If SI timestamps predate FN timestamps by more than a few seconds, the SI
timestamps were manually manipulated (timestomping). FN timestamps are the forensically
reliable set for files that have not been moved.

**What each timestamp means:**

| Timestamp | Updated when |
|---|---|
| Created (SI) | File first created on this volume (resets on copy) |
| Modified (SI) | File content last written |
| Accessed (SI) | File last read (often disabled in modern Windows for performance) |
| MFT Entry Modified (SI) | MFT metadata last changed (permissions, name, timestamps) |

**Copy vs. move:**
- Moving a file within the same volume: SI Created timestamp is preserved.
- Copying to a new volume: SI Created = time of copy operation. FN Created = same.
- This means a file copied from an attacker's machine to the victim will show the
  copy time as SI Created, not the original creation time on the attacker's machine.

### Linux/Unix timestamps (ext4, XFS)

| Timestamp | Name | Updated when |
|---|---|---|
| `mtime` | Modify time | File content written |
| `ctime` | Change time | Metadata changed (permissions, owner, name) — NOT "created" |
| `atime` | Access time | File read (often `relatime` or `noatime` mounted — may be stale) |
| `crtime` | Birth time | File creation (ext4 only, via `debugfs -R "stat <file>"`) |

---

## Artifact-to-timeline mapping

Different artifacts answer different time questions. Use multiple sources to
cross-corroborate and detect manipulation.

| Artifact | Best for | Time resolution | Tamper risk |
|---|---|---|---|
| MFT $FILE_NAME timestamps | File creation/move | 100ns | Low (kernel-controlled) |
| MFT $STANDARD_INFORMATION timestamps | File content changes | 100ns | High (user-modifiable) |
| EVTX event logs | Process creation, logon, service install | 1ms | Medium (can be cleared) |
| Apache/Nginx access log | HTTP requests with second-precision | 1s | Low (append-only by web server) |
| Prefetch last run time | Program execution | 1s | Low |
| Amcache first execution | First program run | 1s | Low |
| UserAssist last run | GUI program execution | 1s | Low |
| Browser history | Web activity | 1ms (SQLite timestamp) | Medium |
| $LogFile / $UsnJrnl | File operations (creates/deletes/renames) | 100ns | Low |
| SAM hive last write | Account changes | 1s | Medium |
| Registry hive last write | Any registry change | 1s | Medium |
| Memory dump acquisition time | Upper bound for all memory artifacts | Known from FTK/DumpIt output | Low |

---

## Building a timeline manually

For most cases, a manually constructed timeline from key artifacts is faster and
more targeted than a full super-timeline. Build it in this order:

**1. Anchor points first** — establish the known-good timestamps:
- OS install date (SOFTWARE hive `Windows NT\CurrentVersion\InstallDate`)
- Memory acquisition time (from acquisition tool log or file timestamp)
- Disk image acquisition time (from FTK/dd log)
- Case-reported incident date (from ITQ-002 answer)

**2. Attack artifact timestamps** — work backward and forward from the anchor:
- First attacker IP in access log
- First webshell creation (MFT FN Created)
- First command execution (EVTX 4688 or cmdscan output)
- Account creation (SAM + EVTX 4720)
- Persistence installation (service, cron, Run key)
- Anti-forensics execution (Eraser/CCleaner Prefetch or cmdscan)

**3. Correlate across sources** — for each event, find at least two independent
artifact sources. Single-source timestamps are facts; dual-source timestamps are
findings you can defend.

**Template for each timeline entry:**
```
[TIMESTAMP UTC] [EVENT] [ARTIFACT SOURCE] [CONFIDENCE: high/medium/low]
```

---

## Super-timeline with log2timeline / Plaso

Use Plaso when manual timeline construction would take too long, when you need full
coverage across all artifact types, or when the case has a large number of unknowns.

```bash
# Parse all artifacts from a disk image
log2timeline.py --storage-file timeline.plaso /dev/<disk_image>

# Filter to a specific time window
psort.py -o l2tcsv timeline.plaso "date > '2015-09-01' AND date < '2015-09-04'" \
  > timeline_filtered.csv

# Or filter by artifact type
psort.py -o l2tcsv timeline.plaso "parser is 'winevtx'" > evtx_only.csv
```

**Cost:** Plaso takes 30–120 minutes on a typical disk image. Use it after HOT
findings have identified the relevant time window — filter immediately rather than
reviewing the full super-timeline.

**mactime format** (alternative, faster for MFT-only):
```bash
fls -r -m C: -o <offset> image.dd > bodyfile.txt
mactime -b bodyfile.txt -d '2015-09-01' -z UTC > mft_timeline.csv
```

---

## Detecting timestomping

Timestomping is the modification of file timestamps to disguise when a file
was created or modified. It is a T1070.006 technique.

### Indicators

**SI/FN divergence:**
- SI Created timestamp is earlier than FN Created timestamp → the file existed on
  the volume before it was moved/renamed to its current location, OR SI was rolled back
- SI timestamps that cluster at an exact round time (midnight, top of hour) →
  manual modification
- SI timestamps earlier than the OS install date → impossible, indicates manipulation

**Tool:** `MFTECmd` output includes both SI and FN timestamps. Export to CSV and
compare columns `SI Created` vs `FN Created`:
```bash
MFTECmd.exe -f '$MFT' --csv /output/ --csvf mft.csv
python3 -c "
import csv
with open('mft.csv') as f:
    for row in csv.DictReader(f):
        si = row.get('SI Created','')
        fn = row.get('FN Created','')
        if si and fn and si < fn:
            print(row['FileName'], 'SI:', si, 'FN:', fn)
"
```

**Zero timestamps:** Some tools set SI timestamps to all zeros or 1970-01-01.
This is an immediate timestomping indicator.

**Compile time vs. disk timestamp:** For PE executables, the compile timestamp in
the PE header should predate the MFT Created timestamp. If the MFT Created is
earlier than the PE compile time, either the MFT timestamp was backdated or the PE
header compile time was forged.

---

## Handling timezone ambiguity

Always record timestamps in UTC. Confirm the system timezone before interpreting
any local-time logs:

```bash
# From SYSTEM hive
reg.py -hive /mnt/img/Windows/System32/config/SYSTEM print \
  "ControlSet001\Control\TimeZoneInformation"
```

Windows event logs store timestamps in UTC. Apache logs default to the server's
local time unless configured otherwise — check `httpd.conf` for `CustomLog` format.
Browser history SQLite timestamps are in microseconds since 1601-01-01 (Chrome)
or seconds since 1970-01-01 (Firefox). Convert before adding to timeline.

---

## Timeline gaps as evidence

A gap in log coverage during an active period is itself a finding. Document:
- What artifact was expected to have coverage
- What time window is missing
- What the most likely explanation is (log cleared, rotation, attacker tampering)
- Whether the gap aligns with any confirmed attacker activity

Gaps that align with the attack window, especially in Security.evtx or auth.log,
should be treated as evidence of log clearing (see `anti-forensics-detection.md`).
