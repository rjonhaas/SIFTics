---
name: windows-artifacts
description: Windows forensic artifact map - what exists, where it lives, what tool reads it, what question it answers
---

# Windows Forensic Artifacts

This skill is a reference map. For each artifact class: what it is, where to find it
on disk, which tool to use, and what forensic question it answers. Use it to ensure
full artifact coverage before concluding a Windows investigation.

---

## Registry hives

Every hive is a separate file. Hive files can be parsed directly from a disk image
without mounting (use `reg.py`, `regipy`, `RECmd`, or `hivex`).

| Hive | Path on disk | What it contains |
|---|---|---|
| SYSTEM | `Windows\System32\config\SYSTEM` | current control set, services, device history, USB connections (USBSTOR), network interfaces, timezone, last shutdown time |
| SOFTWARE | `Windows\System32\config\SOFTWARE` | installed software, Windows version, run keys at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, product install times |
| SAM | `Windows\System32\config\SAM` | local user accounts, password hashes, last logon time, login count, account creation time - requires SYSTEM hive for boot key to decrypt |
| SECURITY | `Windows\System32\config\SECURITY` | LSA secrets, cached domain credentials, audit policy |
| NTUSER.DAT | `Users\<username>\NTUSER.DAT` | per-user run keys, MRU lists, typed paths, recently accessed files, search history, user-installed software, timezone offset |
| UsrClass.dat | `Users\<username>\AppData\Local\Microsoft\Windows\UsrClass.dat` | Shellbags (folder access history including network shares and removable media) |

### Key registry locations

| Location | What it reveals |
|---|---|
| `SYSTEM\...\Enum\USBSTOR` | Every USB storage device ever connected: device type, serial number, first/last connection time |
| `SYSTEM\...\Services` | All registered services - compare against baseline to find attacker-installed services |
| `SOFTWARE\...\Run`, `RunOnce` | Persistence via autorun at login |
| `NTUSER.DAT\...\RecentDocs` | Files recently opened by user, by extension |
| `NTUSER.DAT\...\OpenSavePidlMRU` | Files opened/saved via dialog boxes |
| `NTUSER.DAT\...\TypedPaths` | Paths typed directly into Explorer address bar |
| `NTUSER.DAT\...\WordWheelQuery` | Search terms entered in Windows Search |
| `NTUSER.DAT\...\MuiCache` | Programs that have been executed (display name → executable path) |
| `NTUSER.DAT\...\UserAssist` | GUI program execution counts and last run times (ROT13 encoded) |

**Tool:** `RECmd` with the Zimmermann batch file covers all major registry keys in one pass:
```bash
RECmd.exe -d /mnt/img/Windows/System32/config --bn BatchExamples\RECmd_batch_MC.reb --csv /output/
```

---

## Windows Event Logs

Event logs are in `Windows\System32\winevt\Logs\`. Parse with `EvtxECmd` (bulk) or
`python-evtx` / `evtx_dump.py` (individual). Key event IDs by category:

### Authentication and account activity

| EID | Log | Meaning |
|---|---|---|
| 4624 | Security | Successful logon - note Logon Type: 2=interactive, 3=network, 10=remote interactive (RDP), 7=unlock |
| 4625 | Security | Failed logon - repeated failures = brute force |
| 4634/4647 | Security | Logoff |
| 4648 | Security | Logon with explicit credentials (runas, Pass-the-Hash) |
| 4672 | Security | Special privileges assigned (admin logon) |
| 4720 | Security | **User account created** |
| 4722 | Security | User account enabled |
| 4726 | Security | User account deleted |
| 4732 | Security | **User added to security-enabled local group** (e.g. Remote Desktop Users, Administrators) |
| 4756 | Security | User added to security-enabled universal group |
| 4738 | Security | User account changed |

### Process and execution

| EID | Log | Meaning |
|---|---|---|
| 4688 | Security | Process creation (requires audit policy - includes command line if configured) |
| 4689 | Security | Process exit |
| 1 | Sysmon | Process creation with full command line and parent info (more reliable than 4688) |
| 7045 | System | **New service installed** - common persistence mechanism |
| 7036 | System | Service started/stopped |

### Log tampering

| EID | Log | Meaning |
|---|---|---|
| 1102 | Security | **Security audit log cleared** - records who cleared it |
| 104 | System | **System log cleared** |
| 4616 | Security | **System time changed** - anti-forensics indicator |
| 4608 | Security | Audit system starting - RecordID reset to 1 following log clear |

### Network and firewall

| EID | Log | Meaning |
|---|---|---|
| 5156 | Security | Windows Filtering Platform permitted connection |
| 5157 | Security | Windows Filtering Platform blocked connection |
| 4946/4947 | Security | Windows Firewall rule added/modified |

### RDP

| EID | Log | Meaning |
|---|---|---|
| 4778 | Security | Session reconnected to window station (RDP reconnect) |
| 4779 | Security | Session disconnected from window station |
| 21/25 | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | RDP logon / session reconnect |
| 1149 | Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | RDP authentication attempt |

**Tools (on SIFT, in order of preference):**

```bash
# 1. evtx_dump (Rust, omerbenamram/evtx) - fastest, single binary, no Python deps
evtx_dump /mnt/img/Windows/System32/winevt/Logs/Security.evtx > Security.xml
evtx_dump -o jsonl /mnt/img/.../Security.evtx > Security.jsonl   # JSONL (easier to grep)

# 2. EvtxECmd (Eric Zimmerman, .NET) - bulk CSV with built-in maps
EvtxECmd.exe -d /mnt/img/Windows/System32/winevt/Logs/ --csv /output/ --csvf events.csv

# 3. evtx_dump.py (Python fallback) - only if the Rust binary is unavailable
evtx_dump.py /mnt/img/.../Security.evtx
```

> ⚠️ **Caveat: there are TWO different `evtx_dump` binaries on PATH on a SIFT
> workstation.** The one shipped via `pip install evtx` (`~/.local/bin/evtx_dump`)
> is a Python entry-point shim that frequently breaks with
> `ModuleNotFoundError: No module named 'scripts'` after pip upgrades. The
> canonical, fast one is the Rust binary from
> <https://github.com/omerbenamram/evtx/releases> - also called `evtx_dump`
> but it lives wherever you put it (we install it at `~/.local/bin/evtx_dump`,
> shadowing the broken Python shim). If `evtx_dump` dies with that
> `ModuleNotFoundError`, re-download the Rust release.

---

## File system artifacts

### MFT ($MFT)

The Master File Table records every file on an NTFS volume. Each entry has:
- `$STANDARD_INFORMATION` (SI) - timestamps that users/programs can modify
- `$FILE_NAME` (FN) - timestamps maintained by the kernel; harder to tamper

**Timestomping indicator:** SI timestamps earlier than FN timestamps by more than
a few seconds indicate manual timestamp manipulation.

**Tool:** `MFTECmd` - parses the raw $MFT:
```bash
MFTECmd.exe -f /mnt/img/'$MFT' --csv /output/ --csvf mft.csv
```

### $LogFile (NTFS transaction journal)

Circular journal of NTFS metadata operations. Slower to overwrite than MFT.
Recoverable records include: file creation, deletion, rename, and attribute changes
for files that may no longer appear in MFT.

```bash
# Extract $LogFile from image, then:
python3 LogFileParser.py -i LogFile.bin -o logfile.csv
```

Use when: access log references files absent from disk; MFT entry shows file was
deleted; need to confirm a file existed at a specific time.

### $UsnJrnl ($Extend\$UsnJrnl:$J)

The USN (Update Sequence Number) change journal. Records file creation, modification,
rename, and deletion events with timestamps. Larger retention window than $LogFile.

```bash
MFTECmd.exe -f /mnt/img/'$Extend/$UsnJrnl:$J' --csv /output/ --csvf usnjrnl.csv
```

---

## Execution artifacts

These artifacts prove a program ran, even if the binary has been deleted.

| Artifact | Location | What it proves | Tool |
|---|---|---|---|
| Prefetch | `Windows\Prefetch\*.pf` | Program name, last run time, run count, files loaded | `PECmd` |
| Amcache | `Windows\AppCompat\Programs\Amcache.hve` | SHA1 of executed binaries, first execution time | `AmcacheParser` |
| Shimcache / AppCompatCache | `SYSTEM` hive → `CurrentControlSet\Control\Session Manager\AppCompatCache` | Every executable that touched the filesystem (not necessarily run), last modified time | `AppCompatCacheParser` |
| RecentFileCache | `Windows\AppCompat\Programs\RecentFileCache.bcf` | Program paths that ran (legacy, pre-Win8) | `RecentFileCacheParser` |
| UserAssist | `NTUSER.DAT` → `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | GUI programs run, run count, last run time (ROT13 keys) | `RECmd` |
| MuiCache | `NTUSER.DAT` or `UsrClass.dat` | Executable display name → path mapping | `RECmd` |

**Note:** Windows Server 2008 standard disables Prefetch by default. Absence of
Prefetch on a server is expected, not evidence of tampering.

---

## User activity artifacts

| Artifact | Location | What it reveals |
|---|---|---|
| LNK files | `Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\` | Recently opened files and folders - includes path, timestamps, volume info, MAC address |
| JumpLists | `Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` | Per-application recently opened files |
| Shellbags | `UsrClass.dat` → `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` | Every folder ever navigated to, including USB drives, network shares, zip files |
| Thumbcache | `Users\<user>\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db` | Thumbnail cache - can recover images of files even after deletion |

**Tools:** `LECmd` (LNK), `JLECmd` (JumpLists), `SBECmd` (Shellbags)

---

## Browser artifacts

| Browser | Location | Contains |
|---|---|---|
| Chrome | `Users\<user>\AppData\Local\Google\Chrome\User Data\Default\` | History (SQLite), Cookies, Downloads, Login Data, Bookmarks |
| Firefox | `Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\` | places.sqlite (history + bookmarks), cookies.sqlite, formhistory.sqlite |
| Internet Explorer / Edge Legacy | `Users\<user>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat` | History, cookies, content |

**Tool:** `SQLECmd` for Chrome/Firefox SQLite databases.

---

## Network artifacts

| Artifact | Location | What it reveals |
|---|---|---|
| Network interface history | `SYSTEM` hive → `CurrentControlSet\Services\Tcpip\Parameters\Interfaces` | Historical IP assignments |
| DNS cache | Memory only (not on disk) - use Volatility `windows.netstat` | Recent DNS resolutions |
| WLAN profiles | `ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\` | Previously connected WiFi SSIDs |
| RDP cached credentials | `Users\<user>\AppData\Local\Microsoft\Terminal Server Client\Cache\` | Cached RDP thumbnails of remote sessions |

---

## SAM hive - account forensics

The SAM hive is encrypted by the boot key from the SYSTEM hive.

```bash
# On-disk with impacket
python3 secretsdump.py -sam /mnt/img/Windows/System32/config/SAM \
    -system /mnt/img/Windows/System32/config/SYSTEM LOCAL

# Or with samdump2
samdump2 /mnt/img/Windows/System32/config/SYSTEM \
         /mnt/img/Windows/System32/config/SAM
```

Output includes: username, RID (SID suffix), NT hash, last logon time, creation
time, login count. RIDs are sequential - two new accounts with consecutive RIDs
created at the same timestamp indicate batch creation (likely attacker automation).
