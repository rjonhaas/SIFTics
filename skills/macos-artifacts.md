---
name: macos-artifacts
description: macOS forensic artifact map for acquisition bundles - mac_apt plugins, Unified Log, persistence, and triage workflow
---

# macOS Forensic Artifacts

This skill covers macOS artifact analysis from acquisition packages. The primary tool
is **mac_apt** (installed at `/opt/mac-apt/bin/mac_apt_git/`). It must be run from
its own directory - the symlinks in `/usr/local/bin/` fail due to relative imports.

---

## mac_apt quick reference

### Input formats

| Format flag | What it processes |
|---|---|
| `DD` | Raw disk image (.dd, .img, .001 split) |
| `E01` | EnCase image (via libewf) |
| `DMG` | Apple disk image |
| `AXIOMZIP` | Magnet AXIOM logical acquisition zip |
| `UAC` | UAC (Unix Artifact Collector) triage bundle - zip from `uac -p macos` |
| `VR` | Velociraptor offline collector triage zip |
| `MOUNTED` | Live or already-mounted volume at a path |

### Running mac_apt

**Always run from the mac_apt directory:**
```bash
cd /opt/mac-apt/bin/mac_apt_git

# Full triage (FAST plugin group - most plugins, ~5 min)
python3 mac_apt.py DD /cases/<name>/evidence/mac_image.dd \
    -o /cases/<name>/mac_apt_out/ FAST

# Single plugin
python3 mac_apt.py DD /cases/<name>/evidence/mac_image.dd \
    -o /cases/<name>/mac_apt_out/ AUTOSTART

# UAC bundle (most common acquisition type from a live Mac)
python3 mac_apt.py UAC /cases/<name>/evidence/uac_bundle.tar.gz \
    -o /cases/<name>/mac_apt_out/ FAST

# Output as JSONL (best for agent parsing)
python3 mac_apt.py DD image.dd -o /output/ -j FAST
```

### Plugin → artifact mapping (key plugins)

| Plugin | Artifact | Forensic question |
|---|---|---|
| `BASICINFO` | OS version, serial number, last user, timezone, hostname | System identity and timestamps |
| `AUTOSTART` | LaunchAgents, LaunchDaemons, cron, login items, XPC services | Persistence mechanisms |
| `USERS` | Local user accounts, last login, password hint | Account forensics |
| `FSEVENTS` | FSEvents journal (`.fseventsd/`) | File creation/deletion/rename history |
| `INSTALLHISTORY` | `/Library/Receipts/InstallHistory.plist` | Software installed, when |
| `SAFARI` | History, downloads, bookmarks, cookies | Web activity |
| `CHROMIUM` | Chrome/Edge history, downloads, extensions | Web activity |
| `FIREFOX` | Firefox history, downloads | Web activity |
| `IMESSAGE` | iMessage/SMS database | Communications |
| `RECENTITEMS` | Recent files, recent applications, recent servers | User activity MRU |
| `SPOTLIGHT` | Spotlight database - file access metadata | File access history |
| `SAVEDSTATE` | Application saved state | What apps were open and what documents |
| `TERMINALSTATE` | Terminal window contents | Shell session content |
| `KEYCHAINS` | System keychain items | Saved credentials |
| `INETACCOUNTS` | Configured email, calendar, cloud accounts | Connected services |
| `TCC` | Privacy permissions (camera, microphone, disk access) | What apps had what access |
| `QUARANTINE` | Quarantine database - downloaded files | Files downloaded from internet |
| `NETWORKING` | Network interfaces, last IP, WiFi history | Network configuration |
| `BLUETOOTH` | Paired Bluetooth devices | Physical proximity / device connections |
| `IDEVICEINFO` | Connected iOS devices and sync history | iPhone/iPad connections |
| `IDEVICEBACKUPS` | iOS backup databases | iPhone/iPad forensics |
| `UNIFIEDLOGEXPORT` | Exports `.tracev3` + DSC files for external parsing | Unified Log extraction |
| `ASL` | Legacy Apple System Logs (pre-macOS 10.12) | Older system activity |
| `MSOFFICE` | Office MRU lists | Recently accessed Office files |
| `NOTIF` | Notification center database | App notifications history |
| `SCREENTIME` | Screen Time usage data | App usage duration |

Run `FAST` to cover all of the above plus others in one pass.

---

## Unified Log - the primary macOS activity source

The Unified Log replaced ASL in macOS 10.12 (Sierra) and is now the richest
activity source on any modern Mac. It lives at:
```
/private/var/db/diagnostics/     ← .tracev3 log files
/private/var/db/uuidtext/        ← DSC files (required to decode log messages)
```

### Step 1 - Export log files with mac_apt

```bash
cd /opt/mac-apt/bin/mac_apt_git
python3 mac_apt.py DD image.dd -o /output/mac_apt/ UNIFIEDLOGEXPORT
# Exports .tracev3 files + uuidtext/ DSC directory to output folder
```

### Step 2 - Parse with Mandiant macos-UnifiedLogs

The Mandiant `macos-UnifiedLogs` tool (Rust binary) is the recommended parser.
If not installed:
```bash
# Install from GitHub releases
curl -L https://github.com/mandiant/macos-UnifiedLogs/releases/latest/download/unifiedlog_parser_json-linux-x86_64.zip \
    -o /tmp/unifiedlog_parser.zip
unzip /tmp/unifiedlog_parser.zip -d /usr/local/bin/
chmod +x /usr/local/bin/unifiedlog_parser_json
```

Parse the exported logs:
```bash
unifiedlog_parser_json \
    --input /output/mac_apt/UnifiedLog/ \
    --output /output/unified_log.jsonl \
    --format jsonl
```

Each record includes: timestamp, process, subsystem, category, message.

### Alternative - log command (live system only)

The `log` command is macOS-native and NOT available on Linux/SIFT. Do not attempt
to use it against an acquired image. Use mac_apt + Mandiant parser instead.

### Key Unified Log queries (after parsing to JSONL)

```bash
# Authentication events
grep -i "authd\|sudo\|login\|authenticate" /output/unified_log.jsonl

# Network connections
grep -i "nw_connection\|networkd\|socketfilter" /output/unified_log.jsonl

# Process launches
grep -i "execve\|spawn\|launchd\|xpc" /output/unified_log.jsonl | grep -v "com.apple"

# Suspicious: commands run in Terminal
grep '"process":"bash"\|"process":"zsh"\|"process":"sh"' /output/unified_log.jsonl

# USB device connections
grep -i "IOUSBDevice\|IOUSBHost\|DiskArbitration" /output/unified_log.jsonl
```

---

## macOS persistence - what to check

After confirming initial access, immediately pivot to persistence. macOS has more
persistence locations than Windows.

### LaunchAgents / LaunchDaemons (most common)

```
/Library/LaunchAgents/                  ← system-wide, runs as user
/Library/LaunchDaemons/                 ← system-wide, runs as root
~/Library/LaunchAgents/                 ← per-user
/System/Library/LaunchAgents/           ← Apple-owned (baseline)
/System/Library/LaunchDaemons/          ← Apple-owned (baseline)
```

mac_apt `AUTOSTART` covers all of these. For each plist: check `ProgramArguments`,
`Program`, and `RunAtLoad`. Any path outside `/System/Library/` or `/usr/libexec/`
that wasn't installed by a known vendor is a candidate.

### Login items

```
~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm
~/Library/Preferences/com.apple.loginitems.plist
```

mac_apt `AUTOSTART` covers these.

### Kernel extensions (kexts) - legacy

```
/Library/Extensions/         ← third-party kexts
/System/Library/Extensions/  ← system kexts
```

Malicious kexts are rare post-macOS 11 due to System Extension requirements.
Check `/Library/SystemExtensions/` for modern equivalents.

### Cron and periodic tasks

```bash
cat /etc/crontab
ls /var/at/tabs/           # at jobs
ls /etc/periodic/          # daily/weekly/monthly
```

### Login hooks (legacy but still functional)

```
/private/var/root/Library/Preferences/com.apple.loginwindow.plist
# Key: LoginHook, LogoutHook
```

---

## macOS acquisition types and what's missing

| Acquisition type | Has disk image | Has Unified Log | Has memory | Notes |
|---|---|---|---|---|
| Full disk image (DD/E01) | ✓ | ✓ (if not encrypted) | ✗ | Best coverage; APFS encryption requires PRK or password |
| UAC triage bundle | ✗ | ✓ (exported by UAC) | ✗ | Fast; no deleted files; most artifacts present |
| Velociraptor VR zip | ✗ | ✓ (if configured) | ✗ | Depends on VR artifacts configured |
| AXIOM logical | ✗ | varies | ✗ | App-database level; no raw FS |

For UAC bundles: confirm whether the UAC profile included `-a unifiedlogs` - it's
not always enabled. If Unified Log is absent, FSEvents and ASL are fallbacks.

---

## APFS encryption

If the image is FileVault-encrypted, mac_apt needs the Personal Recovery Key (PRK)
or a user password:

```bash
python3 mac_apt.py DD encrypted_image.dd -o /output/ -p "PRK-XXXX-XXXX-XXXX-XXXX" FAST
# OR
python3 mac_apt.py DD encrypted_image.dd -o /output/ -p "userpassword" FAST
```

If neither is available, document the gap and note that decryption requires legal
process for the Apple escrow key.

---

## macOS acquisition triage checklist

Work through this on every macOS case:

- [ ] Run mac_apt FAST - covers 50+ artifact types
- [ ] Check mac_apt BASICINFO output: OS version, serial, last user, timezone
- [ ] Check mac_apt AUTOSTART: any non-Apple LaunchAgent/Daemon?
- [ ] Check mac_apt USERS: unexpected accounts? root enabled?
- [ ] Run UNIFIEDLOGEXPORT + Mandiant parser: authenticate/process/network events
- [ ] Check mac_apt INSTALLHISTORY: software installed in the incident window
- [ ] Check mac_apt QUARANTINE: files downloaded from internet
- [ ] Check mac_apt TCC: what apps had Full Disk Access?
- [ ] Check mac_apt FSEVENTS: file creation/deletion timeline
- [ ] Check mac_apt SAFARI/CHROMIUM: browser activity
- [ ] Check mac_apt KEYCHAINS: credentials stored
- [ ] Check mac_apt IDEVICEINFO: connected iOS devices (data exfil via USB?)
