# macOS Triage Analysis — SIFT Workstation Runbook

## Overview

This runbook covers triage-based macOS DFIR on a SANS SIFT Ubuntu workstation. It assumes a collected triage package produced by a Mac triage script — not a full disk image — containing live-collected artifact directories. Commands are written against the Ruse case but variable names make them portable.

**Typical triage structure:**
```
<Case>/<hostname>-Mac-Triage/
├── Library/
│   ├── Application Support/com.apple.TCC/  ← TCC.db (privacy permissions)
│   ├── LaunchDaemons/                       ← persistence (system-wide)
│   ├── Logs/
│   └── Preferences/                         ← system-wide plists
├── System/
├── UnifiedLogs/<hostname>.logarchive         ← primary log source
├── Users/
│   └── <username>/
│       ├── Desktop/, Documents/
│       └── Library/
│           ├── Application-Support/
│           │   ├── CallHistoryDB/
│           │   ├── com.apple.TCC/           ← user TCC.db
│           │   ├── Dock/
│           │   └── Knowledge/               ← knowledgeC.db
│           ├── Cookies/
│           ├── Group-Containers/
│           │   ├── group.com.apple.notes/
│           │   └── group.com.apple.mail/
│           ├── Keychains/
│           ├── Logs/
│           ├── Mail/
│           ├── Preferences/                 ← user plists (LaunchServices, etc.)
│           └── Safari/
├── fsevents/                                ← .fseventsd (may be empty)
├── private/
│   ├── etc/                                 ← passwd, sudoers, hosts, shells
│   └── var/db/                              ← CoreDuet, powerlog
└── spotlight/                               ← .Spotlight-V100 (may be empty)
```

---

## SIFT Tools for macOS

| Tool | Invocation | Best For |
|------|-----------|---------|
| **mac_apt** (artifact-only) | `/opt/mac-apt/bin/python3 /opt/mac-apt/bin/mac_apt_git/mac_apt_artifact_only.py <PLUGIN> -i <path> -o <output> -c` | Structured parsing of most macOS artifacts |
| **sqlite3** | `sqlite3 <db> "<query>"` | Direct SQLite queries (knowledgeC, TCC, Safari, CallHistory) |
| **plistutil** | `plistutil -i <file> -o /dev/stdout` | Convert binary plist → XML for reading |
| **python3 plistlib** | `python3 -c "import plistlib,sys; d=plistlib.load(open(sys.argv[1],'rb')); print(d)" <file>` | Parse binary plists inline — always use semicolon one-liners to avoid indentation errors |
| **unifiedlog_iterator** | `/usr/local/bin/unifiedlog_iterator --mode log-archive --input <logarchive> --output <file> --format jsonl` | Parse .logarchive on Linux → JSONL (Mandiant `macos-unifiedlogs`, v0.5.0) — see Phase 9 Setup |
| **log** (macOS only) | N/A on SIFT — use `unifiedlog_iterator` instead | Unified log parsing on a live macOS host |
| **strings / xxd** | `strings <file>` | Quick artifact content preview |
| **jq** | `jq .` | Parse JSONL output from mac_apt |

---

## mac_apt Artifact-Only — Plugin Reference

`mac_apt_artifact_only` is a Python-based framework that parses individual macOS artifact files without needing a full disk image. It is the primary structured parsing tool for triage packages. Each plugin knows the schema of a specific artifact and outputs normalized CSV, JSONL, or SQLite. Pass `-i` for the artifact input path, `-o` for the output directory, and `-c` to produce CSV.

**Base variables — set these before running any command:**

```bash
# CASE must point to the top-level case directory (e.g., /cases/<case_name>/),
# NOT the collection subdirectory — outputs must land in the same ./analysis/ tree
# as all other skills.
CASE="/cases/<case_name>"   # top-level case directory
TRIAGE="$CASE/<CollectionDir>/<Triage-Subdir>"
OUT="$CASE/analysis"
MAC_APT="/opt/mac-apt/bin/python3 /opt/mac-apt/bin/mac_apt_git/mac_apt_artifact_only.py"

# Set to the primary user account on the Mac being analyzed
MAC_USER="<username>"  # e.g., irek, john.doe, localadmin
```

**Generic plugin invocation:**

```bash
$MAC_APT <PLUGIN> -i "$TRIAGE/<artifact_path>" -o "$OUT/<plugin_name>" -c
```

| Plugin | Input Path | Key Forensic Value |
|--------|-----------|-------------------|
| `SAFARI` | `Users/<user>/Library/Safari` | URL history, downloads, cookies, searches |
| `QUARANTINE` | `Users/<user>/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` | Files downloaded from internet (URL, app, timestamp) |
| `AUTOSTART` | `Library/LaunchDaemons` + `Users/<user>/Library/LaunchAgents` | Persistence mechanisms |
| `TCC` | `Library/Application Support/com.apple.TCC/TCC.db` | App privacy/permission grants (camera, mic, full disk, etc.) |
| `RECENTITEMS` | `Users/<user>/Library/Preferences` | Recent docs, servers, volumes, applications |
| `DOCKITEMS` | `Users/<user>/Library/Preferences/com.apple.dock.plist` | Dock contents — installed/launched apps |
| `IMESSAGE` | `Users/<user>/Library/Messages/chat.db` | iMessage conversations |
| `CHROMIUM` | `Users/<user>/Library/Application Support/Google/Chrome` | Chrome history if present |
| `COOKIES` | `Users/<user>/Library/Cookies` | Binary cookies |
| `CALLHISTORY` | `Users/<user>/Library/Application Support/CallHistoryDB/CallHistory.storedata` | FaceTime/phone call log |
| `NOTES` | `Users/<user>/Library/Group Containers/group.com.apple.notes` | Apple Notes content |
| `WIFI` | `Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist` | WiFi networks, connection timestamps |
| `BLUETOOTH` | System bluetooth plists | Paired devices |
| `INSTALLHISTORY` | `/Library/Receipts/InstallHistory.plist` | Software install/update history |
| `NETUSAGE` | `/private/var/networkd/db/netusage.sqlite` | Per-app network usage |
| `UTMPX` | `/private/var/db/utmpx` | Login records |
| `SPOTLIGHT` | `.Spotlight-V100` | File metadata index |
| `SPOTLIGHTSHORTCUTS` | User Library spotlight plist | User spotlight search history |
| `TERMINALSTATE` | User Terminal saved state | Full terminal session text |
| `SCREENTIME` | User ScreenTime DB | App usage duration |
| `XPROTECT` | System XProtect paths | Malware detection events |
| `SUDOLASTRUN` | `/private/var/db/sudo` | Last sudo timestamp |
| `NOTIFICATIONS` | User notification DBs | App notification history |
| `QUICKLOOK` | User QuickLook cache | Thumbnails → evidence of file viewing |
| `MSOFFICE` | User Library Application Support | Office MRU/recently opened |
| `INETACCOUNTS` | User Library Preferences | Cloud account configs |
| `PRINTJOBS` | CUPS spool | Print job history |
| `SCREENSHARING` | User Preferences | Remote desktop connection history |
| `CFURLCACHE` | User CFURL cache | Network request cache |
| `CRASHREPORTER` | User/System crash logs | App crashes with timestamps |

---

## CoreData Timestamp Note

macOS stores timestamps in many databases using Apple's CoreData epoch — **January 1, 2001** — not the Unix epoch (January 1, 1970). The offset between them is 978,307,200 seconds. Any SQLite query against macOS databases must add this offset before converting to a readable UTC time.

```sql
datetime(TIMESTAMP_COLUMN + 978307200, 'unixepoch', 'utc')
```

---

## Triage Playbook — Ordered by Priority

---

### Phase 0: Kick Off Long-Running Jobs First

Before doing any analysis, start the logarchive parser in the background. It takes 5–10 minutes and you will need it throughout the investigation — kick it off immediately so it is ready when you reach Phase 9.

```bash
# Set base variables first (reuse these throughout the playbook)
# CASE must be the top-level case directory so outputs land in ./analysis/ alongside other skills
CASE="/cases/<case_name>"   # top-level case directory (e.g., /cases/jackofallhacks)
TRIAGE="$CASE/<CollectionDir>/<Triage-Subdir>"
OUT="$CASE/analysis"
MAC_USER="<username>"       # primary user account on the Mac (e.g., irek, john.doe)
mkdir -p "$OUT/unified_logs"

# Identify the logarchive (usually named after the hostname + collection date)
LOGARCHIVE=$(find "$TRIAGE/UnifiedLogs" -name "*.logarchive" | head -1)
echo "Logarchive: $LOGARCHIVE"

# Parse to JSONL in the background — do NOT wait; move to Phase 1 immediately
nohup unifiedlog_iterator \
  --mode log-archive \
  --input  "$LOGARCHIVE" \
  --output "$OUT/unified_logs/unified.jsonl" \
  --format jsonl \
  > "$OUT/unified_logs/parse.log" 2>&1 &

echo "Parser PID: $!  — tail $OUT/unified_logs/parse.log to check progress"
```

> **Check progress:** `tail -f "$OUT/unified_logs/parse.log"`
> **Verify done:** `wc -l "$OUT/unified_logs/unified.jsonl"` — expect millions of lines for a multi-day archive.

Once parsing completes, query the JSONL with the `ulog_search()` Python function in Phase 9.

---

### Phase 1: Orient — Who, What, When

Before touching artifacts, establish the system's identity and confirm the time context so all subsequent timestamps can be correctly interpreted.

---

#### 1.1 System Identity

**Artifact:** `SystemConfiguration/preferences.plist` is a binary property list written by the OS containing the machine's configured hostname, computer name, and network setup. `plistutil` converts the binary plist format to human-readable XML on Linux so `grep` can extract key fields. `/private/etc/passwd` and `master.passwd` are standard BSD-style account databases listing all local user accounts and their shell/home directory — `master.passwd` additionally contains password hashes on older macOS versions.

```bash
# ComputerName and LocalHostName are nested — not top-level keys
python3 -c "
import plistlib
d=plistlib.load(open('$TRIAGE/Library/Preferences/SystemConfiguration/preferences.plist','rb'))
print('ComputerName :', d['System']['System'].get('ComputerName','not set'))
print('LocalHostName:', d['System']['Network']['HostNames'].get('LocalHostName','not set'))
print('Model        :', d.get('Model','not set'))
"

# Local user accounts
cat "$TRIAGE/private/etc/passwd"
cat "$TRIAGE/private/etc/master.passwd" 2>/dev/null
```

#### 1.2 Timezone

**Artifact:** `/private/etc/localtime` is a symlink on macOS pointing to the active timezone file under `/usr/share/zoneinfo/`. Reading the symlink target (not the file contents) tells you the configured timezone. This is critical — all timestamps in plist files and some SQLite databases are stored in the system's local time, not UTC, so you must know the offset before interpreting them.

```bash
# localtime is copied as a file in triage (symlink not preserved by cp)
# strings extracts the POSIX TZ string from the tzfile binary
strings "$TRIAGE/private/etc/localtime" | tail -3
```

#### 1.3 Collection Timestamp

**Artifact:** The processing details file is generated by the triage script at collection time. It records the exact commands run, their order, and any errors encountered. Reading it tells you when collection happened, what was captured successfully, and what was missed — for example, FSEvents and Spotlight were empty in this case because the script couldn't access those volumes.

```bash
# Collection timestamp is encoded in the package dirname: YYYYMMDD_HHMMSS (local time)
basename "$CASE"

# Hostname and any collection errors
head -5 "$CASE/"*_Processing_Details.txt
```

---

### Phase 2: Persistence — What Survives Reboot?

macOS uses a launch daemon/agent system (launchd) for persistence. Anything that automatically starts at boot or login will be registered here. Attackers frequently drop plist files into these directories to maintain access.

---

#### 2.1 LaunchDaemons and LaunchAgents

**Artifact:** LaunchDaemons live in `/Library/LaunchDaemons/` and run as root at system boot — they have no user context. LaunchAgents live in `/Library/LaunchAgents/` (system-wide) or `~/Library/LaunchAgents/` (per-user) and run when a user logs in. Each is a plist file with a `Label` (unique identifier), a `ProgramArguments` key (what binary to run and with what flags), and optionally a `RunAtLoad` key (whether to start immediately). `plistutil` converts these binary plists to XML for reading. Legitimate system daemons have Apple-signed binaries; suspicious ones point to unusual paths like `/tmp/`, `/Users/<user>/`, or shell scripts.

```bash
# List all system daemons
ls -la "$TRIAGE/Library/LaunchDaemons/"

# Extract the label and program from each daemon plist
for f in "$TRIAGE/Library/LaunchDaemons/"*.plist; do
  echo "=== $f ==="
  plistutil -i "$f" -o /dev/stdout 2>/dev/null | grep -a -E "Label|Program|ProgramArguments" -A3
done

# Check for user-level agents
ls -la "$TRIAGE/Users/*/Library/LaunchAgents/" 2>/dev/null
```

#### 2.2 mac_apt AUTOSTART

**What it does:** The AUTOSTART plugin aggregates all persistence locations across the triage — LaunchDaemons, LaunchAgents, login items, cron jobs, and kernel extensions — and outputs them in a normalized table with the program path, arguments, and whether it runs as root. This gives a single unified view of everything configured to start automatically without having to manually hunt each directory.

```bash
$MAC_APT AUTOSTART -i "$TRIAGE" -o "$OUT/autostart" -c
cat "$OUT/autostart/"*.csv
```

---

### Phase 3: Execution & Activity — What Ran?

---

#### 3.1 KnowledgeC.db

**Artifact:** `knowledgeC.db` is a SQLite database maintained by the `knowledged` daemon, part of Apple's Duet Activity Scheduler. It records a continuous stream of device activity events — which app was in the foreground and for how long, when the screen was locked or woken, when the device connected to a network, and what URLs were visited in-browser. Each event is stored in the `ZOBJECT` table with a stream name (e.g., `/app/inFocus`, `/device/locked`, `/safari/history`) and a start/end timestamp in Apple's CoreData epoch. This is often the richest single source of user activity in a triage because it persists across reboots and captures events from all apps, not just browsers.

**What the query does:** The query filters ZOBJECT to the most forensically relevant stream types and converts the Apple epoch timestamps to UTC. `/app/inFocus` tells you which app had keyboard/mouse focus and for how long. `/device/locked` shows screen lock/unlock events. `/user/screenwake` shows when the display was turned on. This reconstructs a timeline of what the user was doing and when.

```bash
DB="$TRIAGE/Users/$MAC_USER/Library/Application-Support/Knowledge/knowledgeC.db"

# Interactive query — app usage and device events
sqlite3 "$DB" "
SELECT
  datetime(ZOBJECT.ZSTARTDATE + 978307200, 'unixepoch', 'utc') AS start_utc,
  datetime(ZOBJECT.ZENDDATE   + 978307200, 'unixepoch', 'utc') AS end_utc,
  ZOBJECT.ZVALUESTRING AS bundle_id,
  ZOBJECT.ZSTREAMNAME
FROM ZOBJECT
WHERE ZSTREAMNAME IN (
  '/app/inFocus',
  '/app/webUsage',
  '/app/install',
  '/device/locked',
  '/user/screenwake'
)
ORDER BY ZSTARTDATE ASC;
"
```

```bash
# Export full activity to CSV
sqlite3 -header -csv "$DB" "
SELECT
  datetime(ZSTARTDATE + 978307200, 'unixepoch', 'utc') AS start_utc,
  datetime(ZENDDATE   + 978307200, 'unixepoch', 'utc') AS end_utc,
  ZVALUESTRING AS bundle_id,
  ZSTREAMNAME
FROM ZOBJECT
ORDER BY ZSTARTDATE;
" > "$OUT/knowledgeC_activity.csv"
echo "Exported: $OUT/knowledgeC_activity.csv"
```

#### 3.2 Dock Items

**Artifact:** `com.apple.dock.plist` is a binary plist that stores the user's Dock configuration — pinned apps on the left side and recently used apps on the right. The recently-used section is maintained automatically by the OS and reflects apps the user actually launched, making it useful for proving application execution even without full logs. Pinned items also indicate which tools the user considers important enough to keep readily accessible.

**What mac_apt DOCKITEMS does:** Parses the binary plist structure, extracts app bundle paths from both the static and recent-apps sections, and outputs them as a normalized CSV with the tile type and label.

```bash
$MAC_APT DOCKITEMS -i "$TRIAGE/Users/$MAC_USER/Library/Preferences/com.apple.dock.plist" -o "$OUT/dock" -c
cat "$OUT/dock/"*.csv
```

#### 3.3 Terminal History and Shell Configuration

**Artifact:** Shell history files (`.bash_history`, `.zsh_history`) contain a sequential log of commands typed at the terminal, with optional timestamps if `HISTTIMEFORMAT` was set. Shell RC files (`.zshrc`, `.bashrc`, `.profile`) contain aliases, environment variables, and functions loaded at shell startup — attackers sometimes plant persistence or obfuscation here. The system-wide equivalents under `/private/etc/` apply to all users.

```bash
# Shell history per user
find "$TRIAGE/Users" -name ".bash_history" -o -name ".zsh_history" -o -name ".sh_history" 2>/dev/null \
  | while read f; do echo "=== $f ==="; cat "$f"; done

# System-wide RC files
cat "$TRIAGE/private/etc/zshrc" "$TRIAGE/private/etc/bashrc" 2>/dev/null

# Per-user RC files
find "$TRIAGE/Users" -name ".zshrc" -o -name ".bashrc" -o -name ".profile" 2>/dev/null \
  | while read f; do echo "=== $f ==="; cat "$f"; done
```

#### 3.4 Recent Items

**Artifact:** macOS maintains per-user lists of recently accessed documents, servers, volumes, and applications in a mix of `.plist` and `.sfl2` (Shared File List) binary files under `~/Library/Preferences/` and `~/Library/Application Support/com.apple.sharedfilelist/`. These are updated by the OS every time a user opens a file or connects to a server and persist across reboots. They can prove file access even when the file itself has been deleted.

**What mac_apt RECENTITEMS does:** Decodes the binary SFL2 and plist formats across all recent-item categories (documents, servers, applications, volumes, places) and outputs file paths and timestamps in a single CSV.

```bash
$MAC_APT RECENTITEMS -i "$TRIAGE/Users/$MAC_USER/Library/Preferences" -o "$OUT/recentitems" -c
cat "$OUT/recentitems/"*.csv
```

#### 3.5 Crash Reports

**Artifact:** Crash reports are generated by `ReportCrash` whenever an application terminates abnormally. Each report is a plain-text file stored in `~/Library/Logs/DiagnosticReports/` (user crashes) or `/Library/Logs/DiagnosticReports/` (system crashes). They contain the crashing process name, PID, timestamp, OS version, and a full stack trace. Forensically, crash reports prove that a specific binary was executed at a specific time — including malware that crashes after deployment.

**What mac_apt CRASHREPORTER does:** Parses all crash report plists in the provided directory and extracts process name, timestamp, exception type, and the responsible process — normalized to CSV for timeline correlation.

```bash
ls "$TRIAGE/Library/Logs/DiagnosticReports/" "$TRIAGE/Users/$MAC_USER/Library/Logs/DiagnosticReports/" 2>/dev/null

$MAC_APT CRASHREPORTER -i "$TRIAGE/Library/Logs/DiagnosticReports" -o "$OUT/crashes" -c
```

---

### Phase 4: Browser and Network Activity

---

#### 4.1 Safari History and Downloads

**Artifact:** Safari stores browsing history in a SQLite database (`History.db`) with two tables: `history_items` (unique URLs and visit counts) and `history_visits` (individual visit events with timestamps). Downloads are tracked separately in `Downloads.plist`, a binary plist that records the source URL, local save path, and completion status of each download — this file persists even after the download is removed from the Downloads list in the browser UI.

**What mac_apt SAFARI does:** Parses History.db, Downloads.plist, cookies, top sites, and other Safari databases in one pass, normalizing all timestamps and joining the history tables so each visit row includes the full URL.

**What the direct SQLite query does:** Joins `history_visits` to `history_items` on the item ID to get a flat table of visit time, URL, page title, and visit count, sorted most-recent-first. `plistutil` converts the binary Downloads.plist to readable XML.

```bash
$MAC_APT SAFARI -i "$TRIAGE/Users/$MAC_USER/Library/Safari" -o "$OUT/safari" -c
cat "$OUT/safari/"*.csv
```

```bash
# Direct history query with timestamp conversion
HIST="$TRIAGE/Users/$MAC_USER/Library/Safari/History.db"
sqlite3 -header -csv "$HIST" "
SELECT
  datetime(v.visit_time + 978307200, 'unixepoch', 'utc') AS visit_utc,
  i.url,
  v.title,
  v.visit_count
FROM history_visits v
JOIN history_items i ON v.history_item = i.id
ORDER BY v.visit_time DESC
LIMIT 500;
" > "$OUT/safari_history.csv"
```

```bash
# Downloads list
plistutil -i "$TRIAGE/Users/$MAC_USER/Library/Safari/Downloads.plist" -o /dev/stdout 2>/dev/null
```

#### 4.1b Execution History from Unified Log (App Launch Forensics)

After identifying a downloaded suspicious app, use the Unified Log to reconstruct every time the user launched it, which attempts were blocked by Apple Security Policy (ASP/AMFI), and the exact timestamp of successful execution.

**Key messages to search in `unified.jsonl`:**

| Message Pattern | Source Process | Meaning |
|---|---|---|
| `Successfully spawned <App>[PID]` | launchd (pid 1) | Process launched |
| `ASP: Security policy would not allow process` | kernel | AMFI/ASP blocked execution |
| `applicationReady` | loginwindow | App checked in as ready |
| `applicationQuit` | loginwindow | App quit normally |
| `SecTranslocateCreateSecureDirectoryForURL` | lsd | Gatekeeper App Translocation activated |
| `temporarySigning` | syspolicyd | Temporary signature evaluation |

**No `applicationQuit` after a spawn = process ran to completion (or reverse shell staying alive).**

```python
import json, datetime

UNIFIED = "analysis/unified_logs/unified.jsonl"
APP_NAME = "<SuspiciousAppName>"   # e.g. "Scientific-Calculator"

launches, blocks = [], []
with open(UNIFIED) as f:
    for line in f:
        d = json.loads(line)
        msg = d.get('message', '')
        ts  = d.get('timestamp', '')
        if APP_NAME not in msg:
            continue
        if 'Successfully spawned' in msg:
            launches.append(ts)
        elif 'ASP:' in msg or 'Security policy' in msg:
            blocks.append(ts)

def parse_ts(ts):
    return datetime.datetime.fromisoformat(ts.replace('Z','+00:00'))

print(f"Launches: {len(launches)}, Blocks: {len(blocks)}")
for lt in sorted(launches):
    ldt = parse_ts(lt)
    blocked = any(abs((parse_ts(bt) - ldt).total_seconds()) < 30 for bt in blocks)
    status = 'BLOCKED' if blocked else '*** SUCCEEDED ***'
    print(f"  {lt}  {status}")
```

**Ruse case example:**
```
2025-03-07T21:12:25Z  PID 899   BLOCKED — ASP
2025-03-07T21:12:36Z  PID 910   BLOCKED — ASP
2025-03-07T21:14:16Z  PID 970   BLOCKED — ASP
2025-03-07T21:14:24Z  PID 975   Quit immediately
2025-03-07T21:14:37Z  PID 985   *** SUCCEEDED *** — reverse shell established
```
User's most recent (and successful) interaction with the malicious file: `2025-03-07 21:14:37 UTC`

---

#### 4.2 Quarantine Events

**Artifact:** The Quarantine database (`com.apple.LaunchServices.QuarantineEventsV2`) is a SQLite database maintained by macOS's Gatekeeper system. Every time a file is downloaded through a quarantine-aware application (Safari, Chrome, Mail, AirDrop, curl with the quarantine flag), macOS writes a record to this database containing the download timestamp, the source URL, the referring URL, and the application that performed the download. The quarantine attribute is also set as an extended attribute on the file itself, but the database entry persists even after the file is deleted. This makes it one of the most reliable artifacts for proving that a specific file was downloaded from a specific URL at a specific time.

**What the query does:** Retrieves all quarantine events sorted by most recent, converting the CoreData timestamp and surfacing the source URL, referrer, and downloading app.

```bash
QDB="$TRIAGE/Users/$MAC_USER/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
sqlite3 -header -csv "$QDB" "
SELECT
  datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch', 'utc') AS ts_utc,
  LSQuarantineDataURLString                                         AS source_url,
  LSQuarantineOriginURLString                                       AS referrer,
  LSQuarantineAgentBundleIdentifier                                 AS app_bundle,
  LSQuarantineAgentName
FROM LSQuarantineEvent
ORDER BY LSQuarantineTimeStamp DESC;
" > "$OUT/quarantine_events.csv"
echo "Quarantine events: $(wc -l < "$OUT/quarantine_events.csv") rows"
```

#### 4.3 WiFi Networks

**Artifact:** `com.apple.airport.preferences.plist` is a binary plist maintained by the Airport (WiFi) subsystem. It contains a list of every WiFi network the system has ever joined, including the SSID, BSSID, security type, and the timestamp of the last connection. This is valuable for placing the device at a physical location or identifying unknown/rogue networks the device connected to.

**What mac_apt WIFI does:** Decodes the binary plist, extracts the known networks array, and normalizes the connection timestamps to a CSV — each row is one network with its join history.

```bash
$MAC_APT WIFI -i "$TRIAGE/Library/Preferences/SystemConfiguration" -o "$OUT/wifi" -c
cat "$OUT/wifi/"*.csv
```

#### 4.4 Network Usage (per-app)

**Artifact:** The `netusage.sqlite` database (managed by `networkd`) tracks cumulative bytes sent and received broken down by process name and interface. It is useful for identifying which application was responsible for large data transfers — a key indicator in data exfiltration investigations. Note that this database may be at `/private/var/networkd/db/netusage.sqlite` rather than the generic `var/db` path.

**What mac_apt NETUSAGE does:** Reads the netusage SQLite schema, joins process names to byte counts and timestamps, and outputs a per-app network usage summary.

```bash
ls "$TRIAGE/private/var/db/"

$MAC_APT NETUSAGE -i "$TRIAGE/private/var/db" -o "$OUT/netusage" -c 2>/dev/null \
  || echo "NETUSAGE: check path — may be at /private/var/networkd/db/netusage.sqlite"
```

---

### Phase 5: Privacy and Permissions (TCC)

**Artifact:** TCC (Transparency, Consent, and Control) is macOS's privacy enforcement framework. Its database (`TCC.db`) records which applications have been granted or denied access to sensitive resources: Full Disk Access, Camera, Microphone, Contacts, Calendar, Location Services, Screen Recording, Accessibility, and more. There are two copies: the system-level copy at `/Library/Application Support/com.apple.TCC/TCC.db` (governs system-wide grants, including Full Disk Access) and a per-user copy at `~/Library/Application Support/com.apple.TCC/TCC.db` (governs user-context grants like Contacts and Calendar). Each row in the `access` table records the service name, the requesting app's bundle ID, whether access was allowed or denied, and the timestamp of the last modification.

**What mac_apt TCC does:** Parses both TCC databases and maps the numeric `auth_value` codes to human-readable strings (allowed/denied/limited), making the output immediately actionable without needing to know the schema.

**What the direct query does:** Reads the `access` table directly, translates `auth_value` inline using a CASE statement, and sorts by most recently modified — useful for identifying which permissions were granted just before a suspicious event.

```bash
# System-level TCC (Full Disk Access lives here)
$MAC_APT TCC -i "$TRIAGE/Library/Application Support/com.apple.TCC/TCC.db" -o "$OUT/tcc_system" -c

# User-level TCC (Contacts, Camera, Mic, Calendar, etc.)
$MAC_APT TCC -i "$TRIAGE/Users/$MAC_USER/Library/Application-Support/com.apple.TCC/TCC.db" -o "$OUT/tcc_user" -c
```

```bash
# Direct query — most recently modified permissions across both databases
for TCC_DB in \
  "$TRIAGE/Library/Application Support/com.apple.TCC/TCC.db" \
  "$TRIAGE/Users/$MAC_USER/Library/Application-Support/com.apple.TCC/TCC.db"; do
  echo "=== $TCC_DB ==="
  sqlite3 -header "$TCC_DB" "
  SELECT
    service,
    client,
    client_type,
    CASE auth_value
      WHEN 0 THEN 'denied'
      WHEN 2 THEN 'allowed'
      ELSE cast(auth_value as text)
    END AS access,
    datetime(last_modified, 'unixepoch', 'utc') AS modified_utc
  FROM access
  ORDER BY last_modified DESC;
  " 2>/dev/null
done
```

---

### Phase 6: Communications and Data

---

#### 6.1 Call History

**Artifact:** `CallHistory.storedata` is a CoreData SQLite database maintained by the `CallHistoryDB` framework. It logs all phone calls and FaceTime calls made or received, including the phone number or Apple ID of the other party, call direction (inbound/outbound), duration, and timestamp. On a Mac with iPhone integration (Handoff/Continuity), this database reflects calls handled through the phone as well.

**What mac_apt CALLHISTORY does:** Reads the CoreData object graph from `ZCALLRECORD`, decodes the address and timestamp fields, and outputs a normalized call log CSV.

```bash
$MAC_APT CALLHISTORY \
  -i "$TRIAGE/Users/$MAC_USER/Library/Application-Support/CallHistoryDB" \
  -o "$OUT/callhistory" -c
cat "$OUT/callhistory/"*.csv
```

#### 6.2 iMessage and Messages

**Artifact:** `chat.db` is a SQLite database maintained by the Messages app. It stores all iMessage and SMS conversations in three core tables: `message` (message content, timestamps, read receipts, attachments), `chat` (conversation metadata, group names), and `handle` (contact identifiers — phone numbers or Apple IDs). The database persists deleted messages until their space is reclaimed by SQLite's auto-vacuum, so deleted message content is sometimes recoverable with `strings` or SQLite carving tools.

**What mac_apt IMESSAGE does:** Joins the three core tables, decodes binary blob attachments metadata, converts timestamps, and outputs a flat message log with sender, recipient, content, and direction.

```bash
# Locate chat.db in the triage
find "$TRIAGE/Users" -name "chat.db" 2>/dev/null

# Run plugin once the path is confirmed
$MAC_APT IMESSAGE -i "<path_to_chat.db>" -o "$OUT/imessage" -c
```

#### 6.3 Apple Notes

**Artifact:** Apple Notes stores its content in a CoreData SQLite database inside the `group.com.apple.notes` Group Container. Note body text is stored as compressed, serialized protobuf blobs — not plain text — making direct SQLite queries difficult. mac_apt handles the decompression and deserialization internally. Notes can contain text, embedded images, tables, and scanned documents, and they sync via iCloud so local content may reflect activity across all of the user's Apple devices.

**What mac_apt NOTES does:** Reads the CoreData store, decompresses and deserializes the protobuf-encoded note body, and outputs note titles, creation/modification timestamps, and plain-text content to CSV.

```bash
$MAC_APT NOTES \
  -i "$TRIAGE/Users/$MAC_USER/Library/Group-Containers/group.com.apple.notes" \
  -o "$OUT/notes" -c
cat "$OUT/notes/"*.csv
```

#### 6.4 Mail and Configured Accounts

**Artifact:** The Mail app stores messages as individual `.emlx` files under `~/Library/Mail/`, organized by account and mailbox. The Group Container at `group.com.apple.mail` holds supplementary databases. Configured internet accounts (iCloud, Gmail, Exchange, etc.) are stored as binary plists in `~/Library/Preferences/` — these reveal what external services the user's Mac was connected to, which is useful for understanding data access scope and potential exfiltration vectors.

**What mac_apt INETACCOUNTS does:** Parses the account configuration plists and outputs each configured account's type, username, hostname, and associated services (Mail, Contacts, Calendar, Notes).

```bash
ls "$TRIAGE/Users/$MAC_USER/Library/Mail/" 2>/dev/null
ls "$TRIAGE/Users/$MAC_USER/Library/Group-Containers/group.com.apple.mail/" 2>/dev/null

$MAC_APT INETACCOUNTS -i "$TRIAGE/Users/$MAC_USER/Library/Preferences" -o "$OUT/accounts" -c
cat "$OUT/accounts/"*.csv
```

---

### Phase 7: File Access and Exfiltration Indicators

---

#### 7.1 Spotlight Shortcuts

**Artifact:** When a user types into the Spotlight search bar, macOS records those search strings in a plist under `~/Library/Application Support/com.apple.spotlight/`. This includes app names, file names, and freeform search terms. These records prove that a user specifically searched for something — including file names that may no longer exist on disk.

**What mac_apt SPOTLIGHTSHORTCUTS does:** Parses the plist array of search strings and associated timestamps, outputting each typed query with the time it was entered.

```bash
$MAC_APT SPOTLIGHTSHORTCUTS \
  -i "$TRIAGE/Users/$MAC_USER/Library/Application-Support/com.apple.spotlight" \
  -o "$OUT/spotlight_shortcuts" -c
cat "$OUT/spotlight_shortcuts/"*.csv
```

#### 7.2 QuickLook Thumbnail Cache

**Artifact:** When a user previews a file using QuickLook (spacebar in Finder), macOS generates a thumbnail and stores it in a cache database. The cache stores the thumbnail image, the file path, and the creation timestamp. Critically, the thumbnail persists in the cache even after the original file is deleted — making it possible to prove a user viewed a file that no longer exists, and in some cases to recover a visual preview of the deleted content.

**What mac_apt QUICKLOOK does:** Reads the QuickLook cache SQLite database, extracts file path references and timestamps, and optionally exports thumbnail images for visual review.

```bash
# Locate the QuickLook cache database
find "$TRIAGE" -name "*.db" -path "*/QuickLook*" 2>/dev/null

$MAC_APT QUICKLOOK -i "<quicklook_cache_path>" -o "$OUT/quicklook" -c
```

#### 7.3 Shared File Lists (Per-App Recent Documents)

**Artifact:** Shared File Lists (SFL2 format) are binary plist files stored under `~/Library/Application Support/com.apple.sharedfilelist/`. Each file tracks recently accessed documents for a specific application — for example, `com.apple.LSSharedFileList.RecentDocuments.sfl2` is the global recent documents list, while per-app variants like `com.microsoft.Word.sfl2` track Word's recents separately. These prove file access on a per-application basis and often retain entries after the file has been deleted. The format is a binary NSKeyedArchiver plist; `plistutil` converts it to XML, after which `strings` extracts the file paths.

```bash
ls "$TRIAGE/Users/$MAC_USER/Library/Application-Support/com.apple.sharedfilelist/" 2>/dev/null

# Extract file paths from each SFL2 binary plist
for f in "$TRIAGE/Users/$MAC_USER/Library/Application-Support/com.apple.sharedfilelist/"*.sfl* 2>/dev/null; do
  echo "=== $f ==="
  plistutil -i "$f" -o /dev/stdout 2>/dev/null | strings | grep -a -E "file://|/Users" | head -20
done
```

#### 7.4 iCloud Drive Activity

**Artifact:** The `group.com.apple.iCloudDrive` Group Container holds metadata about the user's iCloud Drive sync state, including which files were uploaded, downloaded, or recently modified. This is useful for identifying whether sensitive files were synced to iCloud — a potential exfiltration path that bypasses local controls.

**What mac_apt ICLOUD does:** Parses iCloud Drive metadata databases to extract file names, paths, sync timestamps, and iCloud item identifiers.

```bash
ls "$TRIAGE/Users/$MAC_USER/Library/Group-Containers/group.com.apple.iCloudDrive/" 2>/dev/null

$MAC_APT ICLOUD \
  -i "$TRIAGE/Users/$MAC_USER/Library/Group-Containers/group.com.apple.iCloudDrive" \
  -o "$OUT/icloud" -c 2>/dev/null
```

---

### Phase 8: User Accounts and Privilege Analysis

---

#### 8.1 Local Accounts and Group Membership

**Artifact:** `/private/etc/passwd` is the BSD account database listing all local users with their UID, GID, home directory, and login shell. On macOS, the `admin` group (GID 80) determines who can run `sudo` and make system changes — any user in this group has effective administrative access. `/private/etc/group` maps group names to member lists. `master.passwd` is the privileged account file that historically held password hashes; on modern macOS it may be present for legacy compatibility.

```bash
cat "$TRIAGE/private/etc/passwd"

# Who is in the admin group?
cat "$TRIAGE/private/etc/group" 2>/dev/null | grep -E "^admin:|^wheel:"

# Password hashes (if present)
cat "$TRIAGE/private/etc/master.passwd" 2>/dev/null
```

#### 8.2 Sudoers Configuration

**Artifact:** `/etc/sudoers` defines which users and groups can run commands as root via `sudo`, and optionally which specific commands they can run. Modifications to sudoers — especially adding `NOPASSWD` entries or adding non-admin users — are a classic privilege escalation and persistence technique. `/etc/sudoers.d/` contains drop-in override files that supplement the main sudoers file.

```bash
cat "$TRIAGE/private/etc/sudoers"
ls "$TRIAGE/private/etc/sudoers.d/" 2>/dev/null
cat "$TRIAGE/private/etc/sudoers.d/"* 2>/dev/null
```

#### 8.3 SSH Configuration and Keys

**Artifact:** `/etc/ssh/` contains the SSH daemon configuration (`sshd_config`) which controls whether remote login is enabled, which auth methods are permitted, and what port is in use. `~/.ssh/authorized_keys` lists public keys that can log in without a password — an attacker planting a key here gains persistent backdoor access. `known_hosts` shows which remote systems the user has connected to via SSH, which can reveal lateral movement or C2 infrastructure.

```bash
ls "$TRIAGE/private/etc/ssh/" 2>/dev/null
cat "$TRIAGE/private/etc/ssh/sshd_config" 2>/dev/null | grep -v "^#" | grep -v "^$"

# Per-user SSH artifacts
find "$TRIAGE/Users" \( -name "known_hosts" -o -name "authorized_keys" -o -name "*.pub" \) 2>/dev/null \
  | while read f; do echo "=== $f ==="; cat "$f"; done
```

#### 8.3a Remote Service Enablement — SSH / VNC / Screen Sharing / ARD

> **Investigator note:** Enabling a remote-access service on a system that did not previously run it is a high-confidence attacker action (T1021.004 / T1021.005). Always check whether SSH, Screen Sharing, VNC, or ARD was enabled *during* the intrusion window and timestamp it precisely.

**On macOS, enabling SSH via System Settings or `systemsetup -setremotelogin on` causes `launchctl` to bootstrap `/System/Library/LaunchDaemons/ssh.plist`. This event is written to `launchd.log` with exact timestamps even when the Unified Log cannot be parsed.**

```bash
LAUNCHD_LOG="$TRIAGE/private/var/log/com.apple.xpc.launchd"

# SSH enablement — look for the Bootstrap succeeded line
grep -r "com.openssh.sshd\|ssh.plist\|Enabling service com.openssh" "$LAUNCHD_LOG/" 2>/dev/null

# All remote-access service bootstrap events
grep -r "Bootstrap by launchctl.*ssh\|Bootstrap by launchctl.*screensharing\|Bootstrap by launchctl.*ARD\|Bootstrap by launchctl.*vnc" \
  "$LAUNCHD_LOG/" 2>/dev/null

# SSH login/logout sessions from system.log (local time — convert to UTC)
grep -i "sshd:\|USER_PROCESS\|DEAD_PROCESS" "$TRIAGE/private/var/log/system.log" 2>/dev/null
```

**What to look for:**

| `launchd.log` line | Meaning |
|---|---|
| `Enabling service com.openssh.sshd` | SSH turned on (attacker or user) |
| `Bootstrap by launchctl[PID] for /System/Library/LaunchDaemons/ssh.plist succeeded` | SSH service now listening |
| `Failed to bootstrap path: path = .../ssh.plist, error = 37: Operation already in progress` | SSH was already running at this point |

**Timestamps in `launchd.log` are local machine time — convert to UTC using the system timezone.**

**Other remote service plists to watch for:**
- `/System/Library/LaunchDaemons/com.apple.screensharing.plist` — Screen Sharing / VNC
- `/System/Library/LaunchDaemons/com.apple.RemoteDesktop.PrivilegeProxy.plist` — ARD
- `/System/Library/LaunchDaemons/com.apple.NetworkSharing.plist` — Internet Sharing

#### 8.3b Power Events — Boot / Shutdown / Sleep / Wake

> **Investigator note:** Always reconstruct the full power-state timeline before interpreting other artifacts. A gap between a compromise event and the next analyst action may be explained by a shutdown or sleep. An unexpected boot during off-hours is itself an indicator.

**Sources (available in a triage without a macOS host):**

| Source | What it records | Location |
|--------|----------------|----------|
| `system.log` `BOOT_TIME` | Kernel boot — Unix timestamp | `private/var/log/system.log` |
| `system.log` `SHUTDOWN_TIME` | Clean shutdown — Unix timestamp | `private/var/log/system.log` |
| `launchd.log*` | First boot task timestamp (local time) | `private/var/log/com.apple.xpc.launchd/` |
| Power mgmt ASL | SMC shutdown cause (clean vs forced) | `private/var/log/powermanagement/*.asl` |

**Missing SHUTDOWN_TIME between two BOOTs = abrupt/forced power-off.** Cross-check by strings-searching the power management ASL for `SMC shutdown cause` — value `0: Battery disconnected` confirms unclean shutdown (hard power-off or VM force-off).

```bash
SYSLOG="$TRIAGE/private/var/log/system.log"
LAUNCHD_LOG="$TRIAGE/private/var/log/com.apple.xpc.launchd"
PMLOG="$TRIAGE/private/var/log/powermanagement"

# All boot and shutdown timestamps (Unix epoch → UTC)
grep -E "BOOT_TIME|SHUTDOWN_TIME" "$SYSLOG"

# Convert to UTC inline
grep -E "BOOT_TIME|SHUTDOWN_TIME" "$SYSLOG" | while read line; do
  ts=$(echo "$line" | grep -oE '[0-9]{10}' | head -1)
  ev=$(echo "$line" | grep -oE 'BOOT_TIME|SHUTDOWN_TIME')
  label=$(echo "$line" | cut -d' ' -f1-3)
  [ -n "$ts" ] && printf "%-12s  %s  %s\n" "$ev" "$(date -u -d @$ts '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date -u -r $ts '+%Y-%m-%d %H:%M:%S UTC')" "$label"
done

# Boot sequence from launchd.log (timestamps are LOCAL time — convert to UTC)
head -1 "$LAUNCHD_LOG/launchd.log" "$LAUNCHD_LOG/launchd.log.1" "$LAUNCHD_LOG/launchd.log.2" 2>/dev/null

# SMC shutdown cause — 'Battery disconnected' = forced/unclean, '3: Software' = clean
strings "$PMLOG/"*.asl 2>/dev/null | grep -i "SMC shutdown cause"
```

**Power event interpretation:**

| Pattern | Meaning |
|---------|---------|
| `BOOT_TIME` with no preceding `SHUTDOWN_TIME` | Forced power-off, crash, or sleep/wake (not logged as shutdown) |
| `SHUTDOWN_TIME` immediately before `BOOT_TIME` | Normal reboot or clean shutdown+boot |
| Long gap between `SHUTDOWN_TIME` and `BOOT_TIME` | Device was off — duration establishes user availability window |
| `SMC shutdown cause: 0: Battery disconnected` | Hard power-off (held power button, VM force-off, battery pull) |
| `SMC shutdown cause: 3: Software` | Normal macOS shutdown |

**Note:** `launchd.log` rotates on each boot (`.log` = most recent, `.log.1` = previous, `.log.2` = oldest). The first line of each file is the boot timestamp in **local machine time**. The `system.log` `BOOT_TIME` value is a Unix epoch timestamp and timezone-independent.

#### 8.4 Login Records

**Artifact:** `utmpx` is a binary database (BSD standard) that records user login and logout events — console logins, remote logins via SSH, and window manager sessions. It contains username, terminal (tty), source host/IP, and timestamps for each session. On macOS this file is at `/private/var/db/utmpx`. The `loginwindow.plist` records which users have logged in via the GUI login window and stores the last logged-in username.

**What mac_apt UTMPX does:** Parses the binary utmpx record structure and outputs each login event as a human-readable row with user, host, and UTC timestamp.

```bash
$MAC_APT UTMPX -i "$TRIAGE/private/var/db/utmpx" -o "$OUT/utmpx" -c 2>/dev/null
cat "$OUT/utmpx/"*.csv

plistutil -i "$TRIAGE/Library/Preferences/com.apple.loginwindow.plist" -o /dev/stdout 2>/dev/null
```

#### 8.5 Sudo Last Run

**Artifact:** `/private/var/db/sudo/` stores per-user timestamps of the most recent successful `sudo` authentication. macOS uses this to enforce the sudo credential caching window (default 5 minutes) — if a timestamp file exists for a user, they authenticated with sudo at that time. This provides a lightweight indicator of privilege escalation activity even without full log access.

**What mac_apt SUDOLASTRUN does:** Reads the timestamp files and outputs the user account and last sudo authentication time in UTC.

```bash
$MAC_APT SUDOLASTRUN -i "$TRIAGE/private/var/db" -o "$OUT/sudo" -c 2>/dev/null
cat "$OUT/sudo/"*.csv
```

---

### Threat Intelligence — VirusTotal Hash Lookup

> **When to run:** Any time you recover a suspicious binary. Always hash every unknown executable before doing anything else — a VT hit gives you family name, first-seen date, and related samples in seconds.

**Compute hashes first:**

```bash
# Hash every suspicious binary recovered from triage
find "$TRIAGE" -type f \( -name "*.bin" -o -perm /111 \) | while read f; do
  echo "$(md5sum "$f" | cut -d' ' -f1)  $(sha256sum "$f" | cut -d' ' -f1)  $f"
done 2>/dev/null
```

**VirusTotal API lookup (requires free API key — 4 req/min on free tier):**

```python
import requests, json, sys

VT_API_KEY = "YOUR_VT_API_KEY"   # set once per session

def vt_lookup(sha256):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers, timeout=10)
    if r.status_code == 200:
        data = r.json()["data"]["attributes"]
        stats  = data.get("last_analysis_stats", {})
        names  = data.get("popular_threat_classification", {})
        family = names.get("suggested_threat_label", "unknown")
        print(f"  Family     : {family}")
        print(f"  Malicious  : {stats.get('malicious',0)}/{sum(stats.values())}")
        print(f"  First seen : {data.get('first_submission_date','n/a')}")
        print(f"  Tags       : {data.get('tags',[])}")
    elif r.status_code == 404:
        print("  Not found in VT — novel sample or private hash")
    else:
        print(f"  VT error {r.status_code}")

# Example — Ruse case Demsty RAT
vt_lookup("6b379289033c4a17a0233e874003a843cd3c812403378af68ad4c16fe0d9b9c4")
```

**Bash one-liner (curl):**

```bash
VT_KEY="YOUR_VT_API_KEY"
SHA256="6b379289033c4a17a0233e874003a843cd3c812403378af68ad4c16fe0d9b9c4"

curl -s "https://www.virustotal.com/api/v3/files/$SHA256" \
  -H "x-apikey: $VT_KEY" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
a=d['data']['attributes']
print('Family  :', a.get('popular_threat_classification',{}).get('suggested_threat_label','n/a'))
print('Hits    :', a['last_analysis_stats']['malicious'], '/', sum(a['last_analysis_stats'].values()))
print('1st seen:', a.get('first_submission_date','n/a'))
"
```

**What to record from VT results:**
- `suggested_threat_label` → malware family name (e.g. `osx.demsty`)
- First submission date → earliest known sighting
- Tags → capabilities declared by VT (e.g. `keylogger`, `backdoor`, `rat`)
- Related samples → pivot to find other components

---

### Phase 9: Unified Logs

**Artifact:** The Unified Logging System (introduced in macOS 10.12) is the centralized logging infrastructure for all Apple system and app activity. Log data is stored in a compressed, binary `.tracev3` format inside a `.logarchive` bundle. The logarchive captures subsystem, category, process, PID, thread ID, and message for every log event — covering authentication, network connections, process launches, XPC calls, and more. It is the macOS equivalent of Windows Event Logs but far more comprehensive. The binary format requires Apple's `log` command-line tool or a compatible parser to read.

**Parser on SIFT:** `unifiedlog_iterator` is part of Mandiant's `macos-unifiedlogs` project (GitHub: `mandiant/macos-unifiedlogs`). v0.5.0 is pre-installed at `/usr/local/bin/unifiedlog_iterator`. It parses `.logarchive` bundles on Linux to JSONL format without requiring a macOS host. A full Ruse logarchive produces ~2.88M entries.

---

#### Setup — Verify or Install `unifiedlog_iterator`

**Verify the existing installation:**

```bash
which unifiedlog_iterator          # expect /usr/local/bin/unifiedlog_iterator
unifiedlog_iterator --version      # expect unifiedlog_iterator 0.5.0
```

**If missing — install from GitHub releases (run once as root):**

The `mandiant/macos-unifiedlogs` project distributes a pre-built Linux x64 static binary on its GitHub releases page. No Rust toolchain required.

```bash
# Download the Linux x64 release zip, then install
cd /tmp
# From: github.com/mandiant/macos-unifiedlogs/releases  →  pick the Linux_x64 asset
unzip unifiedlog_iterator-Linux_x64.zip
sudo install -m 755 unifiedlog_iterator /usr/local/bin/unifiedlog_iterator
unifiedlog_iterator --version
```

**DSC / UUID files — getting full message resolution:**

Without macOS dyld shared cache (DSC) and UUID mapping files, many log messages display raw format strings instead of resolved values (e.g. `"Connection to %{public}s established"` rather than the actual hostname). The logarchive bundle itself embeds a `dsc/` subdirectory and a `uuidtext/` directory — `unifiedlog_iterator` reads these automatically when present:

```bash
# Confirm DSC and UUID files are present inside the logarchive
ls "$LOGARCHIVE/dsc/"         # dyld shared cache files (named by UUID)
ls "$LOGARCHIVE/uuidtext/"    # UUID-to-binary path mapping
```

If these directories are missing (stripped triage), message resolution will be partial. All timestamps and metadata remain intact regardless.

---

**Step 1 — Parse the logarchive to JSONL (one-time, ~5–10 min):**

```bash
LOGARCHIVE=$(find "$TRIAGE/UnifiedLogs" -name "*.logarchive" | head -1)
[ -z "$LOGARCHIVE" ] && echo "ERROR: no .logarchive found under $TRIAGE/UnifiedLogs" && exit 1
OUT="$CASE/analysis/unified_logs"
mkdir -p "$OUT"

unifiedlog_iterator \
  --mode log-archive \
  --input  "$LOGARCHIVE" \
  --output "$OUT/unified.jsonl" \
  --format jsonl

wc -l "$OUT/unified.jsonl"   # verify line count
```

**Step 2 — Query the JSONL with Python (fast, repeatable):**

```bash
export UNIFIED_JSONL="$CASE/analysis/unified_logs/unified.jsonl"
```

```python
import json, sys, os

JSONL = os.environ.get("UNIFIED_JSONL", "$CASE/analysis/unified_logs/unified.jsonl")
KEYWORDS = sys.argv[1:]   # pass keywords as args, or hardcode below

with open(JSONL) as f:
    for line in f:
        d = json.loads(line)
        msg = d.get("message", "")
        if any(k.lower() in msg.lower() for k in KEYWORDS):
            ts  = d.get("timestamp", "")
            pid = d.get("pid", "")
            proc = d.get("process", "").split("/")[-1]
            print(f"{ts}  [{proc}:{pid}]  {msg[:200]}")
```

```bash
# Common DFIR query keywords
python3 query_unified.py ssh sshd        # SSH login/logout
python3 query_unified.py sudo            # privilege escalation
python3 query_unified.py pam             # PAM authentication
python3 query_unified.py loki            # attacker account activity
python3 query_unified.py UsersGroups     # account creation/deletion
python3 query_unified.py sysadminctl     # user management CLI
python3 query_unified.py LaunchAgent     # persistence installation
python3 query_unified.py "Delete a record" "MMDeleteUserAccount"  # account deletion
python3 query_unified.py disableFMM "Remove User"   # FMM pre-delete flow
```

**Step 3 — Time-window slice (inspect a specific UTC range):**

```bash
TARGET="2025-03-08T07:58"   # ISO prefix match
python3 -c "
import json
with open('$OUT/unified.jsonl') as f:
    for line in f:
        d = json.loads(line)
        if d.get('timestamp','').startswith('$TARGET'):
            proc = d.get('process','').split('/')[-1]
            print(d['timestamp'], f'[{proc}:{d.get(\"pid\",\"\")}]', d.get('message','')[:200])
"
```

**Key JSONL fields:**

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 UTC (e.g. `2025-03-08T07:58:55.123456Z`) |
| `process` | Full path of the logging process |
| `pid` | Process ID |
| `subsystem` | Apple subsystem reverse-DNS string |
| `category` | Logging category within subsystem |
| `message` | The log message text |

---

**Option A — macOS host** (transfer logarchive to a Mac and run there):

```bash
# Basic filtered query
log show --archive "$LOGARCHIVE" \
  --predicate 'eventMessage CONTAINS "sudo" OR eventMessage CONTAINS "ssh"' \
  --style syslog \
  --start "2025-03-01" --end "2025-03-09"
```

```bash
# Authentication events (securityd, authorization)
log show --archive "$LOGARCHIVE" \
  --predicate 'subsystem == "com.apple.securityd" OR category == "Authorization"' \
  --info --style syslog
```

```bash
# SSH login/logout events
log show --archive "$LOGARCHIVE" \
  --predicate 'process == "sshd"' \
  --style syslog
```

```bash
# App launches via LaunchServices
log show --archive "$LOGARCHIVE" \
  --predicate 'subsystem == "com.apple.launchservicesd"' \
  --style syslog
```

```bash
# Network TCP connection events
log show --archive "$LOGARCHIVE" \
  --predicate 'subsystem == "com.apple.network.tcp_cca"' \
  --info --style syslog
```

```bash
# Security/password change events
log show --archive "$LOGARCHIVE" \
  --predicate 'category == "authentication" OR eventMessage CONTAINS "password"' \
  --style syslog
```

---

### Phase 10: XProtect and Gatekeeper

**Artifact:** XProtect is Apple's built-in malware detection engine. It maintains a signature database and a behavioral rules database. When a file is quarantined or executed, XProtect checks it against these rules. Detection events are written to the XProtect diagnostic files and the XProtect Behavior Service database. GateKeeper enforces code signing and notarization; when it blocks an application, the rejection is logged to `.LastGKReject` as a binary plist.

**What mac_apt XPROTECT does:** Parses XProtect's diagnostic plists and behavior database to extract detection timestamps, matched rule/signature names, and the path of the flagged file — useful for confirming whether the system's built-in defenses detected a threat.

```bash
$MAC_APT XPROTECT -i "$TRIAGE" -o "$OUT/xprotect" -c 2>/dev/null
cat "$OUT/xprotect/"*.csv
```

```bash
# GateKeeper rejection — binary plist, converted to XML
find "$TRIAGE" -name ".LastGKReject" 2>/dev/null | while read f; do
  echo "=== $f ==="
  plistutil -i "$f" -o /dev/stdout 2>/dev/null
done
```

---

## Quick Reference: Key SQLite Databases

| Database | Path in Triage | Key Tables | Notes |
|----------|---------------|-----------|-------|
| KnowledgeC | `Users/<u>/Library/Application-Support/Knowledge/knowledgeC.db` | ZOBJECT | Apple epoch timestamps |
| TCC (user) | `Users/<u>/Library/Application-Support/com.apple.TCC/TCC.db` | access | Unix timestamps |
| TCC (system) | `Library/Application Support/com.apple.TCC/TCC.db` | access | Unix timestamps |
| Safari History | `Users/<u>/Library/Safari/History.db` | history_items, history_visits | Apple epoch timestamps |
| Quarantine | `Users/<u>/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` | LSQuarantineEvent | Apple epoch timestamps |
| Call History | `Users/<u>/Library/Application-Support/CallHistoryDB/CallHistory.storedata` | ZCALLRECORD | Apple epoch timestamps |
| iMessages | `Users/<u>/Library/Messages/chat.db` | message, chat, handle | Apple epoch timestamps |

---

## MITRE ATT&CK — macOS Technique Quick Reference

Map findings to ATT&CK as you go. Each phase of analysis surfaces specific techniques — tag them in your report so detection gaps and control failures are explicit.

### Initial Access / Execution (TA0001 / TA0002)

| Technique ID | Name | macOS Artifact |
|---|---|---|
| T1566 | Phishing | Quarantine DB source URL; Safari history; email attachments |
| T1204.002 | User Execution: Malicious File | Quarantine DB + Unified Log `Successfully spawned` events; `applicationQuit` absence = success |
| T1059.004 | Unix Shell | Bash/zsh scripts in app bundles; reverse shell via `/dev/tcp/` |
| T1059.007 | JavaScript | Browser-based delivery; Safari history + download records |
| T1105 | Ingress Tool Transfer | `curl`/`wget` in shell history; files without quarantine xattr (CLI-downloaded) |

**Evidence chain for T1204.002:** Download timestamp (QuarantineEvents/Safari Downloads.plist) → execution attempts (Unified Log `spawned`/`ASP:` entries) → success = no `applicationQuit` after final spawn.

### Persistence (TA0003)

| Technique ID | Name | macOS Artifact |
|---|---|---|
| T1543.001 | Launch Agent | `~/Library/LaunchAgents/*.plist` |
| T1543.004 | Launch Daemon | `/Library/LaunchDaemons/*.plist` |
| T1547.007 | Re-opened Applications | `~/Library/Preferences/com.apple.loginwindow.plist` `TALAppsToRelaunchAtLogin` |
| T1037.001 | Logon Script (rc.common) | `/etc/rc.common` |
| T1176 | Browser Extension | `~/Library/Application Support/<browser>/Extensions/` |
| T1554 | Compromise Client Software Binary | Modified system binary (check hashes against known-good) |

### Privilege Escalation (TA0004)

| Technique ID | Name | macOS Artifact |
|---|---|---|
| T1068 | Exploitation for Privilege Escalation | Kernel exploit binary, crash logs, panic reports |
| T1548.001 | Setuid/Setgid | `find / -perm -4000` on image |
| T1548.004 | Elevated Execution with Prompt | `AuthorizationExecuteWithPrivileges` in binary strings |
| T1556.002 | Modify PAM | `/etc/pam.d/*` — compare against macOS defaults |
| T1078.003 | Valid Accounts: Local | Account created via DirectoryServices/dscl |

### Defense Evasion (TA0005)

| Technique ID | Name | macOS Artifact |
|---|---|---|
| T1553.001 | GateKeeper Bypass | Missing `com.apple.quarantine` xattr on executable |
| T1564.001 | Hidden Files/Directories | Files/dirs prefixed with `.`; `chflags hidden` |
| T1036.004 | Masquerade Task/Service | LaunchAgent label mimics `com.apple.*`; binary name mimics system process |
| T1070.003 | Clear Command History | Missing/truncated `.zsh_history`, `.bash_history` |
| T1222.002 | File Permission Modification | `chflags`, `chmod` on malware files (strings in binary) |

### Credential Access (TA0006)

| Technique ID | Name | macOS Artifact |
|---|---|---|
| T1056.001 | Keylogging | Kernel kext (`kext_policy` DB), LaunchDaemon pointing to keylogger |
| T1555.001 | Keychain | `security` tool usage in history; keychain DB access in TCC |
| T1539 | Steal Web Session Cookie | Browser cookie DB (`Cookies.binarycookies`) |

### Discovery (TA0007)

| Technique ID | Name | macOS Artifact |
|---|---|---|
| T1082 | System Information Discovery | `sysctl`, `system_profiler` in shell history |
| T1016 | System Network Configuration | `ifconfig`, `networksetup` in shell history |
| T1033 | System Owner/User Discovery | `whoami`, `id`, `dscl` in shell history |
| T1083 | File and Directory Discovery | `ls`, `find` in shell history; FSEvents |

### Lateral Movement (TA0008)

| Technique ID | Name | macOS Artifact |
|---|---|---|
| T1021.004 | SSH | `launchd.log` Bootstrap event; `system.log` USER_PROCESS/DEAD_PROCESS; `known_hosts` |
| T1021.005 | VNC / Screen Sharing | `launchd.log` Bootstrap for `com.apple.screensharing`; ARD logs |

### Collection (TA0009)

| Technique ID | Name | macOS Artifact |
|---|---|---|
| T1560.001 | Archive via Utility | `zip`/`tar` in shell history; FSEvents on archive creation |
| T1113 | Screen Capture | `screencapture` in history; `CGWindowListCreateImage` in binary strings |

### Command and Control (TA0011)

| Technique ID | Name | macOS Artifact |
|---|---|---|
| T1071.001 | Web Protocols | HTTP GET/POST strings in binary; proxy logs |
| T1105 | Ingress Tool Transfer | `curl`/`wget` in shell history; quarantine DB absence on dropped files |
| T1571 | Non-Standard Port | Network connections on unexpected ports (reverse shell ports) |

### Exfiltration (TA0010)

| Technique ID | Name | macOS Artifact |
|---|---|---|
| T1041 | Exfil over C2 | RAT binary with `send`/`recv` socket symbols; keylog file |
| T1048 | Exfil over Alternative Protocol | `scp`/`sftp` in shell history; `known_hosts` entries |

---

## Output Discipline

Analysis output lives inside the case directory at `$CASE/analysis/`. Never write to or modify the triage evidence itself — everything under `$TRIAGE/` is read-only.

```bash
CASE="/cases/<case_name>"   # top-level case directory
TRIAGE="$CASE/<CollectionDir>/<Triage-Subdir>"
OUT="$CASE/analysis"
MAC_USER="<username>"       # primary user account on the Mac
MAC_APT="/opt/mac-apt/bin/python3 /opt/mac-apt/bin/mac_apt_git/mac_apt_artifact_only.py"
```
