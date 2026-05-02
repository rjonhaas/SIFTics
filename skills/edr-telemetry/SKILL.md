# Skill: EDR Telemetry & Live Hunt Collections

## Overview
Use this skill when evidence arrives as a **Velociraptor collection ZIP** or an **EDR export**
(CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint / Defender ATP, Carbon Black).
These are platform-agnostic collection mechanisms — they run on Windows, Linux, and macOS.

The tools run first. The LLM reads the output, maps process trees to ATT&CK techniques,
identifies C2 connections and malware drops, and follows threads (suspicious leaf process →
build full parent chain, EDR network connection → cross-ref with PCAP, Velociraptor
persistence artifact → check against windows-artifacts autoruns) before escalating to the IC.

**This skill does NOT cover:**
- Linux host forensics from raw filesystem evidence → use `linux-host`
- Windows disk artifacts from KAPE collections → use `windows-artifacts`
- Raw PCAP / Zeek logs → use `network-analysis`

---

## Section A — Velociraptor Collection Analysis

Velociraptor collections arrive as ZIP files containing JSON artifact results. Artifact
names follow the pattern `Windows.System.Pslist`, `Linux.Sys.BashHistory`, etc.

```bash
mkdir -p ./exports/velociraptor ./analysis/velociraptor

VR_ZIP="/cases/<case_name>/<collection>.zip"

# Extract collection
unzip -q "$VR_ZIP" -d ./exports/velociraptor/

# Inventory: list all artifact JSON files and their sizes
find ./exports/velociraptor/ -name "*.json" -o -name "*.jsonl" | sort \
  | xargs wc -l 2>/dev/null | sort -rn | head -30 \
  | tee ./analysis/velociraptor/artifact_inventory.txt

echo "Total artifacts: $(find ./exports/velociraptor/ -name '*.json' -o -name '*.jsonl' | wc -l)"

# ── Process list ──────────────────────────────────────────────────────────
VR_PSLIST=$(find ./exports/velociraptor \
  -name "*Pslist*" -o -name "*Process*" -o -name "*process_list*" 2>/dev/null | head -1)

if [[ -n "$VR_PSLIST" ]]; then
    echo "Process list: $VR_PSLIST"
    jq -r '[.Pid, .PPid, .Name, .Exe, .CommandLine, .Username, .CreateTime] | @csv' \
      "$VR_PSLIST" 2>/dev/null | tee ./analysis/velociraptor/processes.csv
    echo "Processes: $(wc -l < ./analysis/velociraptor/processes.csv)"

    # Suspicious: paths outside System32, Program Files, ProgramData (Windows)
    jq -r 'select(.Exe | test("(\\\\Temp|\\\\AppData|\\\\Users\\\\[^\\\\]+\\\\AppData|\\\\ProgramData|\\\\Windows\\\\Tasks|/tmp/|/dev/shm)"; "i")) |
           [.Pid, .PPid, .Name, .Exe, .CommandLine, .Username, .CreateTime] | @csv' \
      "$VR_PSLIST" 2>/dev/null | tee ./analysis/velociraptor/processes_suspicious.csv

    echo "Suspicious processes: $(wc -l < ./analysis/velociraptor/processes_suspicious.csv)"
fi

# ── Network connections ───────────────────────────────────────────────────
VR_NET=$(find ./exports/velociraptor \
  -name "*Netstat*" -o -name "*Network*" -o -name "*netstat*" 2>/dev/null | head -1)

if [[ -n "$VR_NET" ]]; then
    jq -r '[.Pid, .Status, .LocalAddr, .RemoteAddr, .ProcessName, .Timestamp] | @csv' \
      "$VR_NET" 2>/dev/null | tee ./analysis/velociraptor/netstat.csv

    # External ESTABLISHED connections (exclude RFC1918 + loopback)
    jq -r 'select(.Status == "ESTABLISHED") |
           select(.RemoteAddr |
             test("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|::1)") | not) |
           [.Pid, .Status, .LocalAddr, .RemoteAddr, .ProcessName] | @csv' \
      "$VR_NET" 2>/dev/null | tee ./analysis/velociraptor/external_connections.csv

    echo "External connections: $(wc -l < ./analysis/velociraptor/external_connections.csv)"
fi

# ── Persistence ─────────────────────────────────────────────────────────────
for artifact in RunKey Autorun ScheduledTask Services CronJob SystemdUnit; do
    found=$(find ./exports/velociraptor -iname "*${artifact}*" 2>/dev/null | head -1)
    if [[ -n "$found" ]]; then
        echo "=== $artifact: $found ==="
        jq -r '.' "$found" 2>/dev/null | head -100
    else
        echo "No ${artifact} artifacts found in collection"
    fi
done | tee ./analysis/velociraptor/persistence.txt

# ── Event log artifacts ───────────────────────────────────────────────────
find ./exports/velociraptor -iname "*EventLog*" -o -iname "*Evtx*" 2>/dev/null \
  | while read -r f; do echo "=== $f ==="; wc -l "$f"; done \
  | tee ./analysis/velociraptor/eventlog_inventory.txt

# ── File timeline (MFT / FileFinder) ─────────────────────────────────────
VR_MFT=$(find ./exports/velociraptor \
  -iname "*MFT*" -o -iname "*FileFinder*" -o -iname "*file_finder*" 2>/dev/null | head -1)

if [[ -n "$VR_MFT" ]]; then
    jq -r '[.Created0x10, .Modified0x10, .FullPath, .FileSize, .InUse] | @csv' \
      "$VR_MFT" 2>/dev/null | sort | tee ./analysis/velociraptor/file_timeline.csv
    echo "File timeline rows: $(wc -l < ./analysis/velociraptor/file_timeline.csv)"

    # Files created/modified in attack window — adjust dates
    # Set INCIDENT_START to the beginning of the attack window (YYYY-MM-DD)
    INCIDENT_START="${INCIDENT_START:-2025-01-01}"
    jq -r --arg start "$INCIDENT_START" 'select(.Created0x10 >= $start) |
           [.Created0x10, .Modified0x10, .FullPath, .FileSize] | @csv' \
      "$VR_MFT" 2>/dev/null | tee ./analysis/velociraptor/file_timeline_incident.csv
fi

# ── Loaded DLLs (Windows) ─────────────────────────────────────────────────
VR_DLL=$(find ./exports/velociraptor -iname "*Dll*" -o -iname "*Modules*" 2>/dev/null | head -1)
if [[ -n "$VR_DLL" ]]; then
    # DLLs loaded from non-standard paths
    jq -r 'select(.FullPath | test("(Temp|AppData|ProgramData|\\\\Users\\\\)"; "i")) |
           [.Pid, .ProcessName, .FullPath, .InMemory] | @csv' \
      "$VR_DLL" 2>/dev/null | tee ./analysis/velociraptor/dll_suspicious.csv
fi
```

---

## Section B — EDR Telemetry Analysis

EDR exports arrive as JSON (one event per line) or CSV. The field names differ across
vendors — use the mapping table before writing `jq` or `awk` filters.

### Vendor Field Mapping

| Concept | CrowdStrike Falcon | SentinelOne | Defender for Endpoint (MDE) | Carbon Black |
|---------|-------------------|-------------|----------------------------|--------------|
| Process image | `ImageFileName` | `ProcessName` | `FileName` / `InitiatingProcessFileName` | `process_name` |
| Command line | `CommandLine` | `CmdLine` | `ProcessCommandLine` | `cmdline` |
| Parent image | `ParentImageFileName` | `ParentProcessName` | `InitiatingProcessFileName` | `parent_name` |
| Parent cmdline | `ParentCommandLine` | `ParentCmdLine` | `InitiatingProcessCommandLine` | `parent_cmdline` |
| Process ID | `ContextProcessId_decimal` | `Pid` | `ProcessId` | `process_pid` |
| Parent PID | `ParentProcessId_decimal` | `ParentPid` | `InitiatingProcessId` | `parent_pid` |
| Username | `UserName` | `User` | `AccountName` | `username` |
| SHA256 hash | `SHA256HashData` | `Md5` / `Sha256` | `SHA256` | `md5` |
| Timestamp | `timestamp` | `CreatedAt` | `Timestamp` | `timestamp` |
| Event type | `event_type` | `EventType` | (table name) | `type` |
| Remote IP | `RemoteAddressIP4` | `RemoteIp` | `RemoteIP` | `remote_ip` |
| Remote port | `RemotePort` | `RemotePort` | `RemotePort` | `remote_port` |
| File written | `TargetFileName` | `FilePath` | `FileName` (FileCreated table) | `file_path` |

### CrowdStrike Falcon (JSON Lines)

```bash
EDR_EXPORT="/cases/<case_name>/crowdstrike_export.json"
mkdir -p ./analysis/edr

# Process tree (ProcessRollup2 events)
jq -r 'select(.event_type == "ProcessRollup2") |
       [.timestamp, .UserName, .ImageFileName, .CommandLine,
        .ParentImageFileName, .SHA256HashData] | @csv' \
  "$EDR_EXPORT" 2>/dev/null | tee ./analysis/edr/cs_process_tree.csv

echo "Process events: $(wc -l < ./analysis/edr/cs_process_tree.csv)"

# Suspicious process paths (temp/user-writable directories)
jq -r 'select(.event_type == "ProcessRollup2") |
       select(.ImageFileName | test("\\\\(Temp|AppData|ProgramData|Windows\\\\Tasks|Users\\\\[^\\\\]+\\\\AppData)"; "i")) |
       [.timestamp, .UserName, .ImageFileName, .CommandLine, .ParentImageFileName, .SHA256HashData] | @csv' \
  "$EDR_EXPORT" 2>/dev/null | tee ./analysis/edr/cs_suspicious_processes.csv

# External network connections
jq -r 'select(.event_type == "NetworkConnectIP4") |
       select(.RemoteAddressIP4 |
         test("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.)") | not) |
       [.timestamp, .ImageFileName, .LocalAddressIP4, .LocalPort,
        .RemoteAddressIP4, .RemotePort, .Protocol] | @csv' \
  "$EDR_EXPORT" 2>/dev/null | tee ./analysis/edr/cs_network_external.csv

# File writes to staging locations
jq -r 'select(.event_type == "DocumentFileChangeInfo" or .event_type == "WriteFile") |
       select(.TargetFileName | test("\\\\(Temp|AppData|ProgramData|Windows\\\\Tasks)"; "i")) |
       [.timestamp, .ImageFileName, .TargetFileName, .UserName] | @csv' \
  "$EDR_EXPORT" 2>/dev/null | tee ./analysis/edr/cs_suspicious_writes.csv

echo "Suspicious writes: $(wc -l < ./analysis/edr/cs_suspicious_writes.csv)"
```

### SentinelOne (JSON or CSV)

```bash
S1_EXPORT="/cases/<case_name>/s1_export.json"

# Process events
jq -r 'select(.EventType == "Process Creation" or .type == "process") |
       [.CreatedAt, .User, .ProcessName, .CmdLine,
        .ParentProcessName, .ParentCmdLine, .Sha256] | @csv' \
  "$S1_EXPORT" 2>/dev/null | tee ./analysis/edr/s1_processes.csv

# Suspicious paths
jq -r 'select(.EventType == "Process Creation") |
       select(.ProcessName | test("(Temp|AppData|ProgramData|Tasks)"; "i")) |
       [.CreatedAt, .User, .ProcessName, .CmdLine, .ParentProcessName] | @csv' \
  "$S1_EXPORT" 2>/dev/null | tee ./analysis/edr/s1_suspicious_processes.csv

# Network connections
jq -r 'select(.EventType == "IP Connect" or .type == "network") |
       select(.RemoteIp |
         test("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.)") | not) |
       [.CreatedAt, .ProcessName, .LocalIp, .RemoteIp, .RemotePort] | @csv' \
  "$S1_EXPORT" 2>/dev/null | tee ./analysis/edr/s1_network_external.csv
```

### Microsoft Defender for Endpoint / MDE (Advanced Hunting CSV export)

```bash
MDE_PROCS="/cases/<case_name>/mde_DeviceProcessEvents.csv"
MDE_NET="/cases/<case_name>/mde_DeviceNetworkEvents.csv"
MDE_FILES="/cases/<case_name>/mde_DeviceFileEvents.csv"

# Process events — filter to suspicious paths
awk -F',' 'NR==1 || tolower($0) ~ /(\\temp\\|\\appdata\\|\\programdata\\|\\tasks\\)/' \
  "$MDE_PROCS" 2>/dev/null | tee ./analysis/edr/mde_suspicious_processes.csv

# External network connections
awk -F',' 'NR==1' "$MDE_NET" > ./analysis/edr/mde_network_external.csv 2>/dev/null
awk -F',' 'NR>1 && $0 !~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/' \
  "$MDE_NET" 2>/dev/null >> ./analysis/edr/mde_network_external.csv

# File writes to staging locations
awk -F',' 'NR==1 || tolower($0) ~ /(\\temp\\|\\appdata\\|\\programdata\\|\\tasks\\)/' \
  "$MDE_FILES" 2>/dev/null | tee ./analysis/edr/mde_suspicious_writes.csv

echo "MDE process hits: $(wc -l < ./analysis/edr/mde_suspicious_processes.csv)"
echo "MDE external network: $(wc -l < ./analysis/edr/mde_network_external.csv)"
```

### Parent-Chain Builder (all vendors)

```bash
# Adapt field names for non-CrowdStrike vendors — see Vendor Field Mapping table above.
# Set EDR_EXPORT to the correct vendor export path before running.
(python3 - "$EDR_EXPORT" <<'EOF'
import json, sys
from collections import defaultdict

events = []
source_file = sys.argv[1]
for line in open(source_file):
    line = line.strip()
    if not line:
        continue
    try:
        events.append(json.loads(line))
    except json.JSONDecodeError:
        pass

# Build process table (CrowdStrike field names — adjust for other vendors)
processes = {}
for e in events:
    if e.get('event_type') != 'ProcessRollup2':
        continue
    pid = e.get('ContextProcessId_decimal')
    if pid:
        processes[pid] = e

def chain(pid, depth=0, seen=None):
    if seen is None:
        seen = set()
    if pid in seen or depth > 15:
        return
    seen.add(pid)
    p = processes.get(pid)
    if not p:
        return
    indent = "  " * depth
    ts = p.get('timestamp', '')
    img = p.get('ImageFileName', '?').split('\\')[-1]
    cmd = (p.get('CommandLine') or '')[:120]
    print(f"{indent}[{ts}] {img} (PID:{pid})")
    if cmd:
        print(f"{indent}  CMD: {cmd}")
    chain(p.get('ParentProcessId_decimal'), depth + 1, seen)

SUSPICIOUS_TERMS = [
    'cmd.exe', 'powershell', 'wscript', 'cscript', 'mshta', 'regsvr32',
    'certutil', 'bitsadmin', 'rundll32', 'msiexec', 'wmic',
    '\\temp\\', '\\appdata\\', 'programdata',
]

suspicious_pids = [
    pid for pid, p in processes.items()
    if any(s in (p.get('ImageFileName') or '').lower() or
           s in (p.get('CommandLine') or '').lower()
           for s in SUSPICIOUS_TERMS)
]

print(f"Suspicious process chains ({len(suspicious_pids)} roots):\n")
for pid in list(dict.fromkeys(suspicious_pids))[:30]:
    chain(pid)
    print()
EOF
) | tee ./analysis/edr/process_chains.txt
```

---

## Finding Recognition

| Pattern | Source | Indicator | Severity |
|---------|--------|-----------|----------|
| Process from `\Temp\` / `\AppData\` / `/tmp/` | Velociraptor / EDR | Malware execution from staging path | High |
| `Office` → `PowerShell` → `cmd.exe` chain | EDR | Phishing execution chain (T1566) | High |
| `w3wp.exe` spawning `cmd.exe` / `powershell.exe` | EDR | Webshell execution (T1505.003) | High |
| External ESTABLISHED connection from `powershell.exe` | Velociraptor / EDR | PowerShell C2 (T1059.001) | High |
| File write to `\Temp\` or `\AppData\` by `cmd.exe` child | EDR | Malware drop (T1105) | High |
| Velociraptor: external connection from non-browser process | Velociraptor | C2 beaconing candidate | High |
| Scheduled task pointing to `\Temp\` or `\AppData\` | Velociraptor | Persistence via scheduled task (T1053.005) | High |
| Process with no parent (orphaned) | EDR | Process injection / hollowing (T1055) | High |
| Signed binary (certutil, msiexec) with download URL in cmdline | EDR | LOLBIN download cradle (T1105) | High |
| DLL loaded from `\AppData\` or `\Temp\` | Velociraptor | DLL sideloading / hijacking (T1574.001 / T1574.002) — use T1574.001 for search-order manipulation, T1574.002 for sideloading via legitimate app | High |
| `lsass.exe` accessed by non-OS process | EDR | Credential dumping (T1003.001) | Critical |

---

## In-Skill Pivot Protocol

| Finding | Follow-up within this skill |
|---------|-----------------------------|
| Suspicious process in process_chains.txt | Build full chain; identify root entry point (first process not in known-OS set) |
| External connection from EDR | Check if same IP appears in Velociraptor `external_connections.csv`; add to IOC list |
| File written by suspicious process | Check file path against `file_timeline.csv` for creation time; hash the file |
| Scheduled task or run key in Velociraptor | Cross-check path against `processes_suspicious.csv` to confirm execution |
| Orphaned process (no parent in table) | Indicates injection or hollowing — flag for `malware-analysis` with process image |
| DLL from non-standard path | Extract path; check `file_timeline.csv` for creation time; hand hash to `yara-hunting` |

---

## Escalation to IC (cross-skill pivots)

Classify each escalated finding as CONFIRMED, INFERRED, or CONTRADICTED per the IC Finding Taxonomy (≥2 independent artefact types = CONFIRMED; 1–2 sources = INFERRED) before writing to the COP.

| Finding | IC pivot |
|---------|---------|
| Confirmed process from staging path | IC tasks `malware-analysis` with file path or process dump |
| External IP or domain from EDR/Velociraptor | IC adds to IOC master; `network-analysis` cross-refs in PCAP |
| Scheduled task / run key at suspicious path | IC tasks `windows-artifacts` to confirm on-disk artifact in registry/task XML |
| Phishing execution chain confirmed | IC records T1566 + T1059 in COP; possible `yara-hunting` for matching dropper |
| lsass.exe access confirmed | IC updates Credential Access in COP; checks for DCSync in windows-artifacts |
| Lateral movement connection to internal IP | IC expands scope to destination host |
| Webshell execution chain (`w3wp.exe` parent) | IC tasks `windows-artifacts` webserver phase for IIS log corroboration |

---

## Output Paths

| Output | Path |
|--------|------|
| Velociraptor artifact inventory | `./analysis/velociraptor/artifact_inventory.txt` |
| Velociraptor processes (all / suspicious) | `./analysis/velociraptor/processes.csv`, `processes_suspicious.csv` |
| Velociraptor external connections | `./analysis/velociraptor/external_connections.csv` |
| Velociraptor persistence | `./analysis/velociraptor/persistence.txt` |
| Velociraptor file timeline | `./analysis/velociraptor/file_timeline.csv`, `file_timeline_incident.csv` |
| Velociraptor DLLs from non-standard paths | `./analysis/velociraptor/dll_suspicious.csv` |
| CrowdStrike process tree / suspicious / network / writes | `./analysis/edr/cs_*.csv` |
| SentinelOne process / network | `./analysis/edr/s1_*.csv` |
| MDE process / network / file | `./analysis/edr/mde_*.csv` |
| Parent-chain reconstruction | `./analysis/edr/process_chains.txt` |

---

## Notes

- Velociraptor JSON field names vary by artifact version — always inspect one record first with `jq '.' <file> | head -30` before writing filters
- CrowdStrike exports may use either decimal PIDs (`ContextProcessId_decimal`) or hex (`ContextProcessId`) — check the first record and adapt
- SentinelOne exports sometimes arrive as CSV rather than JSON — check `file` output and use `awk -F','` rather than `jq` if so
- MDE Advanced Hunting exports are always CSV; column names match the KQL table schema
- For Carbon Black, event types are: `process`, `netconn`, `filemod`, `regmod` — adapt the `select(.type == ...)` filters
- Process chain depth of >10 levels from a browser or Office app to `cmd.exe` is almost always malicious
- `lsass.exe` access by any process other than `werfault.exe`, `csrss.exe`, or security products is a critical finding regardless of other context
