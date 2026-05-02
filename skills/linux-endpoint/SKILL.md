# Skill: Linux Endpoint / Velociraptor / EDR Telemetry

## Overview
Use this skill for three related evidence types that share no Windows-specific tools:

- **Linux host forensics** — live or imaged Linux/Unix endpoints (auth logs, bash history,
  cron, systemd, /proc, auditd)
- **Velociraptor collection** — ZIP artifacts from a Velociraptor hunt (Windows or Linux)
- **EDR telemetry exports** — CrowdStrike, SentinelOne, Defender ATP, Carbon Black
  detection/process-tree exports in JSON or CSV format

The tools run first. The LLM reads the output, recognizes suspicious patterns, follows
threads (suspicious process → check bash history, persistence in cron → check file creation
time, EDR process tree → map parent-child chain), and escalates confirmed findings to the IC.

---

## Section A — Linux Host Forensics

### Tool Inventory

| Artifact | Location | Purpose |
|----------|----------|---------|
| Auth log | `/var/log/auth.log` or `/var/log/secure` | SSH logins, sudo, su, PAM events |
| Syslog | `/var/log/syslog` or `/var/log/messages` | General system events |
| Bash history | `/home/<user>/.bash_history`, `/root/.bash_history` | Command history (may be cleared) |
| Auditd log | `/var/log/audit/audit.log` | Syscall-level audit (if configured) |
| Cron | `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/crontabs/` | Scheduled persistence |
| Systemd units | `/etc/systemd/system/`, `/lib/systemd/system/` | Service persistence |
| /proc | `/proc/<pid>/` | Running process details, maps, cmdline |
| /tmp / /dev/shm | | Common staging locations for malware |
| passwd / shadow | `/etc/passwd`, `/etc/shadow` | User accounts, password hashes |
| SSH | `~/.ssh/authorized_keys`, `~/.ssh/known_hosts` | Key-based auth, pivoted-to hosts |
| Loaded modules | `/proc/modules` | Kernel rootkit check |
| SUID/SGID | `find / -perm /6000` | Privilege escalation vectors |

### Execution Workflow

```bash
mkdir -p ./analysis/linux ./exports/linux

CASE_ROOT="/cases/<case_name>/linux_evidence"  # adjust to evidence path

# ── User accounts ──────────────────────────────────────────────────────────
echo "=== Local accounts ===" \
  && cat "$CASE_ROOT/etc/passwd" | awk -F: '$3 >= 1000 {print}' \
  | tee ./analysis/linux/local_users.txt

# UID 0 accounts other than root = backdoor account
awk -F: '$3 == 0 && $1 != "root" {print "UID-0 NON-ROOT:", $0}' \
  "$CASE_ROOT/etc/passwd" | tee ./analysis/linux/uid0_accounts.txt

# Accounts with shell access but no login expected
awk -F: '$7 ~ /(bash|sh|zsh)/ && $3 < 1000 {print "SYSTEM ACCT WITH SHELL:", $0}' \
  "$CASE_ROOT/etc/passwd" | tee ./analysis/linux/system_shell_accounts.txt

# ── SSH activity ────────────────────────────────────────────────────────────
echo "=== Accepted SSH logins ===" \
  && grep -h "Accepted" "$CASE_ROOT/var/log/auth.log" \
       "$CASE_ROOT/var/log/secure" 2>/dev/null \
  | tee ./analysis/linux/ssh_logins.txt

echo "=== Failed SSH logins (top source IPs) ===" \
  && grep -h "Failed password" "$CASE_ROOT/var/log/auth.log" \
       "$CASE_ROOT/var/log/secure" 2>/dev/null \
  | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | head -20 \
  | tee ./analysis/linux/ssh_bruteforce.txt

# Authorized keys added (persistence)
find "$CASE_ROOT" -name "authorized_keys" -exec echo "=== {} ===" \; \
  -exec cat {} \; | tee ./analysis/linux/authorized_keys.txt

# ── Bash history ─────────────────────────────────────────────────────────────
find "$CASE_ROOT" -name ".bash_history" 2>/dev/null | while read -r f; do
    user=$(echo "$f" | grep -oP '/home/\K[^/]+' || echo "root")
    echo "=== $user bash history ==="
    cat "$f"
done | tee ./analysis/linux/bash_history_all.txt

# High-value command patterns in history
grep -Eh '(wget|curl|nc |netcat|python.*-c|perl.*-e|chmod \+x|base64|/tmp/|/dev/shm|scp |ssh -|sudo|su -|useradd|usermod|crontab|systemctl|/etc/passwd|/etc/shadow|iptables|ufw)' \
  ./analysis/linux/bash_history_all.txt \
  | tee ./analysis/linux/bash_history_suspicious.txt

echo "Suspicious commands: $(wc -l < ./analysis/linux/bash_history_suspicious.txt)"

# ── Persistence ─────────────────────────────────────────────────────────────
echo "=== System crontab ===" && cat "$CASE_ROOT/etc/crontab" 2>/dev/null
echo "=== Cron.d entries ===" && ls -la "$CASE_ROOT/etc/cron.d/" 2>/dev/null \
  && cat "$CASE_ROOT/etc/cron.d/"* 2>/dev/null
echo "=== User crontabs ===" \
  && find "$CASE_ROOT/var/spool/cron" -type f 2>/dev/null -exec echo "---{}---" \; -exec cat {} \; \
  | tee ./analysis/linux/cron_all.txt

# Systemd units not from package manager (custom = suspicious)
find "$CASE_ROOT/etc/systemd/system/" -name "*.service" 2>/dev/null \
  | xargs grep -l "ExecStart" 2>/dev/null \
  | while read -r svc; do
      echo "=== $svc ==="; cat "$svc"
    done | tee ./analysis/linux/systemd_custom_services.txt

# ── Staging locations ──────────────────────────────────────────────────────
echo "=== Files in /tmp ===" \
  && find "$CASE_ROOT/tmp" -type f 2>/dev/null \
  | xargs -I{} sh -c 'echo "{}"; file "{}"; sha256sum "{}"' \
  | tee ./analysis/linux/tmp_files.txt

echo "=== Files in /dev/shm ===" \
  && find "$CASE_ROOT/dev/shm" -type f 2>/dev/null \
  | xargs -I{} sh -c 'echo "{}"; file "{}"; sha256sum "{}"' \
  | tee ./analysis/linux/devshm_files.txt

# ── SUID/SGID binaries (privilege escalation) ─────────────────────────────
find "$CASE_ROOT" -perm /6000 -type f 2>/dev/null \
  | grep -v -E '^/proc' \
  | xargs ls -la 2>/dev/null \
  | tee ./analysis/linux/suid_sgid_binaries.txt

# Unexpected SUID (compare against known-good SUID set)
KNOWN_SUID="ping|sudo|su|passwd|chsh|chfn|newgrp|mount|umount|fusermount|pkexec"
grep -v -E "$KNOWN_SUID" ./analysis/linux/suid_sgid_binaries.txt \
  | tee ./analysis/linux/suid_unexpected.txt

# ── Recently modified files (attack window) ───────────────────────────────
# Adjust -mtime window to match attack timeline
find "$CASE_ROOT" -not -path "*/proc/*" -not -path "*/sys/*" \
  -newer "$CASE_ROOT/etc/passwd" -type f 2>/dev/null \
  | grep -v -E '\.(log|journal)$' \
  | head -100 | tee ./analysis/linux/recently_modified.txt
```

### Finding Recognition

| Pattern | Indicator | Severity |
|---------|-----------|----------|
| UID 0 account other than root | Backdoor account | High |
| System account with bash/sh shell | Account modification for persistence | High |
| `authorized_keys` file with unfamiliar key | SSH key persistence | High |
| `/tmp` or `/dev/shm` executable | Staged malware | High |
| Cron job running from `/tmp` or curl/wget | Download cradle persistence | High |
| Custom systemd service pointing to `/tmp` | Service-based persistence | High |
| Bash history contains base64 decode + execute | Encoded payload execution | High |
| Unexpected SUID binary | LPE vector installed by attacker | High |
| `wget`/`curl` in bash history followed by `chmod +x` + execution | Malware download + run | High |
| SSH brute force (>100 failed from same IP) + subsequent success | Successful credential attack | High |

---

## Section B — Velociraptor Collection Analysis

Velociraptor collections arrive as ZIP files containing JSON artifact results.

```bash
mkdir -p ./exports/velociraptor ./analysis/velociraptor

VR_ZIP="/cases/<case_name>/<collection>.zip"

# Extract collection
unzip -q "$VR_ZIP" -d ./exports/velociraptor/
find ./exports/velociraptor/ -name "*.json" | sort \
  | tee ./analysis/velociraptor/artifact_inventory.txt

echo "Artifacts collected: $(wc -l < ./analysis/velociraptor/artifact_inventory.txt)"

# ── Process list ──────────────────────────────────────────────────────────
VR_PSLIST=$(find ./exports/velociraptor -name "*Pslist*" -o -name "*Process*" 2>/dev/null | head -1)
if [[ -n "$VR_PSLIST" ]]; then
    jq -r '[.Pid, .PPid, .Name, .Exe, .CommandLine, .Username, .CreateTime] | @csv' \
      "$VR_PSLIST" 2>/dev/null | tee ./analysis/velociraptor/processes.csv
    echo "Processes: $(wc -l < ./analysis/velociraptor/processes.csv)"
    
    # Suspicious process paths (not in system dirs)
    jq -r 'select(.Exe | test("\\\\(Temp|AppData|Users|ProgramData|Windows\\\\Tasks)"; "i")) |
           [.Pid, .PPid, .Name, .Exe, .CommandLine, .Username] | @csv' \
      "$VR_PSLIST" 2>/dev/null | tee ./analysis/velociraptor/processes_suspicious.csv
fi

# ── Network connections ───────────────────────────────────────────────────
VR_NET=$(find ./exports/velociraptor -name "*Netstat*" -o -name "*Network*" 2>/dev/null | head -1)
if [[ -n "$VR_NET" ]]; then
    jq -r '[.Pid, .Status, .LocalAddr, .RemoteAddr, .Timestamp] | @csv' \
      "$VR_NET" 2>/dev/null | tee ./analysis/velociraptor/netstat.csv
    
    # External connections
    jq -r 'select(.RemoteAddr | test("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.0\\.0\\.1)") | not) |
           select(.Status == "ESTABLISHED") |
           [.Pid, .Status, .LocalAddr, .RemoteAddr] | @csv' \
      "$VR_NET" 2>/dev/null | tee ./analysis/velociraptor/external_connections.csv
fi

# ── Persistence (Run keys, scheduled tasks, services) ─────────────────────
find ./exports/velociraptor -name "*RunKey*" -o -name "*Autorun*" \
  -o -name "*ScheduledTask*" -o -name "*Services*" 2>/dev/null \
  | while read -r f; do
      echo "=== $f ==="; jq -r '.[] | @json' "$f" 2>/dev/null | head -50
    done | tee ./analysis/velociraptor/persistence.txt

# ── Event log artifacts ───────────────────────────────────────────────────
find ./exports/velociraptor -name "*EventLog*" -o -name "*Evtx*" 2>/dev/null \
  | while read -r f; do
      echo "=== $f ===" ; wc -l "$f"
    done | tee ./analysis/velociraptor/eventlog_inventory.txt

# ── File timeline ─────────────────────────────────────────────────────────
VR_MFT=$(find ./exports/velociraptor -name "*MFT*" -o -name "*FileFinder*" 2>/dev/null | head -1)
if [[ -n "$VR_MFT" ]]; then
    jq -r '[.Created0x10, .FullPath, .FileSize, .InUse] | @csv' \
      "$VR_MFT" 2>/dev/null | sort | tee ./analysis/velociraptor/file_timeline.csv
fi
```

---

## Section C — EDR Telemetry Analysis

EDR exports arrive as JSON or CSV. The workflows below handle CrowdStrike, SentinelOne,
and Defender ATP exports. Adapt field names as needed — all three follow similar schemas.

```bash
mkdir -p ./analysis/edr

EDR_EXPORT="/cases/<case_name>/edr_export.json"  # or .csv

# ── CrowdStrike process tree (JSON) ──────────────────────────────────────
# Fields: timestamp, aid, event_type, ImageFileName, CommandLine,
#         ParentImageFileName, ParentCommandLine, UserName, SHA256HashData

jq -r 'select(.event_type == "ProcessRollup2") |
       [.timestamp, .UserName, .ImageFileName, .CommandLine,
        .ParentImageFileName, .SHA256HashData] | @csv' \
  "$EDR_EXPORT" 2>/dev/null | tee ./analysis/edr/process_tree.csv

# Suspicious process paths
jq -r 'select(.event_type == "ProcessRollup2") |
       select(.ImageFileName | test("\\\\(Temp|AppData|Users\\\\[^\\\\]+\\\\AppData|ProgramData|Windows\\\\Tasks)"; "i")) |
       [.timestamp, .UserName, .ImageFileName, .CommandLine, .ParentImageFileName] | @csv' \
  "$EDR_EXPORT" 2>/dev/null | tee ./analysis/edr/suspicious_processes.csv

# Network connections from EDR
jq -r 'select(.event_type == "NetworkConnectIP4") |
       select(.RemoteAddressIP4 | test("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.)") | not) |
       [.timestamp, .ImageFileName, .LocalAddressIP4, .LocalPort,
        .RemoteAddressIP4, .RemotePort, .Protocol] | @csv' \
  "$EDR_EXPORT" 2>/dev/null | tee ./analysis/edr/network_external.csv

# File write events (malware drop or staging)
jq -r 'select(.event_type == "DocumentFileChangeInfo" or .event_type == "WriteFile") |
       select(.TargetFileName | test("\\\\(Temp|AppData|ProgramData|Windows\\\\Tasks)"; "i")) |
       [.timestamp, .ImageFileName, .TargetFileName, .UserName] | @csv' \
  "$EDR_EXPORT" 2>/dev/null | tee ./analysis/edr/suspicious_writes.csv

# ── Build parent-child chain from EDR ────────────────────────────────────
# Find process IDs that match known-suspicious images, then walk upward
python3 - <<'EOF'
import json, sys
from collections import defaultdict

events = []
for line in open(sys.argv[1]):
    try:
        events.append(json.loads(line.strip()))
    except:
        pass

processes = {e.get('ContextProcessId_decimal'): e
             for e in events if e.get('event_type') == 'ProcessRollup2'}

def chain(pid, depth=0):
    p = processes.get(pid)
    if not p or depth > 10:
        return
    indent = "  " * depth
    print(f"{indent}[{p.get('timestamp','')}] {p.get('ImageFileName','?')} "
          f"(PID:{pid}) CMD: {p.get('CommandLine','')[:120]}")
    chain(p.get('ParentProcessId_decimal'), depth+1)

suspicious = [pid for pid, p in processes.items()
              if any(s in (p.get('ImageFileName') or '').lower()
                     for s in ['cmd.exe','powershell','wscript','mshta','regsvr32',
                                'certutil','bitsadmin','temp','appdata'])]

print(f"Suspicious process chains ({len(suspicious)} roots):")
for pid in suspicious[:20]:
    chain(pid)
    print()
EOF
"$EDR_EXPORT" 2>/dev/null | tee ./analysis/edr/process_chains.txt
```

---

## Finding Recognition — Cross-Section

| Pattern | Section | Indicator | Severity |
|---------|---------|-----------|----------|
| UID 0 non-root account | Linux | Backdoor root account | High |
| `/tmp` or `/dev/shm` executable | Linux | Staged malware | High |
| SSH authorized_keys addition | Linux | Persistence via SSH key | High |
| Custom cron/systemd running from temp path | Linux | Persistence mechanism | High |
| Velociraptor process from non-system path | Velociraptor | Suspicious execution | High |
| Velociraptor external ESTABLISHED connection | Velociraptor | Live C2 connection | High |
| EDR process writing to AppData/Temp | EDR | Malware drop | High |
| EDR process chain: Office → PowerShell → cmd | EDR | Phishing execution chain | High |
| EDR external connection from `powershell.exe` | EDR | PowerShell C2 | High |

---

## In-Skill Pivot Protocol

| Finding | Follow-up within this skill |
|---------|-----------------------------|
| Suspicious file in `/tmp` or `/dev/shm` | Hash it and run strings; if PE/ELF, hand to malware-analysis |
| bash history cleared (file empty or missing) | Flag anti-forensics; check auth.log for timing of clearing |
| Velociraptor process at suspicious path | Cross-check against file_timeline.csv for creation time |
| EDR process chain ending in suspicious leaf | Build full chain with parent-child script; identify entry point |
| New SSH authorized_key added | Check auth.log for first login using that key; correlate to attack window |

---

## Escalation to IC (cross-skill pivots)

| Finding | IC pivot |
|---------|---------|
| Staged binary in `/tmp` or `/dev/shm` | IC tasks malware-analysis |
| External IP from Velociraptor netstat | IC adds to IOC master; network-analysis cross-ref |
| EDR network connection to suspicious IP | IC adds to IOC master; network-analysis verifies in PCAP |
| New root account or SSH key | IC updates Credential Access / Persistence in COP |
| Phishing execution chain confirmed (EDR) | IC records ATT&CK Initial Access + Execution techniques |
| Lateral movement artifact (SSH known_hosts, net connections to internal IPs) | IC expands scope to pivot targets |

---

## Output Paths

| Output | Path |
|--------|------|
| Linux user accounts | `./analysis/linux/local_users.txt`, `uid0_accounts.txt` |
| SSH logins / brute force | `./analysis/linux/ssh_logins.txt`, `ssh_bruteforce.txt` |
| Bash history (all users) | `./analysis/linux/bash_history_all.txt`, `_suspicious.txt` |
| Persistence (cron, systemd) | `./analysis/linux/cron_all.txt`, `systemd_custom_services.txt` |
| Staging locations | `./analysis/linux/tmp_files.txt`, `devshm_files.txt` |
| SUID/SGID | `./analysis/linux/suid_sgid_binaries.txt`, `suid_unexpected.txt` |
| Velociraptor processes | `./analysis/velociraptor/processes.csv`, `processes_suspicious.csv` |
| Velociraptor network | `./analysis/velociraptor/external_connections.csv` |
| Velociraptor persistence | `./analysis/velociraptor/persistence.txt` |
| EDR process chains | `./analysis/edr/process_chains.txt` |
| EDR suspicious processes | `./analysis/edr/suspicious_processes.csv` |
| EDR network external | `./analysis/edr/network_external.csv` |

---

## Notes

- Bash history is easily cleared — absence of `.bash_history` is itself a finding; note it in COP
- Velociraptor field names vary by artifact and version — always check the actual JSON keys before filtering
- EDR exports from different vendors use different field names (CrowdStrike: `ImageFileName`; SentinelOne: `ProcessName`; Defender ATP: `FileName`) — adapt `jq` filters accordingly
- For auditd logs, use `ausearch -i` for human-readable output: `ausearch -i --start <date> --end <date>`
- Linux malware frequently stages in `/dev/shm` because it is tmpfs (RAM-backed, no disk writes) — always check it
