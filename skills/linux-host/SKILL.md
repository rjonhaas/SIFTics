# Skill: Linux Host Forensics

## Overview
Use this skill for live or imaged Linux/Unix endpoints. The tools run first — they produce
ground truth from the filesystem, logs, and running process state. The LLM reads the output,
recognizes suspicious patterns, follows threads (suspicious cron job → check file creation
time, bash history cleared → check auth.log for timing, SUID binary → check owner and mtime),
and escalates confirmed findings to the IC.

**This skill covers the Linux host itself.** For Velociraptor collections or EDR telemetry
exports (CrowdStrike, SentinelOne, Defender ATP), use the `edr-telemetry` skill instead.

---

## Tool Inventory

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
| Loaded modules | `/proc/modules`, `lsmod` output | Kernel rootkit check |
| SUID/SGID | `find $CASE_ROOT -perm /6000` | Privilege escalation vectors |

---

## Execution Workflow

```bash
mkdir -p ./analysis/linux ./exports/linux

CASE_ROOT="/cases/<case_name>/linux_evidence"  # adjust to evidence path

# ── User accounts ──────────────────────────────────────────────────────────
echo "=== Local accounts (UID ≥ 1000) ===" \
  && awk -F: '$3 >= 1000 {print}' "$CASE_ROOT/etc/passwd" \
  | tee ./analysis/linux/local_users.txt

# UID 0 accounts other than root = backdoor account
awk -F: '$3 == 0 && $1 != "root" {print "UID-0 NON-ROOT:", $0}' \
  "$CASE_ROOT/etc/passwd" | tee ./analysis/linux/uid0_accounts.txt

# System accounts with interactive shell access (should not have one)
awk -F: '$7 ~ /(bash|sh|zsh|fish)/ && $3 < 1000 {print "SYSTEM ACCT WITH SHELL:", $0}' \
  "$CASE_ROOT/etc/passwd" | tee ./analysis/linux/system_shell_accounts.txt

# Password hash algorithm (check for weak MD5 $1$ or DES hashes)
awk -F: 'NF >= 2 && $2 !~ /^[!*]/ {print $1, $2}' \
  "$CASE_ROOT/etc/shadow" 2>/dev/null | tee ./analysis/linux/shadow_hashes.txt

# ── SSH activity ────────────────────────────────────────────────────────────
echo "=== Accepted SSH logins ===" \
  && grep -h "Accepted" \
       "$CASE_ROOT/var/log/auth.log" \
       "$CASE_ROOT/var/log/secure" 2>/dev/null \
  | tee ./analysis/linux/ssh_logins.txt

echo "=== Failed SSH logins (top source IPs) ===" \
  && grep -h "Failed password" \
       "$CASE_ROOT/var/log/auth.log" \
       "$CASE_ROOT/var/log/secure" 2>/dev/null \
  | grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | head -20 \
  | tee ./analysis/linux/ssh_bruteforce.txt

# Authorized keys (key-based persistence)
find "$CASE_ROOT" -name "authorized_keys" -exec echo "=== {} ===" \; \
  -exec cat {} \; | tee ./analysis/linux/authorized_keys.txt

# known_hosts (machines this host pivoted to)
find "$CASE_ROOT" -name "known_hosts" -exec echo "=== {} ===" \; \
  -exec cat {} \; | tee ./analysis/linux/known_hosts.txt

# ── Bash history ─────────────────────────────────────────────────────────────
find "$CASE_ROOT" -name ".bash_history" -o -name ".zsh_history" 2>/dev/null \
  | while read -r f; do
      user=$(echo "$f" | grep -oP '/home/\K[^/]+' || echo "root")
      echo "=== $user: $f ==="
      cat "$f"
    done | tee ./analysis/linux/bash_history_all.txt

# Check for cleared/missing history files (anti-forensics indicator)
for dir in "$CASE_ROOT/root" "$CASE_ROOT/home"/*/; do
    user=$(basename "$dir")
    hist="$dir/.bash_history"
    if [[ ! -f "$hist" ]]; then
        echo "MISSING: $hist (user: $user)"
    elif [[ ! -s "$hist" ]]; then
        echo "EMPTY: $hist (user: $user)"
    fi
done | tee ./analysis/linux/history_gaps.txt

# High-value command patterns in history
grep -Eh \
  -e '(wget|curl[ :]|nc |netcat|python.*-c|perl.*-e|ruby.*-e|chmod \+x|base64)' \
  -e '(/tmp/|/dev/shm|scp |ssh -|sudo|su -|useradd|usermod|groupadd)' \
  -e '(crontab|systemctl enable|/etc/passwd|/etc/shadow)' \
  -e '(iptables|ufw|nmap|masscan|ldapsearch|secretsdump|mimikatz)' \
  -e '(openssl.*-d|dd if=|mkfifo|mknod)' \
  ./analysis/linux/bash_history_all.txt \
  | tee ./analysis/linux/bash_history_suspicious.txt

echo "Suspicious commands: $(wc -l < ./analysis/linux/bash_history_suspicious.txt)"

# ── Persistence ─────────────────────────────────────────────────────────────
echo "=== System crontab ===" && cat "$CASE_ROOT/etc/crontab" 2>/dev/null
echo "=== Cron.d entries ===" \
  && find "$CASE_ROOT/etc/cron.d/" -type f 2>/dev/null \
       -exec echo "---{}---" \; -exec cat {} \;
echo "=== User crontabs ===" \
  && find "$CASE_ROOT/var/spool/cron" -type f 2>/dev/null \
       -exec echo "---{}---" \; -exec cat {} \; \
  | tee ./analysis/linux/cron_all.txt

# Systemd units not from package manager (custom = suspicious)
find "$CASE_ROOT/etc/systemd/system/" -name "*.service" 2>/dev/null \
  | xargs grep -l "ExecStart" 2>/dev/null \
  | while read -r svc; do
      echo "=== $svc ==="; cat "$svc"
    done | tee ./analysis/linux/systemd_custom_services.txt

# rc.local (legacy init persistence)
cat "$CASE_ROOT/etc/rc.local" 2>/dev/null | tee ./analysis/linux/rc_local.txt

# .profile / .bashrc / .bash_profile modifications (user-level persistence)
find "$CASE_ROOT" \( -name ".profile" -o -name ".bashrc" -o -name ".bash_profile" \) \
  -newer "$CASE_ROOT/etc/passwd" 2>/dev/null \
  | xargs grep -l -E '(wget|curl|nc |base64|/tmp|/dev/shm)' 2>/dev/null \
  | tee ./analysis/linux/profile_persistence.txt

# ── Staging locations ──────────────────────────────────────────────────────
for stagedir in tmp dev/shm var/tmp; do
    echo "=== Files in /$stagedir ===" \
      && find "$CASE_ROOT/$stagedir" -type f 2>/dev/null \
      | while read -r f; do
          echo "FILE: $f"; file "$f"; sha256sum "$f"
        done
done | tee ./analysis/linux/staging_files.txt

# ── Kernel modules (rootkit check) ───────────────────────────────────────
if [[ -f "$CASE_ROOT/proc/modules" ]]; then
    echo "=== Loaded kernel modules ===" && cat "$CASE_ROOT/proc/modules" \
      | tee ./analysis/linux/kernel_modules.txt
fi

# ── SUID/SGID binaries ────────────────────────────────────────────────────
find "$CASE_ROOT" -perm /6000 -type f 2>/dev/null \
  | grep -v -E '^.*/proc/' \
  | xargs ls -la 2>/dev/null \
  | tee ./analysis/linux/suid_sgid_binaries.txt

# Unexpected SUID (anything outside the known-good set)
KNOWN_SUID="ping|sudo|su|passwd|chsh|chfn|newgrp|mount|umount|fusermount|pkexec|gpasswd|newuidmap|newgidmap"
grep -v -E "$KNOWN_SUID" ./analysis/linux/suid_sgid_binaries.txt \
  | tee ./analysis/linux/suid_unexpected.txt

# ── Recently modified files ───────────────────────────────────────────────
# Adjust reference point to match attack timeline anchor
find "$CASE_ROOT" \
  -not -path "*/proc/*" -not -path "*/sys/*" \
  -not -path "*/run/*" \
  -newer "$CASE_ROOT/etc/passwd" -type f 2>/dev/null \
  | grep -v -E '\.(log|journal)$' \
  | head -100 | tee ./analysis/linux/recently_modified.txt

# ── Auditd log ─────────────────────────────────────────────────────────────
if [[ -f "$CASE_ROOT/var/log/audit/audit.log" ]]; then
    # Privilege escalation events
    grep -E "type=SYSCALL.*comm=\"su\"|type=USER_AUTH|type=USER_LOGIN|type=EXECVE" \
      "$CASE_ROOT/var/log/audit/audit.log" \
      | head -100 | tee ./analysis/linux/auditd_privesc.txt

    # File access to sensitive paths
    grep -E "/etc/shadow|/etc/passwd|/root/\.ssh|/proc/mem" \
      "$CASE_ROOT/var/log/audit/audit.log" \
      | tee ./analysis/linux/auditd_sensitive_access.txt
fi
```

---

## Finding Recognition

| Pattern | Indicator | Severity |
|---------|-----------|----------|
| UID 0 account other than root | Backdoor root account | High |
| System account with bash/sh/zsh shell | Account modified for persistence | High |
| `authorized_keys` with unfamiliar key | SSH key persistence | High |
| `known_hosts` with internal hosts not in normal scope | Pivot path evidence | High |
| `/tmp`, `/dev/shm`, `/var/tmp` executable | Staged malware | High |
| Cron job running from `/tmp` or with `curl`/`wget` | Download-cradle persistence | High |
| Custom systemd service with `ExecStart` pointing to non-standard path | Service-based persistence | High |
| `.bashrc` / `.profile` modified after attack window start | User-level persistence | High |
| Bash history contains `base64 -d \| bash` or similar | Encoded payload execution | High |
| Bash history cleared or missing | Anti-forensics | High |
| Unexpected SUID binary (not in known-good set) | LPE vector installed by attacker | High |
| `wget`/`curl` in bash history followed by `chmod +x` | Malware download + execute chain | High |
| SSH brute force (>100 failed from same IP) + subsequent accepted login | Successful credential attack | High |
| Kernel module not in distro package list | Rootkit / kernel implant | Critical |

---

## In-Skill Pivot Protocol

| Finding | Follow-up within this skill |
|---------|-----------------------------|
| Suspicious file in `/tmp` or `/dev/shm` | Hash it; run `strings -a -n 8` on it; if PE/ELF, hand to malware-analysis |
| Bash history cleared (empty or missing) | Flag anti-forensics in COP; check auth.log for timing of clearing event |
| Cron job pointing to non-standard path | Check `recently_modified.txt` for creation time of that file |
| New SSH `authorized_keys` entry | Check `ssh_logins.txt` for first successful login using that key |
| SUID binary not in known-good set | Check `recently_modified.txt` for mtime; if modified in attack window, High confidence |
| Custom systemd service | Check `recently_modified.txt` for service file creation time; check `ExecStart` path |
| `known_hosts` contains internal hosts | Add those hosts to COP scope expansion list |

---

## Escalation to IC (cross-skill pivots)

Classify each escalated finding as CONFIRMED, INFERRED, or CONTRADICTED per the IC Finding Taxonomy (≥2 independent artefact types = CONFIRMED; 1–2 sources = INFERRED) before writing to the COP.

| Finding | IC pivot |
|---------|---------|
| Staged binary confirmed | IC tasks `malware-analysis` |
| External IP from auth.log or bash history | IC adds to IOC master; `network-analysis` cross-ref if PCAP available |
| New UID 0 account or SSH authorized key | IC updates Persistence and Credential Access in COP |
| `known_hosts` reveals pivot targets | IC expands scope to those hosts |
| Bash history shows credential harvesting | IC updates Credential Access in COP; checks other machines for same accounts |
| Kernel module anomaly | IC flags possible rootkit; `yara-hunting` sweep against module binary |

---

## Output Paths

| Output | Path |
|--------|------|
| Local user accounts | `./analysis/linux/local_users.txt`, `uid0_accounts.txt` |
| System accounts with shell | `./analysis/linux/system_shell_accounts.txt` |
| Shadow hashes | `./analysis/linux/shadow_hashes.txt` |
| SSH logins / brute force | `./analysis/linux/ssh_logins.txt`, `ssh_bruteforce.txt` |
| Authorized keys / known_hosts | `./analysis/linux/authorized_keys.txt`, `known_hosts.txt` |
| Bash history (all users) | `./analysis/linux/bash_history_all.txt`, `bash_history_suspicious.txt` |
| History gaps (anti-forensics) | `./analysis/linux/history_gaps.txt` |
| Persistence (cron, systemd, rc.local) | `./analysis/linux/cron_all.txt`, `systemd_custom_services.txt`, `rc_local.txt` |
| Profile-level persistence | `./analysis/linux/profile_persistence.txt` |
| Staging locations | `./analysis/linux/staging_files.txt` |
| SUID/SGID | `./analysis/linux/suid_sgid_binaries.txt`, `suid_unexpected.txt` |
| Recently modified files | `./analysis/linux/recently_modified.txt` |
| Kernel modules | `./analysis/linux/kernel_modules.txt` |
| Auditd findings | `./analysis/linux/auditd_privesc.txt`, `auditd_sensitive_access.txt` |

---

## Notes

- Bash history is easily cleared — absence of `.bash_history` is itself a finding; note it in the COP under Anti-Forensics
- `/dev/shm` is tmpfs (RAM-backed, no disk writes) — commonly used by Linux malware to avoid leaving artifacts; always check
- For auditd logs, `ausearch -i` gives human-readable output: `ausearch -i --start <date> --end <date>`
- `known_hosts` entries identify machines this host has SSH'd to — key for tracing lateral movement pivot paths
- If the evidence is an image rather than a live mount, adjust `CASE_ROOT` to the mount point
- Velociraptor-collected Linux artifacts (JSON ZIP) go to `edr-telemetry` skill, not this skill
