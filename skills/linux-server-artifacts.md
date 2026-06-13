---
name: linux-server-artifacts
description: Linux and web server forensic artifact map - logs, persistence, web artifacts, and compromise indicators
---

# Linux and Web Server Forensic Artifacts

This skill covers artifact locations and forensic procedures for Linux-based systems
and web servers (Apache, Nginx, PHP). Use alongside `windows-artifacts.md` when the
evidence set includes both platforms.

---

## System logs

### Log locations

| Log | Path | What it contains |
|---|---|---|
| Authentication | `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS) | SSH logons, sudo commands, su attempts, PAM events |
| Syslog | `/var/log/syslog` or `/var/log/messages` | General system events, kernel messages, daemon activity |
| Kernel | `/var/log/kern.log` | Kernel-level events, driver errors, OOM kills |
| Boot | `/var/log/boot.log` | Service startup/shutdown sequence |
| Package install | `/var/log/dpkg.log` (Debian) / `/var/log/yum.log` (RHEL) | Software installed, removed, or upgraded with timestamps |
| Cron | `/var/log/cron` | Cron job execution history |
| Mail | `/var/log/mail.log` | Mail server events (if present) |

### Key log patterns

**Brute force / password spray:**
```bash
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
```

**Successful SSH logons with source IP:**
```bash
grep "Accepted" /var/log/auth.log | awk '{print $11, $13}' | sort | uniq -c
```

**Sudo command history:**
```bash
grep "sudo:" /var/log/auth.log | grep "COMMAND"
```

---

## User activity artifacts

### Shell history

| Shell | Location |
|---|---|
| bash | `~/.bash_history` (written on logout - may be empty if attacker killed shell without exiting) |
| zsh | `~/.zsh_history` |
| fish | `~/.local/share/fish/fish_history` |

**Attacker evasion patterns:**
- `HISTFILE=/dev/null` in the session to disable logging
- `history -c` or `unset HISTFILE` before logout
- Reverse shell connections that never write history (netcat, socat)
- When history is empty but other artifacts confirm activity, note the discrepancy

**Note:** Shell history is unreliable as a primary evidence source. Corroborate with
auth.log, syslog, web logs, or process accounting.

### Process accounting

If `psacct` or `acct` was enabled:
```bash
lastcomm --file /var/account/pacct | head -50   # all commands run, with user and time
```

### Last logon records

```bash
last -f /var/log/wtmp          # all logon/logoff history
lastb -f /var/log/btmp         # failed logon attempts
who /var/log/utmp              # currently logged-in users at acquisition time
```

---

## Persistence mechanisms

Check all of these when compromise is confirmed. Attackers typically install multiple
persistence points; finding one does not mean you have found all.

| Mechanism | Location | Command |
|---|---|---|
| Cron jobs | `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/crontabs/` | `cat /etc/crontab; ls -la /etc/cron.d/` |
| At jobs | `/var/spool/at/` | `ls -la /var/spool/at/` |
| Init scripts | `/etc/init.d/` | Compare against known-good baseline |
| systemd units | `/etc/systemd/system/`, `/lib/systemd/system/` | `systemctl list-units --type=service` or parse files directly |
| rc.local | `/etc/rc.local` | `cat /etc/rc.local` |
| SSH authorized_keys | `~/.ssh/authorized_keys` for every user | Attacker-added public key = persistent backdoor |
| PAM modules | `/etc/pam.d/`, `/lib/security/` | Modified PAM = credential harvesting or bypass |
| LD_PRELOAD / ld.so.preload | `/etc/ld.so.preload` | Rootkit injection point |
| SUID/SGID binaries | Anywhere | `find / -perm -4000 -type f 2>/dev/null` - compare against baseline |
| World-writable directories | `/tmp`, `/dev/shm`, `/var/tmp` | Primary attacker staging areas |

**Hidden files in common staging paths:**
```bash
ls -la /tmp/ /dev/shm/ /var/tmp/
find /tmp /dev/shm /var/tmp -name ".*" -type f 2>/dev/null
```

---

## Web server artifacts

### Apache log locations

| Log | Default path |
|---|---|
| Access log | `/var/log/apache2/access.log` or `/etc/httpd/logs/access_log` or `C:\xampp\apache\logs\access.log` (Windows/XAMPP) |
| Error log | `/var/log/apache2/error.log` |
| Virtual host logs | `/var/log/apache2/<vhost>-access.log` |

**Access log field order (Combined Log Format):**
```
<ip> <ident> <authuser> [<datetime>] "<method> <uri> <protocol>" <status> <bytes> "<referer>" "<user-agent>"
```

### Nginx log locations

| Log | Default path |
|---|---|
| Access log | `/var/log/nginx/access.log` |
| Error log | `/var/log/nginx/error.log` |

### PHP artifacts

| Artifact | What it reveals |
|---|---|
| PHP session files | `/var/lib/php/sessions/sess_*` - active user sessions, may contain attacker session tokens |
| `php.ini` | `allow_url_include`, `disable_functions` - tells you what PHP can/cannot do |
| Webshell signatures | `system(`, `exec(`, `passthru(`, `shell_exec(`, `eval(base64_decode(` in `.php` files |
| Upload directories | Configured in web app - check for PHP files in image/upload directories |

**Find PHP files with command execution functions:**
```bash
grep -rn "system\|exec\|passthru\|shell_exec\|eval.*base64" /var/www/ --include="*.php" | grep -v ".git"
```

**Find recently modified PHP files (within last 30 days):**
```bash
find /var/www -name "*.php" -mtime -30 -type f | sort
```

### MySQL / web application database artifacts

| Artifact | Path | What it reveals |
|---|---|---|
| MySQL error log | `/var/log/mysql/error.log` | Connection errors, `INTO OUTFILE` permission errors, SQL syntax errors |
| MySQL general query log | `/var/lib/mysql/<hostname>.log` (disabled by default) | All SQL executed |
| MySQL binary log | `/var/lib/mysql/mysql-bin.*` | All data-modifying queries for replication - recoverable even without general log |
| Database files | `/var/lib/mysql/<dbname>/` | Table data files - may contain injected content in text fields |

---

## File system indicators of compromise

### Files that should not exist

```bash
# PHP files in non-web directories
find /tmp /dev/shm /var/tmp -name "*.php" 2>/dev/null

# Executables in web document roots
find /var/www -perm /111 -type f 2>/dev/null | grep -v ".cgi\|.pl\|.py"

# Recently created files in web root
find /var/www -mtime -7 -type f 2>/dev/null | sort -t'/' -k5

# Hidden directories in web root
find /var/www -maxdepth 4 -name ".*" -type d 2>/dev/null
```

### File timestamps and inode information

```bash
stat <filename>             # shows Access, Modify, Change times + inode
ls -lai <directory>         # inode number - sequential inodes suggest batch creation
debugfs -R "stat <file>" /dev/<device>   # full inode metadata from live volume
```

### /proc artifacts (memory image alternative)

When a memory image is unavailable but the system is live:
```bash
cat /proc/<pid>/cmdline    # full command line of running process
ls -la /proc/<pid>/fd/     # open file descriptors
cat /proc/<pid>/maps       # memory map
cat /proc/<pid>/net/tcp    # TCP connections (hex ports)
```

---

## Evidence of web compromise - artifact checklist

When the evidence type is a web server compromise, work through this list before
forming a conclusion:

- [ ] Access log UA histogram (W-1 from triage-methodology)
- [ ] Access log: files POSTed to that don't exist on disk (dropped and deleted)
- [ ] Web root: PHP files in upload directories
- [ ] Web root: files with random names matching `tmp[a-z]{5,8}\.php` pattern
- [ ] MySQL error log: `INTO OUTFILE` errors (failed file-write attempts)
- [ ] auth.log: SSH logons from attacker IP during compromise window
- [ ] /tmp, /dev/shm: staging files
- [ ] Cron/systemd: new jobs or units created during compromise window
- [ ] SAM / /etc/passwd + /etc/shadow: new accounts
- [ ] Firewall rules: iptables / ufw changes during compromise window
