---
name: linux-server-artifacts
description: Linux and web server forensic artifact map — logs, persistence, web artifacts, and compromise indicators
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

### Reading the logs

The shell snippets below collect data; the analysis is reading that data
against what you know about normal use of the host.

**Failed-authentication frequency by source:**
```bash
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
```
A long tail of failures from one source against many usernames, a short
burst against one account, and a steady drip across days each tell different
stories. Read the top sources against the host's expected client population.

**Successful SSH logons with source IP:**
```bash
grep "Accepted" /var/log/auth.log | awk '{print $11, $13}' | sort | uniq -c
```
Compare the accepted sources to the failed-attempt sources, to the user's
normal travel/network pattern, and to the auth method used (password vs key).

**Sudo command history:**
```bash
grep "sudo:" /var/log/auth.log | grep "COMMAND"
```
Read each sudo invocation in context: which user, what command, was the
target consistent with their role, and does it correlate with other
artifacts in the same time window.

---

## User activity artifacts

### Shell history

| Shell | Location |
|---|---|
| bash | `~/.bash_history` (written on logout — may be empty if attacker killed shell without exiting) |
| zsh | `~/.zsh_history` |
| fish | `~/.local/share/fish/fish_history` |

Read each user's history file in full and reason about it. An empty or
suspiciously short history for an account that auth.log shows actively
logging in is a meaningful gap; commands that disable logging or clear
history mid-session, sessions that ran over non-shell channels (netcat,
socat reverse shells), or histories that simply don't match the user's
role all warrant noting. Cross-corroborate every conclusion drawn from
history against auth.log, syslog, web logs, or process accounting —
shell history alone is too easily manipulated to support a finding.

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
| SUID/SGID binaries | Anywhere | `find / -perm -4000 -type f 2>/dev/null` — compare against baseline |
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

| Artifact | Path / scope | What to read it for |
|---|---|---|
| PHP session files | `/var/lib/php/sessions/sess_*` | Active or recent user sessions; may carry attacker session tokens |
| `php.ini` | System config | Settings that change the attack surface (`allow_url_include`, `disable_functions`, `open_basedir`) |
| Webroot PHP files | `/var/www/` and configured roots | Files that should not exist; files that should exist but were modified |
| Upload directories | Per-application | PHP files in directories meant only for images or other non-executable content |

The greps below surface candidate files; reading each candidate is the analysis.

```bash
# Candidate webshells: PHP files that invoke shell or eval primitives
grep -rn "system\|exec\|passthru\|shell_exec\|eval.*base64" /var/www/ --include="*.php" | grep -v ".git"

# Recently changed PHP within the incident window (adjust -mtime to match)
find /var/www -name "*.php" -mtime -30 -type f | sort
```

Open each candidate file and read it. Legitimate frameworks call `exec()`
and use `base64`; the question is whether this file's invocation makes sense
for the application that owns it, whether the entrypoint is reachable by an
unauthenticated request, and whether the modification time aligns with other
attacker activity. A clean-looking match in a well-known framework path is
usually noise; an obfuscated payload in an upload directory is usually a
finding — but distinguish the two by reading the code, not by counting
keyword hits.

### MySQL / web application database artifacts

| Artifact | Path | What it reveals |
|---|---|---|
| MySQL error log | `/var/log/mysql/error.log` | Connection errors, `INTO OUTFILE` permission errors, SQL syntax errors |
| MySQL general query log | `/var/lib/mysql/<hostname>.log` (disabled by default) | All SQL executed |
| MySQL binary log | `/var/lib/mysql/mysql-bin.*` | All data-modifying queries for replication — recoverable even without general log |
| Database files | `/var/lib/mysql/<dbname>/` | Table data files — may contain injected content in text fields |

---

## File system indicators of compromise

### Files worth inspecting

The find commands below produce candidate lists. Open each result and reason
about whether it belongs — the application's deployment pattern, the package
manager's record, and the file's content determine the answer.

```bash
# PHP scripts in staging or world-writable directories
find /tmp /dev/shm /var/tmp -name "*.php" 2>/dev/null

# Executables under the web document root
find /var/www -perm /111 -type f 2>/dev/null | grep -v ".cgi\|.pl\|.py"

# Files modified inside the incident window (tune -mtime to the case)
find /var/www -mtime -7 -type f 2>/dev/null | sort -t'/' -k5

# Hidden directories under the web root
find /var/www -maxdepth 4 -name ".*" -type d 2>/dev/null
```

### File timestamps and inode information

```bash
stat <filename>             # shows Access, Modify, Change times + inode
ls -lai <directory>         # inode number — sequential inodes suggest batch creation
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

## Evidence of web compromise — artifact checklist

When the evidence type is a web server compromise, work through these passes
before forming a conclusion. Each line names a data source to read; the
interpretation is yours after running the tool.

- [ ] Access log: UA histogram (W-1 from triage-methodology) — read the tail
      for tooling that doesn't belong to the user population.
- [ ] Access log: requests for files that no longer exist on disk — candidate
      dropped-and-deleted payloads, worth recovering via `$LogFile` /
      `extundelete` / journal walks.
- [ ] Web root: every PHP file in directories meant only for uploads or
      images — open each and read it.
- [ ] Web root: files with names that don't match the application's naming
      conventions — read them.
- [ ] MySQL error log: file-write or `OUTFILE` errors during the window;
      cross-check successful writes via the binlog if enabled.
- [ ] auth.log: SSH activity during the window, evaluated against the user's
      normal pattern.
- [ ] `/tmp`, `/dev/shm`, `/var/tmp`: any file created during the window —
      list contents and read what's there.
- [ ] cron, systemd: new jobs or units; compare to package-manager records
      and the host's baseline.
- [ ] `/etc/passwd`, `/etc/shadow`, `getent passwd`: accounts that did not
      exist at baseline.
- [ ] Firewall state (`iptables-save`, `ufw status verbose`, nftables): rules
      added during the window.
