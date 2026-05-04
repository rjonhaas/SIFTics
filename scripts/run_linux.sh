#!/usr/bin/env bash
# run_linux.sh — Phase 15: Kali Linux Partition Analysis
#
# Analyzes the Kali Linux partition embedded in the case disk image (EWF).
# The partition is mounted read-only via losetup + mount -o ro,noload because
# the ext4 journal was not cleanly unmounted.
#
# Sections:
#   L1. Bash History     → {MACHINE}_L_bash_history.csv
#   L2. File Inventory   → {MACHINE}_L_file_inventory.csv
#   L3. Apache Logs      → {MACHINE}_L_apache_access.csv
#   L4. Offensive Tools  → {MACHINE}_L_offensive_tools.csv
#   L5. Cron Jobs        → {MACHINE}_L_cron.csv
#   L6. SSH              → {MACHINE}_L_ssh.csv
#   L7. Auth/System Logs → {MACHINE}_L_auth_log.csv
#   L8. CTF Artifacts    → {MACHINE}_L_ctf_artifacts.csv
#
# Optional env overrides (defaults target defcon2019_dfir):
#   LINUX_MOUNT              default /mnt/linux_mount
#   EWF_IMAGE                default /mnt/ewf_mount/ewf1
#   LINUX_PARTITION_OFFSET   default 38687211520   (sector 75560960 × 512)
#   LINUX_MACHINE            default Bob

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CASE_ROOT="${1:-${CASE_ROOT:-}}"
if [[ -z "$CASE_ROOT" ]]; then
    read -rp "Case root directory (e.g. /cases/defcon2019_dfir): " CASE_ROOT
fi
[[ -d "$CASE_ROOT" ]] || { echo "ERROR: CASE_ROOT '${CASE_ROOT}' does not exist." >&2; exit 1; }
export CASE_ROOT

ANALYSIS_DIR="${CASE_ROOT}/analysis"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")

LINUX_MOUNT="${LINUX_MOUNT:-/mnt/linux_mount}"
EWF_IMAGE="${EWF_IMAGE:-/mnt/ewf_mount/ewf1}"
LINUX_PARTITION_OFFSET="${LINUX_PARTITION_OFFSET:-38687211520}"
LINUX_MACHINE="${LINUX_MACHINE:-Bob}"

PARSE_BASH="${SCRIPT_DIR}/parse_bash_history.py"
PARSE_APACHE="${SCRIPT_DIR}/parse_apache_log.py"

OUT_DIR="${ANALYSIS_DIR}/${LINUX_MACHINE}/Linux"
PREFIX="${LINUX_MACHINE}_L"

# ─── helpers ────────────────────────────────────────────────────────────────

log_cmd() {
    local machine="$1" tool="$2" cmd="$3" purpose="$4" output="$5" result="$6"
    cat >> "${COMMAND_LOG}" <<EOF

[${TIMESTAMP}] ${machine} | ${tool} | Linux
  ${cmd}
  > Purpose  : ${purpose}
  > Output   : ${output}
  > Result   : ${result}

--------------------------------------------------------------------------------
EOF
}

section()  { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
status()   { printf "  [%-10s] %s\n" "$1" "$2"; }

run_py() {
    set +e; out=$(python3 "$@" 2>&1); rc=$?; set -e
    echo "${out}"; return ${rc}
}

# ─── mount ───────────────────────────────────────────────────────────────────

ensure_linux_mount() {
    if mountpoint -q "${LINUX_MOUNT}" 2>/dev/null; then
        status "OK" "Already mounted at ${LINUX_MOUNT}"
        return 0
    fi

    if [[ ! -e "${EWF_IMAGE}" ]]; then
        status "ERROR" "EWF image not found at ${EWF_IMAGE} — run ewfmount first"
        return 1
    fi

    local loop_dev
    # Find existing loop device for this image + offset
    loop_dev=$(sudo losetup -a 2>/dev/null \
        | grep "offset ${LINUX_PARTITION_OFFSET}" \
        | grep -F "$(basename "${EWF_IMAGE}")" \
        | cut -d: -f1 | head -1)

    if [[ -z "${loop_dev}" ]]; then
        loop_dev=$(sudo losetup --find --show --read-only \
            --offset="${LINUX_PARTITION_OFFSET}" "${EWF_IMAGE}" 2>&1) || {
            status "ERROR" "losetup failed: ${loop_dev}"
            return 1
        }
        status "OK" "Created loop device ${loop_dev} (offset ${LINUX_PARTITION_OFFSET})"
    else
        status "OK" "Reusing loop device ${loop_dev}"
    fi

    sudo mkdir -p "${LINUX_MOUNT}"
    if ! sudo mount -o ro,noload "${loop_dev}" "${LINUX_MOUNT}" 2>/dev/null; then
        status "ERROR" "mount failed for ${loop_dev} at ${LINUX_MOUNT}"
        return 1
    fi
    status "OK" "Mounted at ${LINUX_MOUNT} (ro,noload — dirty ext4 journal)"
    return 0
}

# ─── init ────────────────────────────────────────────────────────────────────

mkdir -p "${OUT_DIR}"
mkdir -p "$(dirname "${COMMAND_LOG}")"
touch "${COMMAND_LOG}"

echo "════════════════════════════════════════════════════"
echo " Linux Partition Analysis — Phase 15"
echo " $(date -u)"
echo " Machine : ${LINUX_MACHINE}"
echo " Output  : ${OUT_DIR}/"
echo "════════════════════════════════════════════════════"

for helper in "${PARSE_BASH}" "${PARSE_APACHE}"; do
    [[ -f "${helper}" ]] || { echo "ERROR: helper not found: ${helper}" >&2; exit 1; }
done

# ─── establish mount ─────────────────────────────────────────────────────────

section "Mount: Kali Linux Partition"
ensure_linux_mount || {
    echo "FATAL: cannot proceed without Linux partition mount" >&2
    exit 1
}

if [[ -f "${LINUX_MOUNT}/etc/os-release" ]]; then
    os_ver=$(grep -m1 PRETTY_NAME "${LINUX_MOUNT}/etc/os-release" 2>/dev/null \
        | cut -d'"' -f2 || echo 'Unknown')
    status "INFO" "OS: ${os_ver}"
fi

# ════════════════════════════════════════════════════════════════════════════
section "L1. Bash History — /root/.bash_history"
# ════════════════════════════════════════════════════════════════════════════

out_csv="${OUT_DIR}/${PREFIX}_bash_history.csv"
hist_src="${LINUX_MOUNT}/root/.bash_history"

if [[ -f "${hist_src}" ]]; then
    hist_tmp=$(mktemp /tmp/bash_hist_XXXXXX)
    if sudo cat "${hist_src}" > "${hist_tmp}" 2>/dev/null; then
        set +e
        row_count=$(python3 "${PARSE_BASH}" "${hist_tmp}" "${LINUX_MACHINE}" "root" "${out_csv}" 2>&1)
        py_rc=$?
        set -e
        if [[ ${py_rc} -eq 0 ]]; then
            status "OK" "${row_count} commands → ${out_csv}"
            log_cmd "${LINUX_MACHINE}" "parse_bash_history.py" \
                "sudo cat ${hist_src} | python3 ${PARSE_BASH}" \
                "Categorize root bash history, extract IOCs and flag indicators" \
                "${out_csv}" "${row_count} rows"
            # Highlight key categories
            if [[ -f "${out_csv}" ]]; then
                for cat in FLAG CREDENTIAL_ACCESS ANTI_FORENSICS TOOL_EXECUTION; do
                    hits=$(awk -F',' -v c="${cat}" 'NR>1 && $5==c' "${out_csv}" 2>/dev/null | wc -l)
                    [[ "${hits}" -gt 0 ]] && status "ALERT" "${hits} ${cat} command(s)"
                done
            fi
        else
            status "ERROR" "parse_bash_history.py exited ${py_rc}: ${row_count}"
        fi
    else
        status "ERROR" "sudo cat failed for ${hist_src}"
    fi
    rm -f "${hist_tmp}"
else
    status "MISSING" "${hist_src} not found"
fi

# ════════════════════════════════════════════════════════════════════════════
section "L2. File Inventory — /root"
# ════════════════════════════════════════════════════════════════════════════

out_csv="${OUT_DIR}/${PREFIX}_file_inventory.csv"

if [[ -d "${LINUX_MOUNT}/root" ]]; then
    file_tmp=$(mktemp /tmp/filelist_XXXXXX)
    sudo find "${LINUX_MOUNT}/root" -type f 2>/dev/null | sort > "${file_tmp}"
    file_count=$(wc -l < "${file_tmp}")
    status "INFO" "${file_count} files found under /root"

    set +e
    row_count=$(python3 - "${file_tmp}" "${LINUX_MACHINE}" "${LINUX_MOUNT}" "${out_csv}" <<'PYEOF'
import sys, csv, os, hashlib, datetime

file_list_path, machine, mount_root, out_csv = sys.argv[1:]

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f'ERROR:{e}'

rows = []
with open(file_list_path) as f:
    for line in f:
        fpath = line.rstrip('\n')
        if not fpath:
            continue
        rel = fpath[len(mount_root):]
        try:
            st   = os.stat(fpath)
            size = st.st_size
            mtime = datetime.datetime.utcfromtimestamp(st.st_mtime).strftime('%Y-%m-%dT%H:%M:%SZ')
        except Exception:
            size, mtime = -1, ''
        if 0 <= size < 104857600:
            digest = sha256(fpath)
        elif size >= 104857600:
            digest = 'SKIPPED_LARGE'
        else:
            digest = 'STAT_ERROR'
        rows.append({'Machine': machine, 'FilePath': rel,
                     'SizeBytes': size, 'ModifiedTime_UTC': mtime, 'SHA256': digest})

os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
with open(out_csv, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=['Machine','FilePath','SizeBytes','ModifiedTime_UTC','SHA256'])
    w.writeheader()
    w.writerows(rows)
print(len(rows))
PYEOF
)
    py_rc=$?
    set -e
    rm -f "${file_tmp}"

    if [[ ${py_rc} -eq 0 ]]; then
        status "OK" "${row_count} files inventoried → ${out_csv}"
        log_cmd "${LINUX_MACHINE}" "find+sha256" \
            "sudo find ${LINUX_MOUNT}/root -type f | sha256 (files < 100MB)" \
            "Inventory all /root files with size, mtime, SHA256" \
            "${out_csv}" "${row_count} rows"
    else
        status "ERROR" "File inventory Python script failed (rc=${py_rc})"
    fi
else
    status "MISSING" "${LINUX_MOUNT}/root not found"
fi

# ════════════════════════════════════════════════════════════════════════════
section "L3. Apache Access Logs"
# ════════════════════════════════════════════════════════════════════════════

out_csv="${OUT_DIR}/${PREFIX}_apache_access.csv"
access_log="${LINUX_MOUNT}/var/log/apache2/access.log"

if [[ -f "${access_log}" ]]; then
    log_size=$(stat -c '%s' "${access_log}" 2>/dev/null || echo 0)
    if [[ "${log_size}" -eq 0 ]]; then
        status "INFO" "access.log is empty (Apache was installed but never received requests)"
    fi
    set +e
    row_count=$(run_py "${PARSE_APACHE}" "${access_log}" "${LINUX_MACHINE}" "${out_csv}")
    py_rc=$?
    set -e
    if [[ ${py_rc} -eq 0 ]]; then
        status "OK" "${row_count} log entries → ${out_csv}"
        log_cmd "${LINUX_MACHINE}" "parse_apache_log.py" \
            "python3 ${PARSE_APACHE} ${access_log}" \
            "Parse Apache combined access log (empty = header-only CSV)" \
            "${out_csv}" "${row_count} rows"
    else
        status "ERROR" "parse_apache_log.py failed (rc=${py_rc}): ${row_count}"
    fi
else
    status "MISSING" "${access_log} not found"
    python3 "${PARSE_APACHE}" "/dev/null" "${LINUX_MACHINE}" "${out_csv}" > /dev/null 2>&1 || true
fi

# Also check error log
error_log="${LINUX_MOUNT}/var/log/apache2/error.log"
if [[ -f "${error_log}" ]] && [[ $(stat -c '%s' "${error_log}" 2>/dev/null || echo 0) -gt 0 ]]; then
    err_lines=$(wc -l < "${error_log}")
    status "INFO" "error.log: ${err_lines} lines (review manually at ${error_log})"
    head -20 "${error_log}" | sed 's/^/    /' 2>/dev/null || true
fi

# ════════════════════════════════════════════════════════════════════════════
section "L4. Offensive Tools"
# ════════════════════════════════════════════════════════════════════════════

out_csv="${OUT_DIR}/${PREFIX}_offensive_tools.csv"

set +e
row_count=$(python3 - "${LINUX_MACHINE}" "${LINUX_MOUNT}" "${out_csv}" <<'PYEOF'
import sys, csv, os, hashlib

machine, mount, out_csv = sys.argv[1:]

KNOWN_TOOLS = [
    ('root/Desktop/mimikatz/mimikatz.exe',    'mimikatz.exe',         'CREDENTIAL_TOOL'),
    ('root/Desktop/mimikatz/mimidrv.sys',     'mimidrv.sys',          'CREDENTIAL_TOOL'),
    ('root/Desktop/mimikatz/mimilib.dll',     'mimilib.dll',          'CREDENTIAL_TOOL'),
    ('root/Downloads/mimikatz_trunk.zip',     'mimikatz_trunk.zip',   'CREDENTIAL_TOOL'),
    ('root/.msf4',                            'Metasploit .msf4 dir', 'C2_FRAMEWORK'),
    ('usr/bin/msfconsole',                    'msfconsole',           'C2_FRAMEWORK'),
    ('usr/share/metasploit-framework',        'metasploit-framework', 'C2_FRAMEWORK'),
    ('usr/bin/nmap',                          'nmap',                 'RECON_TOOL'),
    ('usr/bin/binwalk',                       'binwalk',              'FORENSIC_TOOL'),
    ('usr/bin/john',                          'john',                 'PASSWORD_CRACKER'),
    ('usr/bin/hashcat',                       'hashcat',              'PASSWORD_CRACKER'),
    ('usr/bin/hydra',                         'hydra',                'BRUTE_FORCE'),
    ('usr/bin/aircrack-ng',                   'aircrack-ng',          'WIFI_TOOL'),
    ('usr/bin/sqlmap',                        'sqlmap',               'WEB_ATTACK_TOOL'),
    ('usr/share/beef-xss',                    'BeEF',                 'WEB_ATTACK_TOOL'),
    ('usr/share/burpsuite',                   'Burp Suite',           'WEB_ATTACK_TOOL'),
]

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return 'N/A'

rows = []
for rel_path, name, category in KNOWN_TOOLS:
    full_path = os.path.join(mount, rel_path)
    if not os.path.exists(full_path):
        continue
    try:
        size   = os.path.getsize(full_path) if os.path.isfile(full_path) else -1
        digest = sha256(full_path) if os.path.isfile(full_path) else 'DIR'
    except Exception:
        size, digest = -1, 'ERROR'
    rows.append({'Machine': machine, 'ToolName': name, 'FilePath': '/'+rel_path,
                 'SHA256': digest, 'SizeBytes': size, 'Category': category,
                 'Note': 'directory' if os.path.isdir(full_path) else ''})

import re
pe_pattern = re.compile(r'\.(exe|dll|sys|elf)$', re.IGNORECASE)
known_set = {os.path.join(mount, r) for r, _, _ in KNOWN_TOOLS}
for dirpath, dirnames, filenames in os.walk(os.path.join(mount, 'root')):
    dirnames[:] = [d for d in dirnames if d not in ('modules','plugins','loot')]
    for fname in filenames:
        if pe_pattern.search(fname):
            full = os.path.join(dirpath, fname)
            if full not in known_set:
                rel = full[len(mount):]
                try:
                    size   = os.path.getsize(full)
                    digest = sha256(full)
                except Exception:
                    size, digest = -1, 'ERROR'
                rows.append({'Machine': machine, 'ToolName': fname, 'FilePath': rel,
                             'SHA256': digest, 'SizeBytes': size,
                             'Category': 'PE_BINARY', 'Note': 'auto-detected'})

os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
fields = ['Machine','ToolName','FilePath','SHA256','SizeBytes','Category','Note']
with open(out_csv, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
print(len(rows))
PYEOF
)
py_rc=$?
set -e

if [[ ${py_rc} -eq 0 ]]; then
    status "OK" "${row_count} offensive tool(s) found → ${out_csv}"
    log_cmd "${LINUX_MACHINE}" "offensive-tools-scan" \
        "find ${LINUX_MOUNT}/root -name '*.exe|*.dll|*.sys' + known-paths check" \
        "Identify offensive security tools: mimikatz, Metasploit, scanners" \
        "${out_csv}" "${row_count} rows"
    [[ "${row_count}" -gt 0 ]] && status "ALERT" "Offensive tools present on Linux partition"
else
    status "ERROR" "Offensive tools scan failed (rc=${py_rc})"
fi

# ════════════════════════════════════════════════════════════════════════════
section "L5. Cron Jobs"
# ════════════════════════════════════════════════════════════════════════════

out_csv="${OUT_DIR}/${PREFIX}_cron.csv"

set +e
row_count=$(python3 - "${LINUX_MACHINE}" "${LINUX_MOUNT}" "${out_csv}" <<'PYEOF'
import sys, csv, os, subprocess

machine, mount, out_csv = sys.argv[1:]

CRON_PATHS = [
    '/etc/crontab',
    '/etc/cron.hourly',
    '/etc/cron.daily',
    '/etc/cron.weekly',
    '/etc/cron.monthly',
    '/etc/cron.d',
    '/var/spool/cron/crontabs',
]

def list_dir_sudo(full_path):
    """List directory, falling back to sudo if permission denied."""
    try:
        return [os.path.join(full_path, f) for f in os.listdir(full_path)
                if not f.startswith('.')]
    except PermissionError:
        result = subprocess.run(['sudo', 'ls', full_path],
                                capture_output=True, text=True)
        if result.returncode == 0:
            return [os.path.join(full_path, f)
                    for f in result.stdout.splitlines()
                    if f and not f.startswith('.')]
        return []

def read_file_sudo(fpath):
    """Read file content, falling back to sudo if permission denied."""
    try:
        with open(fpath, 'r', errors='replace') as f:
            return f.read()
    except PermissionError:
        result = subprocess.run(['sudo', 'cat', fpath],
                                capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        return None

rows = []
for rel in CRON_PATHS:
    full = mount + rel
    if not os.path.exists(full):
        continue
    targets = list_dir_sudo(full) if os.path.isdir(full) else [full]
    for fpath in sorted(targets):
        content = read_file_sudo(fpath)
        if content is None:
            rows.append({'Machine': machine, 'Source': fpath[len(mount):],
                         'LineNo': 0, 'CronEntry': 'ERROR: unreadable', 'Note': ''})
            continue
        for lineno, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            rows.append({'Machine': machine, 'Source': fpath[len(mount):],
                         'LineNo': lineno, 'CronEntry': stripped, 'Note': ''})

os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
fields = ['Machine', 'Source', 'LineNo', 'CronEntry', 'Note']
with open(out_csv, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
print(len(rows))
PYEOF
)
py_rc=$?
set -e

if [[ ${py_rc} -eq 0 ]]; then
    status "OK" "${row_count} cron entries → ${out_csv}"
    log_cmd "${LINUX_MACHINE}" "cron-scan" \
        "read /etc/crontab /etc/cron.d/ /var/spool/cron/crontabs/" \
        "Enumerate scheduled tasks on Kali partition" \
        "${out_csv}" "${row_count} rows"
else
    status "ERROR" "Cron scan failed (rc=${py_rc})"
fi

# ════════════════════════════════════════════════════════════════════════════
section "L6. SSH Keys and Configuration"
# ════════════════════════════════════════════════════════════════════════════

out_csv="${OUT_DIR}/${PREFIX}_ssh.csv"

set +e
row_count=$(python3 - "${LINUX_MACHINE}" "${LINUX_MOUNT}" "${out_csv}" <<'PYEOF'
import sys, csv, os, hashlib, re

machine, mount, out_csv = sys.argv[1:]

SSH_PATHS = [
    ('/root/.ssh/authorized_keys', 'AUTHORIZED_KEY'),
    ('/root/.ssh/id_rsa',          'PRIVATE_KEY'),
    ('/root/.ssh/id_ed25519',      'PRIVATE_KEY'),
    ('/root/.ssh/id_ecdsa',        'PRIVATE_KEY'),
    ('/root/.ssh/id_rsa.pub',      'PUBLIC_KEY'),
    ('/root/.ssh/id_ed25519.pub',  'PUBLIC_KEY'),
    ('/root/.ssh/known_hosts',     'KNOWN_HOSTS'),
    ('/root/.ssh/config',          'SSH_CLIENT_CONFIG'),
    ('/etc/ssh/sshd_config',       'SSHD_CONFIG'),
]

SSHD_INTEREST = ['PermitRootLogin','PasswordAuthentication','PubkeyAuthentication',
                 'AuthorizedKeysFile','Port','ListenAddress','PermitEmptyPasswords',
                 'AllowUsers','DenyUsers']

rows = []
for rel, ftype in SSH_PATHS:
    full = mount + rel
    if not os.path.exists(full):
        continue
    try:
        with open(full, 'r', errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                # For sshd_config only emit interesting directives
                if ftype == 'SSHD_CONFIG':
                    key = stripped.split()[0] if stripped.split() else ''
                    if key not in SSHD_INTEREST:
                        continue
                note = ''
                if ftype == 'PRIVATE_KEY':
                    note = 'PRIVATE KEY PRESENT'
                rows.append({'Machine': machine, 'Type': ftype,
                             'FilePath': rel, 'LineNo': lineno,
                             'Content': stripped[:200], 'Note': note})
    except Exception as e:
        rows.append({'Machine': machine, 'Type': ftype, 'FilePath': rel,
                     'LineNo': 0, 'Content': f'ERROR:{e}', 'Note': ''})

# Also check for SSH known_hosts entries (lateral movement clues)
known_full = mount + '/root/.ssh/known_hosts'
if os.path.exists(known_full):
    try:
        with open(known_full, 'r', errors='replace') as f:
            hosts = [l.split()[0] for l in f if l.strip() and not l.startswith('#')]
        if hosts:
            rows.append({'Machine': machine, 'Type': 'KNOWN_HOST_SUMMARY',
                         'FilePath': '/root/.ssh/known_hosts', 'LineNo': 0,
                         'Content': f'{len(hosts)} known host(s): ' + ', '.join(hosts[:10]),
                         'Note': 'lateral movement indicator'})
    except Exception:
        pass

os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
fields = ['Machine','Type','FilePath','LineNo','Content','Note']
with open(out_csv, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
print(len(rows))
PYEOF
)
py_rc=$?
set -e

if [[ ${py_rc} -eq 0 ]]; then
    status "OK" "${row_count} SSH entries → ${out_csv}"
    log_cmd "${LINUX_MACHINE}" "ssh-scan" \
        "read /root/.ssh/ /etc/ssh/sshd_config" \
        "Enumerate SSH keys, authorized_keys, known_hosts, sshd config" \
        "${out_csv}" "${row_count} rows"
    if [[ -f "${out_csv}" ]]; then
        priv=$(awk -F',' '$2=="PRIVATE_KEY"' "${out_csv}" 2>/dev/null | wc -l)
        [[ "${priv}" -gt 0 ]] && status "ALERT" "Private SSH key(s) present"
    fi
else
    status "ERROR" "SSH scan failed (rc=${py_rc})"
fi

# ════════════════════════════════════════════════════════════════════════════
section "L7. Auth and System Logs"
# ════════════════════════════════════════════════════════════════════════════

out_csv="${OUT_DIR}/${PREFIX}_auth_log.csv"

set +e
row_count=$(python3 - "${LINUX_MACHINE}" "${LINUX_MOUNT}" "${out_csv}" <<'PYEOF'
import sys, csv, os, re

machine, mount, out_csv = sys.argv[1:]

LOG_SOURCES = [
    (mount + '/var/log/auth.log',   'auth.log'),
    (mount + '/var/log/syslog',     'syslog'),
    (mount + '/var/log/dpkg.log',   'dpkg.log'),
]

# Syslog line: "Month DD HH:MM:SS hostname service[pid]: message"
SYSLOG_RE = re.compile(
    r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s*(.*)'
)

EVENT_PATTERNS = [
    (re.compile(r'\bAccepted\s+(?:password|publickey)\b', re.I), 'SSH_LOGIN_SUCCESS'),
    (re.compile(r'\bFailed\s+(?:password|publickey)\b',   re.I), 'SSH_LOGIN_FAIL'),
    (re.compile(r'\bInvalid\s+user\b',                    re.I), 'SSH_INVALID_USER'),
    (re.compile(r'\bsudo\b.*COMMAND',                     re.I), 'SUDO_EXEC'),
    (re.compile(r'\bsession opened\b',                    re.I), 'SESSION_OPEN'),
    (re.compile(r'\bsession closed\b',                    re.I), 'SESSION_CLOSE'),
    (re.compile(r'\bauthentication failure\b',            re.I), 'AUTH_FAILURE'),
    (re.compile(r'install|configure',                     re.I), 'PACKAGE_INSTALL'),
]

def classify_msg(msg):
    for pattern, label in EVENT_PATTERNS:
        if pattern.search(msg):
            return label
    return 'OTHER'

rows = []
for log_path, log_name in LOG_SOURCES:
    if not os.path.exists(log_path):
        continue
    if os.path.getsize(log_path) == 0:
        continue
    try:
        with open(log_path, 'r', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n')
                if not line.strip():
                    continue
                m = SYSLOG_RE.match(line)
                if not m:
                    continue
                ts, hostname, service, pid, msg = (
                    m.group(1), m.group(2), m.group(3),
                    m.group(4) or '', m.group(5))
                event_type = classify_msg(msg)
                # Only emit non-trivial events + all auth.log entries
                if log_name == 'auth.log' or event_type != 'OTHER':
                    rows.append({
                        'Machine':    machine,
                        'LogSource':  log_name,
                        'Timestamp':  ts,
                        'Hostname':   hostname,
                        'Service':    service,
                        'PID':        pid,
                        'Message':    msg[:300],
                        'EventType':  event_type,
                    })
    except Exception as e:
        rows.append({'Machine': machine, 'LogSource': log_name,
                     'Timestamp': '', 'Hostname': '', 'Service': 'ERROR',
                     'PID': '', 'Message': str(e), 'EventType': 'PARSE_ERROR'})

os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
fields = ['Machine','LogSource','Timestamp','Hostname','Service',
          'PID','Message','EventType']
with open(out_csv, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
print(len(rows))
PYEOF
)
py_rc=$?
set -e

if [[ ${py_rc} -eq 0 ]]; then
    status "OK" "${row_count} log entries → ${out_csv}"
    log_cmd "${LINUX_MACHINE}" "auth-syslog-parse" \
        "parse /var/log/auth.log /var/log/syslog /var/log/dpkg.log" \
        "Extract SSH, sudo, session, package install events" \
        "${out_csv}" "${row_count} rows"
    if [[ -f "${out_csv}" ]]; then
        ssh_ok=$(awk -F',' '$8=="SSH_LOGIN_SUCCESS"' "${out_csv}" 2>/dev/null | wc -l)
        sudo_hits=$(awk -F',' '$8=="SUDO_EXEC"' "${out_csv}" 2>/dev/null | wc -l)
        [[ "${ssh_ok}" -gt 0 ]]   && status "ALERT" "${ssh_ok} successful SSH login(s)"
        [[ "${sudo_hits}" -gt 0 ]] && status "INFO"  "${sudo_hits} sudo execution(s)"
    fi
else
    status "ERROR" "Auth/syslog parse failed (rc=${py_rc})"
fi

# ════════════════════════════════════════════════════════════════════════════
section "L8. CTF Artifacts"
# ════════════════════════════════════════════════════════════════════════════

out_csv="${OUT_DIR}/${PREFIX}_ctf_artifacts.csv"

# Known CTF-relevant files based on recon
CTF_FILES=(
    "root/Desktop/Checklist"
    "root/Desktop/mimikatz/mimikatz.exe"
    "root/Downloads/mimikatz_trunk.zip"
    "root/Documents/myfirsthack/hellworld.sh"
    "root/Documents/myfirsthack/firstscript"
    "root/Documents/myfirsthack/firstscript_fixed"
    "root/Documents/myfirsthack/didyouthinkwedmakeiteasy.jpg"
    "root/Documents/myfirsthack/bob.txt"
    "root/Pictures/keys.txt"
    "root/irZLAohL.jpeg"
    "root/snky"
    "root/Desktop/SuperSecretFile.txt"
)

set +e
row_count=$(python3 - "${LINUX_MACHINE}" "${LINUX_MOUNT}" "${out_csv}" \
    "${CTF_FILES[@]+"${CTF_FILES[@]}"}" <<'PYEOF'
import sys, csv, os, hashlib, re, subprocess

machine    = sys.argv[1]
mount      = sys.argv[2]
out_csv    = sys.argv[3]
ctf_relpaths = sys.argv[4:]

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return 'ERROR'

def read_text(path, max_bytes=2000):
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read(max_bytes).replace('\n', ' | ')
    except Exception:
        return 'BINARY_OR_UNREADABLE'

def strings_extract(path, min_len=6):
    try:
        result = subprocess.run(['strings', '-n', str(min_len), path],
                                capture_output=True, text=True, timeout=30)
        return result.stdout[:3000].replace('\n', ' | ') if result.returncode == 0 else ''
    except Exception:
        return ''

def binwalk_scan(path):
    try:
        result = subprocess.run(['binwalk', path],
                                capture_output=True, text=True, timeout=60)
        return result.stdout[:2000].replace('\n', ' | ') if result.returncode == 0 else ''
    except Exception:
        return ''

# Parse keys.txt keystroke log → decode flag
def parse_keystroke_log(text):
    """Decode a raw keystroke log with <KeyName> special keys."""
    special_skip = {'Right Shift','Left Shift','Shift','LAlt','RAlt',
                    'LCtrl','RCtrl','Left','Right','Up','Down','Home',
                    'End','Insert','Delete','Escape','Tab','Super_L'}
    result = []
    caps = False
    i = 0
    while i < len(text):
        if text[i] == '<':
            j = text.find('>', i)
            if j == -1:
                result.append(text[i]); i += 1; continue
            key = text[i+1:j]
            if key == 'Caps Lock':
                caps = not caps
            elif key == 'BackSpace':
                if result: result.pop()
            elif key == 'Space':
                result.append(' ')
            elif key in special_skip:
                pass
            else:
                # unknown — emit raw
                result.append(f'<{key}>')
            i = j + 1
        else:
            c = text[i].upper() if caps else text[i]
            result.append(c)
            i += 1
    return ''.join(result)

rows = []

for rel in ctf_relpaths:
    full = os.path.join(mount, rel)
    if not os.path.exists(full):
        continue
    try:
        size   = os.path.getsize(full) if os.path.isfile(full) else -1
        digest = sha256(full) if os.path.isfile(full) else 'DIR'
    except Exception:
        size, digest = -1, 'ERROR'

    # Determine artifact type and content
    ext = os.path.splitext(full)[1].lower()
    basename = os.path.basename(full)
    content_preview = ''
    note = ''

    if ext in ('.jpg', '.jpeg', '.png', '.gif', '.bmp'):
        strings_out = strings_extract(full)
        binwalk_out = binwalk_scan(full)
        content_preview = f'strings: {strings_out[:500]}'
        note = f'binwalk: {binwalk_out[:300]}'
    elif basename == 'keys.txt':
        raw = read_text(full, 5000)
        decoded = parse_keystroke_log(raw.replace(' | ', ''))
        content_preview = f'raw: {raw[:200]}'
        note = f'DECODED_FLAG: {decoded[:200]}'
    elif ext == '.zip':
        content_preview = strings_extract(full, 8)[:300]
        note = f'archive — see mimikatz_trunk.zip'
    else:
        content_preview = read_text(full, 500)

    artifact_type = 'IMAGE' if ext in ('.jpg','.jpeg','.png') else \
                    'SCRIPT' if ext in ('.sh','') else \
                    'ARCHIVE' if ext == '.zip' else \
                    'TEXT' if ext in ('.txt','') else 'BINARY'

    rows.append({
        'Machine':         machine,
        'ArtifactType':    artifact_type,
        'FilePath':        '/' + rel,
        'SHA256':          digest,
        'SizeBytes':       size,
        'ContentPreview':  content_preview[:500],
        'Note':            note[:500],
    })

# Also extract any lines containing 'flag' from bash_history CSV if it exists
bash_csv = out_csv.replace('_ctf_artifacts.csv', '_bash_history.csv')
if os.path.exists(bash_csv):
    try:
        with open(bash_csv, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('Category') == 'FLAG':
                    rows.append({
                        'Machine':        machine,
                        'ArtifactType':   'BASH_FLAG_CMD',
                        'FilePath':       '/root/.bash_history',
                        'SHA256':         '',
                        'SizeBytes':      0,
                        'ContentPreview': row.get('Command','')[:200],
                        'Note':           f"IOC: {row.get('IOC_Note','')}",
                    })
    except Exception:
        pass

os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
fields = ['Machine','ArtifactType','FilePath','SHA256','SizeBytes','ContentPreview','Note']
with open(out_csv, 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
print(len(rows))
PYEOF
)
py_rc=$?
set -e

if [[ ${py_rc} -eq 0 ]]; then
    status "OK" "${row_count} CTF artifact(s) → ${out_csv}"
    log_cmd "${LINUX_MACHINE}" "ctf-artifacts" \
        "hash + strings + binwalk on known CTF files" \
        "Hash key files, extract strings from images, decode keys.txt flag" \
        "${out_csv}" "${row_count} rows"

    # Print keys.txt decoded flag inline
    if [[ -f "${out_csv}" ]]; then
        keys_note=$(awk -F',' '/keys.txt/ && /DECODED_FLAG/{print $7}' "${out_csv}" 2>/dev/null | head -1)
        [[ -n "${keys_note}" ]] && status "ALERT" "keys.txt ${keys_note}"
    fi
else
    status "ERROR" "CTF artifacts scan failed (rc=${py_rc})"
fi

# ════════════════════════════════════════════════════════════════════════════
section "Summary"
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "Linux analysis output:"
echo ""
total_rows=0
for f in "${OUT_DIR}"/${PREFIX}_*.csv; do
    [[ -f "${f}" ]] || continue
    r=$(( $(wc -l < "${f}") - 1 ))
    printf "  %-8s  (%4d rows)  %s\n" "${LINUX_MACHINE}" "${r}" "${f}"
    total_rows=$(( total_rows + r ))
done
echo ""
echo "  Total data rows : ${total_rows}"
echo ""
echo " Phase 15 complete — $(date -u)"
