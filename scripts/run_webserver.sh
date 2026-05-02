#!/usr/bin/env bash
# run_webserver.sh — Phase 13: Web Server & Initial Access Triage
#
# Analyses IIS W3C access logs to detect:
#   A. Exploitation attempts (OS command injection, URL-decoded payloads)
#   B. LOLBIN download cradles (certutil, bitsadmin, PowerShell WebClient, etc.)
#   C. Operator sessions (source IP + User-Agent grouping, request cadence)
#   D. Webshell inventory (script files in web root with timestamps)
#
# Input priority:
#   1. Raw IIS W3C logs: <drive_root>/inetpub/logs/LogFiles/W3SVC*/*.log
#                        <drive_root>/Windows/System32/LogFiles/W3SVC*/*.log
#   2. iisGeolocate CSV fallback: analysis/<MACHINE>/Execution/IIS/*.csv
#   3. wwwroot filesystem: <drive_root>/inetpub/wwwroot/
#
# Output: analysis/<MACHINE>/WebServer/
#           injection_attempts.csv   — decoded payloads, HTTP status, response size
#           lolbin_downloads.csv     — download cradle events with dest path
#           operator_sessions.csv    — IP + UA session summary
#           webshell_inventory.csv   — script files found in web root
#         analysis/webserver_summary.txt
#
# Logging: appends to analysis/commands.txt

set -uo pipefail

# Resolve CASE_ROOT: $1 argument → inherited env var → interactive prompt
CASE_ROOT="${1:-${CASE_ROOT:-}}"
if [[ -z "$CASE_ROOT" ]]; then
    read -rp "Case root directory (e.g. /cases/jack2): " CASE_ROOT
fi
[[ -d "$CASE_ROOT" ]] || { echo "ERROR: CASE_ROOT '${CASE_ROOT}' does not exist." >&2; exit 1; }
export CASE_ROOT
ANALYSIS_DIR="${CASE_ROOT}/analysis"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")

# ─── helpers ──────────────────────────────────────────────────────────────────

log_cmd() {
    local machine="$1" tool="$2" cmd="$3" purpose="$4" output="$5" result="$6"
    cat >> "${COMMAND_LOG}" <<EOF

[${TIMESTAMP}] ${machine} | ${tool}
  ${cmd}
  > Purpose  : ${purpose}
  > Output   : ${output}
  > Result   : ${result}

--------------------------------------------------------------------------------
EOF
}

csv_has_data() {
    local dir="$1" pattern="${2:-*.csv}"
    [[ -d "${dir}" ]] || return 1
    while IFS= read -r f; do
        [[ $(wc -l < "${f}" 2>/dev/null) -gt 1 ]] && return 0
    done < <(find "${dir}" -maxdepth 3 -name "${pattern}" -size +100c 2>/dev/null)
    return 1
}

section()        { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
machine_header() { echo ""; echo "  ── $* ──"; }
status()         { printf "  [%-12s] %s\n" "$1" "$2"; }

# ─── machine discovery ────────────────────────────────────────────────────────

mapfile -t DRIVE_ROOTS < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name '$MFT' -print \
    | sort | xargs -I{} dirname {}
)

echo "════════════════════════════════════════════════════"
echo " Web Server & Initial Access Triage — jackofallhacks"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ─── embedded Python analyser ─────────────────────────────────────────────────

PY_SCRIPT=$(mktemp /tmp/webserver_triage_XXXXXX.py)
trap 'rm -f "${PY_SCRIPT}"' EXIT INT TERM

cat > "${PY_SCRIPT}" << 'PYEOF'
#!/usr/bin/env python3
"""
webserver_triage.py

Usage:
  python3 webserver_triage.py \
      --machine IIS \
      --drive-root /cases/jackofallhacks/IIS_Kape/E \
      --iis-csv-dir /cases/jackofallhacks/analysis/IIS/Execution/IIS \
      --out-dir /cases/jackofallhacks/analysis/IIS/WebServer

Outputs (all UTF-8, Unix line endings):
  injection_attempts.csv
  lolbin_downloads.csv
  operator_sessions.csv
  webshell_inventory.csv
"""

import argparse
import csv
import glob
import os
import re
import sys
import urllib.parse
from collections import defaultdict
from datetime import datetime, timedelta

# ── detection patterns ────────────────────────────────────────────────────────

# Patterns that indicate command injection / webshell interaction in query strings
INJECTION_RE = re.compile(
    r'(?:'
    r'cmd=|command=|exec=|execute=|shell='   # explicit cmd parameters
    r'|powershell(?:\.exe)?'                  # PowerShell references
    r'|cmd\.exe'                              # cmd.exe
    r'|/bin/(?:sh|bash)'                      # Unix shells (pentest on Windows?)
    r'|certutil'                              # certutil LOLBIN
    r'|bitsadmin'                             # bitsadmin LOLBIN
    r'|mshta|wscript|cscript'                 # script hosts
    r'|Invoke-(?:WebRequest|Expression|Command|Item)'  # PowerShell cmdlets
    r'|\bIEX\b|\bIWR\b'                       # PowerShell aliases
    r'|-EncodedCommand|-enc\b'               # Base64 execution
    r'|Net\.WebClient|DownloadFile|DownloadString'  # download methods
    r'|whoami|ipconfig|hostname|systeminfo'   # recon commands
    r'|net\s+(?:user|group|localgroup|share)' # net commands
    r'|reg\s+(?:query|add|delete)'            # registry commands
    r'|\.\./|\.\.\\|\.\.\%2[Ff]'             # path traversal
    r'|<script|javascript:|vbscript:'         # XSS/injection markers
    r')',
    re.IGNORECASE
)

# Patterns that indicate LOLBIN download cradles (in decoded query strings)
LOLBIN_RE = [
    (re.compile(r'certutil\s+.*-urlcache\s+.*-f\s+(https?://\S+)', re.IGNORECASE), 'certutil.exe'),
    (re.compile(r'certutil\s+.*-f\s+(https?://\S+)', re.IGNORECASE),               'certutil.exe'),
    (re.compile(r'bitsadmin\s+/transfer\s+\S+\s+(https?://\S+)', re.IGNORECASE),   'bitsadmin.exe'),
    (re.compile(r'Invoke-WebRequest\s+.*?(https?://\S+)', re.IGNORECASE),           'powershell.exe'),
    (re.compile(r'WebClient\)\.DownloadFile\s*\(["\']?(https?://\S+)', re.IGNORECASE), 'powershell.exe'),
    (re.compile(r'DownloadString\s*\(["\']?(https?://\S+)', re.IGNORECASE),         'powershell.exe'),
    (re.compile(r'\bcurl\b.*?(https?://\S+)', re.IGNORECASE),                       'curl.exe'),
    (re.compile(r'\bwget\b.*?(https?://\S+)', re.IGNORECASE),                       'wget.exe'),
]

# Destination path pattern (certutil -f <url> <dest>)
DEST_RE = re.compile(
    r'(?:certutil[^\n]*-f\s+\S+\s+(\S+)'
    r'|/transfer\s+\S+\s+\S+\s+(\S+)'
    r'|DownloadFile[^\n]*,\s*["\']?([^"\')\s]+))',
    re.IGNORECASE
)

# Script extensions considered webshell candidates
WEBSHELL_EXTS = {'.aspx', '.asp', '.php', '.jsp', '.jspx', '.cfm',
                 '.ashx', '.axd', '.shtml', '.phtml', '.php5'}

# Benign filenames that are default IIS content (not flagged)
BENIGN_NAMES = {'default.aspx', 'index.aspx', 'global.asax', 'web.config',
                'error.aspx', 'notfound.aspx', 'login.aspx'}

# ── IIS W3C log parser ────────────────────────────────────────────────────────

def parse_iis_w3c(log_files):
    """Yield dicts from IIS W3C log files, URL-decoding cs-uri-query."""
    field_names = []
    for path in sorted(log_files):
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                for line in fh:
                    line = line.rstrip('\r\n')
                    if line.startswith('#Fields:'):
                        field_names = line[9:].strip().split()
                    elif line.startswith('#') or not line:
                        continue
                    elif field_names:
                        parts = line.split(' ', len(field_names) - 1)
                        if len(parts) < len(field_names):
                            continue
                        row = dict(zip(field_names, parts))
                        # Build UTC datetime string
                        row['_datetime'] = (row.get('date', '') + ' '
                                            + row.get('time', '')).strip()
                        # URL-decode query string
                        raw_q = row.get('cs-uri-query', '-')
                        if raw_q and raw_q != '-':
                            try:
                                row['_decoded_query'] = urllib.parse.unquote_plus(raw_q)
                            except Exception:
                                row['_decoded_query'] = raw_q
                        else:
                            row['_decoded_query'] = ''
                        yield row
        except OSError as e:
            print(f'  [WARN] Cannot read {path}: {e}', file=sys.stderr)


def parse_iis_geo_csv(csv_files):
    """
    Fallback: read iisGeolocate CSV output (Phase 5).
    Column names vary — map common aliases to canonical names.
    """
    FIELD_MAP = {
        'datetime': '_datetime', 'date': '_datetime',
        'c-ip': 'c-ip', 'clientip': 'c-ip', 'cip': 'c-ip',
        'cs-method': 'cs-method', 'method': 'cs-method',
        'cs-uri-stem': 'cs-uri-stem', 'stem': 'cs-uri-stem', 'uristem': 'cs-uri-stem',
        'cs-uri-query': 'cs-uri-query', 'query': 'cs-uri-query', 'uriquery': 'cs-uri-query',
        'sc-status': 'sc-status', 'status': 'sc-status',
        'sc-bytes': 'sc-bytes', 'scbytes': 'sc-bytes',
        'cs(user-agent)': 'cs(User-Agent)', 'useragent': 'cs(User-Agent)',
        'cs-useragent': 'cs(User-Agent)', 'cs-username': 'cs-username',
    }
    for path in sorted(csv_files):
        try:
            with open(path, 'r', encoding='utf-8-sig', errors='replace') as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    continue
                for raw_row in reader:
                    row = {}
                    for k, v in raw_row.items():
                        canon = FIELD_MAP.get((k or '').lower().strip(), k)
                        row[canon] = (v or '').strip()
                    if '_datetime' not in row:
                        row['_datetime'] = (row.get('date', '') + ' '
                                            + row.get('time', '')).strip()
                    raw_q = row.get('cs-uri-query', '-')
                    if raw_q and raw_q != '-':
                        try:
                            row['_decoded_query'] = urllib.parse.unquote_plus(raw_q)
                        except Exception:
                            row['_decoded_query'] = raw_q
                    else:
                        row['_decoded_query'] = ''
                    yield row
        except OSError as e:
            print(f'  [WARN] Cannot read {path}: {e}', file=sys.stderr)


# ── wwwroot scanner ───────────────────────────────────────────────────────────

def find_webshell_candidates(drive_root):
    """Walk web root directories, return list of (path, ext, size, ctime, mtime)."""
    web_roots = []
    for candidate in [
        os.path.join(drive_root, 'inetpub', 'wwwroot'),
        os.path.join(drive_root, 'inetpub', 'wwwroot', 'aspnet_client'),
    ]:
        if os.path.isdir(candidate):
            web_roots.append(candidate)

    results = []
    seen = set()
    for web_root in web_roots:
        for dirpath, _, filenames in os.walk(web_root):
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                if full in seen:
                    continue
                seen.add(full)
                _, ext = os.path.splitext(fname.lower())
                if ext not in WEBSHELL_EXTS:
                    continue
                try:
                    stat = os.stat(full)
                    results.append({
                        'path': full,
                        'filename': fname,
                        'extension': ext,
                        'size_bytes': stat.st_size,
                        'created_utc': datetime.utcfromtimestamp(
                            stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                        'modified_utc': datetime.utcfromtimestamp(
                            stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'assessment': (
                            'BENIGN_DEFAULT' if fname.lower() in BENIGN_NAMES
                            else 'REVIEW'
                        ),
                    })
                except OSError:
                    pass
    return results


# ── operator session analysis ─────────────────────────────────────────────────

def build_sessions(rows, gap_minutes=30):
    """
    Group requests by (c-ip, User-Agent).  A new session starts when
    the gap between consecutive requests exceeds gap_minutes.
    """
    from collections import defaultdict

    buckets = defaultdict(list)
    for r in rows:
        ip = r.get('c-ip', '-')
        ua = r.get('cs(User-Agent)', '-')
        dt_str = r.get('_datetime', '')
        try:
            dt = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue
        buckets[(ip, ua)].append(dt)

    sessions = []
    for (ip, ua), times in buckets.items():
        times.sort()
        # split into sessions by gap
        session_start = times[0]
        prev = times[0]
        req_count = 1
        for t in times[1:]:
            if (t - prev).total_seconds() > gap_minutes * 60:
                sessions.append({
                    'source_ip': ip,
                    'user_agent': urllib.parse.unquote_plus(ua),
                    'session_start_utc': session_start.strftime('%Y-%m-%d %H:%M:%S'),
                    'session_end_utc': prev.strftime('%Y-%m-%d %H:%M:%S'),
                    'request_count': req_count,
                    'phase': classify_ua(ua),
                })
                session_start = t
                req_count = 1
            else:
                req_count += 1
            prev = t
        sessions.append({
            'source_ip': ip,
            'user_agent': urllib.parse.unquote_plus(ua),
            'session_start_utc': session_start.strftime('%Y-%m-%d %H:%M:%S'),
            'session_end_utc': prev.strftime('%Y-%m-%d %H:%M:%S'),
            'request_count': req_count,
            'phase': classify_ua(ua),
        })
    sessions.sort(key=lambda x: x['session_start_utc'])
    return sessions


def classify_ua(ua):
    """Classify UA as BROWSER (interactive operator), TOOL (automated), or SCANNER."""
    ua_l = ua.lower()
    if any(x in ua_l for x in ('mozilla', 'chrome', 'firefox', 'safari', 'msie', 'edge')):
        return 'BROWSER (operator)'
    if any(x in ua_l for x in ('curl', 'python-requests', 'python-urllib', 'wget',
                                 'go-http', 'libwww', 'okhttp', 'java/')):
        return 'TOOL (automated)'
    if any(x in ua_l for x in ('nmap', 'zgrab', 'masscan', 'nuclei', 'sqlmap', 'nikto')):
        return 'SCANNER'
    return 'UNKNOWN'


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--machine',      required=True)
    ap.add_argument('--drive-root',   required=True)
    ap.add_argument('--iis-csv-dir',  required=True, help='Phase 5 iisGeolocate output dir')
    ap.add_argument('--out-dir',      required=True)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # ── find input log files ──────────────────────────────────────────────────
    raw_logs = []
    for log_pattern in [
        os.path.join(args.drive_root, 'inetpub', 'logs', 'LogFiles', 'W3SVC*', '*.log'),
        os.path.join(args.drive_root, 'inetpub', 'logs', 'LogFiles', '*.log'),
        os.path.join(args.drive_root, 'Windows', 'System32', 'LogFiles', 'W3SVC*', '*.log'),
    ]:
        raw_logs.extend(glob.glob(log_pattern))
    raw_logs = list(set(raw_logs))

    geo_csvs = glob.glob(os.path.join(args.iis_csv_dir, '*.csv'))

    if raw_logs:
        print(f'  [INFO] Using {len(raw_logs)} raw IIS W3C log file(s)')
        rows = list(parse_iis_w3c(raw_logs))
    elif geo_csvs:
        print(f'  [INFO] No raw logs found — falling back to {len(geo_csvs)} iisGeolocate CSV(s)')
        rows = list(parse_iis_geo_csv(geo_csvs))
    else:
        print(f'  [SKIP] No IIS logs or iisGeolocate CSVs found for {args.machine}')
        sys.exit(0)

    print(f'  [INFO] Parsed {len(rows):,} log entries')

    # ── A. Injection attempts ─────────────────────────────────────────────────
    injection_rows = []
    for r in rows:
        decoded = r.get('_decoded_query', '')
        full_url = (r.get('cs-uri-stem', '') + '?' + decoded).rstrip('?')
        if decoded and INJECTION_RE.search(decoded):
            injection_rows.append({
                'datetime_utc':   r.get('_datetime', ''),
                'source_ip':      r.get('c-ip', '-'),
                'method':         r.get('cs-method', '-'),
                'uri_stem':       r.get('cs-uri-stem', '-'),
                'decoded_query':  decoded[:2000],       # cap long payloads
                'http_status':    r.get('sc-status', '-'),
                'response_bytes': r.get('sc-bytes', '-'),
                'user_agent':     urllib.parse.unquote_plus(
                                      r.get('cs(User-Agent)', '-')),
            })

    injection_out = os.path.join(args.out_dir, 'injection_attempts.csv')
    with open(injection_out, 'w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=[
            'datetime_utc', 'source_ip', 'method', 'uri_stem',
            'decoded_query', 'http_status', 'response_bytes', 'user_agent'])
        w.writeheader()
        w.writerows(injection_rows)
    print(f'  [OK] injection_attempts.csv  — {len(injection_rows):,} rows')

    # ── B. LOLBIN downloads ───────────────────────────────────────────────────
    lolbin_rows = []
    for r in rows:
        decoded = r.get('_decoded_query', '')
        if not decoded:
            continue
        for pattern, binary in LOLBIN_RE:
            m = pattern.search(decoded)
            if m:
                src_url = m.group(1) if m.lastindex else ''
                # Try to find destination path
                dest_m = DEST_RE.search(decoded)
                dest = next((g for g in (dest_m.groups() if dest_m else []) if g), '')
                lolbin_rows.append({
                    'datetime_utc':    r.get('_datetime', ''),
                    'source_ip':       r.get('c-ip', '-'),
                    'method':          r.get('cs-method', '-'),
                    'uri_stem':        r.get('cs-uri-stem', '-'),
                    'lolbin':          binary,
                    'source_url':      src_url,
                    'destination_path': dest,
                    'decoded_query':   decoded[:2000],
                    'http_status':     r.get('sc-status', '-'),
                    'response_bytes':  r.get('sc-bytes', '-'),
                })
                break  # one entry per request

    lolbin_out = os.path.join(args.out_dir, 'lolbin_downloads.csv')
    with open(lolbin_out, 'w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=[
            'datetime_utc', 'source_ip', 'method', 'uri_stem',
            'lolbin', 'source_url', 'destination_path',
            'decoded_query', 'http_status', 'response_bytes'])
        w.writeheader()
        w.writerows(lolbin_rows)
    print(f'  [OK] lolbin_downloads.csv    — {len(lolbin_rows):,} rows')

    # ── C. Operator sessions ──────────────────────────────────────────────────
    sessions = build_sessions(rows, gap_minutes=30)
    session_out = os.path.join(args.out_dir, 'operator_sessions.csv')
    with open(session_out, 'w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=[
            'source_ip', 'phase', 'session_start_utc', 'session_end_utc',
            'request_count', 'user_agent'])
        w.writeheader()
        w.writerows(sessions)
    print(f'  [OK] operator_sessions.csv   — {len(sessions):,} sessions')

    # ── D. Webshell inventory ─────────────────────────────────────────────────
    webshells = find_webshell_candidates(args.drive_root)
    webshell_out = os.path.join(args.out_dir, 'webshell_inventory.csv')
    with open(webshell_out, 'w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=[
            'filename', 'extension', 'size_bytes', 'created_utc',
            'modified_utc', 'assessment', 'path'])
        w.writeheader()
        w.writerows(webshells)
    print(f'  [OK] webshell_inventory.csv  — {len(webshells):,} files')

    # ── return counts for summary ─────────────────────────────────────────────
    print(f'COUNTS:{len(injection_rows)}:{len(lolbin_rows)}:{len(sessions)}:{len(webshells)}')


if __name__ == '__main__':
    main()

PYEOF

# ─── per-machine processing ───────────────────────────────────────────────────

declare -A MACHINE_INJECTIONS
declare -A MACHINE_LOGINS
declare -A MACHINE_SESSIONS
declare -A MACHINE_WEBSHELLS

section "A-D. Web Server Triage — all machines"

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')

    machine_header "${machine} (drive ${drive}:)"

    out_dir="${ANALYSIS_DIR}/${machine}/WebServer"
    iis_csv_dir="${ANALYSIS_DIR}/${machine}/Execution/IIS"

    # Skip if no IIS logs and no iisGeolocate CSV for this machine
    has_raw_logs=false
    for pattern in \
        "${drive_root}/inetpub/logs/LogFiles/W3SVC1/"*.log \
        "${drive_root}/inetpub/logs/LogFiles/W3SVC"[0-9]*"/"*.log \
        "${drive_root}/Windows/System32/LogFiles/W3SVC"*"/"*.log
    do
        # glob expansion — check if any matches exist
        for f in ${pattern}; do
            [[ -f "${f}" ]] && has_raw_logs=true && break 2
        done
    done

    has_geo_csv=false
    if csv_has_data "${iis_csv_dir}" "*.csv"; then
        has_geo_csv=true
    fi

    if [[ "${has_raw_logs}" == "false" && "${has_geo_csv}" == "false" ]]; then
        status "SKIP" "No IIS logs or iisGeolocate CSVs found"
        MACHINE_INJECTIONS["${machine}"]="0"
        MACHINE_LOGINS["${machine}"]="0"
        MACHINE_SESSIONS["${machine}"]="0"
        MACHINE_WEBSHELLS["${machine}"]="0"
        continue
    fi

    # Skip if already done
    if csv_has_data "${out_dir}" "injection_attempts.csv" && \
       csv_has_data "${out_dir}" "lolbin_downloads.csv"; then
        status "SKIP" "WebServer output already exists"
        # Read existing counts for summary
        inj=$(( $(wc -l < "${out_dir}/injection_attempts.csv" 2>/dev/null) - 1 ))
        lol=$(( $(wc -l < "${out_dir}/lolbin_downloads.csv"   2>/dev/null) - 1 ))
        ses=$(( $(wc -l < "${out_dir}/operator_sessions.csv"  2>/dev/null) - 1 ))
        wsh=$(( $(wc -l < "${out_dir}/webshell_inventory.csv" 2>/dev/null) - 1 ))
        MACHINE_INJECTIONS["${machine}"]="${inj}"
        MACHINE_LOGINS["${machine}"]="${lol}"
        MACHINE_SESSIONS["${machine}"]="${ses}"
        MACHINE_WEBSHELLS["${machine}"]="${wsh}"
        continue
    fi

    mkdir -p "${out_dir}"

    cmd="python3 ${PY_SCRIPT} --machine ${machine} --drive-root ${drive_root} --iis-csv-dir ${iis_csv_dir} --out-dir ${out_dir}"
    status "RUN" "python3 webserver_triage.py"

    set +e
    py_out=$(python3 "${PY_SCRIPT}" \
        --machine     "${machine}" \
        --drive-root  "${drive_root}" \
        --iis-csv-dir "${iis_csv_dir}" \
        --out-dir     "${out_dir}" 2>&1)
    py_rc=$?
    set -e

    echo "${py_out}" | sed 's/^/    /'

    if [[ ${py_rc} -ne 0 ]]; then
        status "ERROR" "Python exited ${py_rc}"
        log_cmd "${machine}" "webserver_triage.py" "${cmd}" \
            "Web server triage" "${out_dir}" "ERROR (exit ${py_rc})"
        MACHINE_INJECTIONS["${machine}"]="ERROR"
        MACHINE_LOGINS["${machine}"]="ERROR"
        MACHINE_SESSIONS["${machine}"]="ERROR"
        MACHINE_WEBSHELLS["${machine}"]="ERROR"
        continue
    fi

    # Parse COUNTS line emitted by Python
    counts_line=$(echo "${py_out}" | grep '^COUNTS:' || true)
    if [[ -n "${counts_line}" ]]; then
        IFS=':' read -r _ inj lol ses wsh <<< "${counts_line}"
    else
        inj=$(( $(wc -l < "${out_dir}/injection_attempts.csv" 2>/dev/null) - 1 ))
        lol=$(( $(wc -l < "${out_dir}/lolbin_downloads.csv"   2>/dev/null) - 1 ))
        ses=$(( $(wc -l < "${out_dir}/operator_sessions.csv"  2>/dev/null) - 1 ))
        wsh=$(( $(wc -l < "${out_dir}/webshell_inventory.csv" 2>/dev/null) - 1 ))
    fi

    MACHINE_INJECTIONS["${machine}"]="${inj}"
    MACHINE_LOGINS["${machine}"]="${lol}"
    MACHINE_SESSIONS["${machine}"]="${ses}"
    MACHINE_WEBSHELLS["${machine}"]="${wsh}"

    log_cmd "${machine}" "webserver_triage.py" "${cmd}" \
        "Web server triage: injection/LOLBIN/session/webshell analysis" \
        "${out_dir}" "OK — ${inj} injection(s), ${lol} LOLBIN(s), ${ses} session(s), ${wsh} webshell(s)"
done

# ─── global summary ───────────────────────────────────────────────────────────

section "Summary"

SUMMARY_FILE="${ANALYSIS_DIR}/webserver_summary.txt"

{
printf "Web Server Triage Summary — jackofallhacks\n"
printf "==========================================\n"
printf "Generated : %s\n\n" "$(date -u)"

printf "  %-10s  %-14s  %-14s  %-12s  %-14s\n" \
    "Machine" "Injection Hits" "LOLBIN Events" "Sessions" "Webshell Files"
printf "  %s\n" "──────────────────────────────────────────────────────────────"

total_inj=0; total_lol=0; total_ses=0; total_wsh=0

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    inj="${MACHINE_INJECTIONS["${machine}"]:-0}"
    lol="${MACHINE_LOGINS["${machine}"]:-0}"
    ses="${MACHINE_SESSIONS["${machine}"]:-0}"
    wsh="${MACHINE_WEBSHELLS["${machine}"]:-0}"

    printf "  %-10s  %-14s  %-14s  %-12s  %-14s\n" \
        "${machine}" "${inj}" "${lol}" "${ses}" "${wsh}"

    [[ "${inj}" =~ ^[0-9]+$ ]] && total_inj=$(( total_inj + inj ))
    [[ "${lol}" =~ ^[0-9]+$ ]] && total_lol=$(( total_lol + lol ))
    [[ "${ses}" =~ ^[0-9]+$ ]] && total_ses=$(( total_ses + ses ))
    [[ "${wsh}" =~ ^[0-9]+$ ]] && total_wsh=$(( total_wsh + wsh ))
done

printf "  %s\n" "──────────────────────────────────────────────────────────────"
printf "  %-10s  %-14s  %-14s  %-12s  %-14s\n" \
    "TOTAL" "${total_inj}" "${total_lol}" "${total_ses}" "${total_wsh}"

echo ""

if [[ ${total_inj} -gt 0 ]]; then
    echo "  [HIGH] Injection attempts detected (${total_inj})."
    echo "         Review <MACHINE>/WebServer/injection_attempts.csv for decoded payloads."
fi
if [[ ${total_wsh} -gt 0 ]]; then
    echo "  [HIGH] Script files found in web root (${total_wsh})."
    echo "         Review <MACHINE>/WebServer/webshell_inventory.csv for webshell candidates."
fi
if [[ ${total_lol} -gt 0 ]]; then
    echo "  [HIGH] LOLBIN download events detected (${total_lol})."
    echo "         Review <MACHINE>/WebServer/lolbin_downloads.csv for payload delivery paths."
fi
if [[ ${total_ses} -gt 0 ]]; then
    echo "  [MED ] Operator sessions profiled (${total_ses} session windows)."
    echo "         Review <MACHINE>/WebServer/operator_sessions.csv to distinguish operator phases."
fi

echo ""
echo "Output root:"
for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    [[ "${MACHINE_INJECTIONS["${machine}"]:-0}" == "0" ]] \
        && [[ "${MACHINE_WEBSHELLS["${machine}"]:-0}" == "0" ]] && continue
    echo "  ${ANALYSIS_DIR}/${machine}/WebServer/"
done

} | tee "${SUMMARY_FILE}"

echo ""
echo " Summary written to: ${SUMMARY_FILE}"
echo "════════════════════════════════════════════════════"
