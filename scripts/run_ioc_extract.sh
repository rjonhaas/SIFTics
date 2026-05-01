#!/usr/bin/env bash
# run_ioc_extract.sh — Phase 9: IOC Extraction
#
# Reads ALL CSV files under analysis/ (recursively) and extracts IOCs
# from every cell in every row via a single embedded Python pass.
#
# Output:
#   analysis/ioc_master.csv    — one row per unique IOC, sorted by type then count DESC
#   analysis/ioc_summary.txt   — human-readable summary
#
# Logging: appends to analysis/commands.txt

set -uo pipefail

CASE_ROOT="/cases/jackofallhacks"
ANALYSIS_DIR="${CASE_ROOT}/analysis"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")

IOC_CSV="${ANALYSIS_DIR}/ioc_master.csv"
IOC_SUMMARY="${ANALYSIS_DIR}/ioc_summary.txt"

# ─── helpers ────────────────────────────────────────────────────────────────

log_cmd() {
    local machine="$1" tool="$2" cmd="$3" purpose="$4" output="$5" result="$6"
    cat >> "${COMMAND_LOG}" <<EOF

[${TIMESTAMP}] ${machine} | ${tool} | Python
  ${cmd}
  > Purpose  : ${purpose}
  > Output   : ${output}
  > Result   : ${result}

--------------------------------------------------------------------------------
EOF
}

section()  { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
status()   { printf "  [%-10s] %s\n" "$1" "$2"; }

# ─── skip guard ─────────────────────────────────────────────────────────────

section "Phase 9 — IOC Extraction"

if [[ -f "${IOC_CSV}" ]] && [[ $(wc -l < "${IOC_CSV}" 2>/dev/null) -gt 1 ]]; then
    status "SKIP" "ioc_master.csv already exists and has data — delete to re-run"
    echo ""
    if [[ -f "${IOC_SUMMARY}" ]]; then
        cat "${IOC_SUMMARY}"
    fi
    exit 0
fi

# ─── temp file with trap cleanup ─────────────────────────────────────────────

TMPPY=$(mktemp /tmp/ioc_extractor_XXXXXX.py)
trap 'rm -f "${TMPPY}"' EXIT INT TERM

# ─── embedded Python script ──────────────────────────────────────────────────

cat > "${TMPPY}" << 'PYEOF'
#!/usr/bin/env python3
"""
IOC Extractor — Phase 9
Reads all CSV files under ANALYSIS_DIR and extracts IOCs from every cell.
"""

import csv
import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from urllib.parse import urlparse

ANALYSIS_DIR = sys.argv[1]
IOC_CSV      = sys.argv[2]
IOC_SUMMARY  = sys.argv[3]

# ── regex patterns ────────────────────────────────────────────────────────────

RE_IPV4    = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
RE_URL     = re.compile(r'https?://[^\s,\'"<>]{4,}')
RE_SHA256  = re.compile(r'\b[0-9a-fA-F]{64}\b')
RE_SHA1    = re.compile(r'\b[0-9a-fA-F]{40}\b')
RE_MD5_RAW = re.compile(r'\b[0-9a-fA-F]{32}\b')
RE_WINPATH = re.compile(r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*')
RE_EMAIL   = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')

# ── noise filters ─────────────────────────────────────────────────────────────

SKIP_IP_PREFIXES = ('127.', '169.254.')
SKIP_IPS_EXACT   = {'255.255.255.255', '0.0.0.0'}

SKIP_DOMAIN_SUFFIXES = (
    '.local', '.corp', '.lan', '.internal', '.localdomain'
)

def is_noisy_ip(ip: str) -> bool:
    if ip in SKIP_IPS_EXACT:
        return True
    for pfx in SKIP_IP_PREFIXES:
        if ip.startswith(pfx):
            return True
    return False

def is_noisy_domain(domain: str) -> bool:
    if '.' not in domain:
        return True
    domain_lower = domain.lower()
    for suf in SKIP_DOMAIN_SUFFIXES:
        if domain_lower.endswith(suf):
            return True
    return False

def is_trivial_hash(h: str) -> bool:
    """All same character (000...0, fff...f, aaa...a, etc.)"""
    return len(set(h.lower())) == 1

def extract_machine(filepath: str) -> str:
    """
    Extracts machine name from path of the form:
      .../analysis/<MACHINE>/...
    Returns '' if not determinable.
    """
    norm = filepath.replace('\\', '/')
    # Find 'analysis/' in the path, next component is the machine
    marker = '/analysis/'
    idx = norm.find(marker)
    if idx == -1:
        return ''
    rest = norm[idx + len(marker):]
    parts = rest.split('/')
    if len(parts) >= 2:
        # analysis/<MACHINE>/...  — only if there is a subdirectory
        return parts[0]
    return ''

def is_analysis_tool_path(value: str) -> bool:
    """
    Skip IOC values that are paths under the analysis directory itself
    (avoid extracting our own tool output filenames as IOCs).
    """
    norm = value.replace('\\', '/')
    return '/analysis/' in norm and 'jackofallhacks' in norm

# ── IOC accumulator ───────────────────────────────────────────────────────────
# key: (ioc_type, ioc_value)
# value: {'count': int, 'machines': set, 'source_files': list, 'first_context': str}

ioc_data = defaultdict(lambda: {
    'count': 0,
    'machines': set(),
    'source_files': [],
    'first_context': ''
})

def record(ioc_type: str, ioc_value: str, machine: str, src_file: str, context: str):
    key = (ioc_type, ioc_value)
    entry = ioc_data[key]
    entry['count'] += 1
    if machine:
        entry['machines'].add(machine)
    if src_file not in entry['source_files']:
        entry['source_files'].append(src_file)
    if not entry['first_context']:
        entry['first_context'] = context[:80]

def extract_iocs_from_cell(cell: str, machine: str, src_file: str):
    if not cell or not cell.strip():
        return

    context = cell.strip()

    # — SHA256 (64 hex chars) — must come before SHA1 and MD5 checks
    for m in RE_SHA256.finditer(cell):
        v = m.group(0)
        if not is_trivial_hash(v) and not is_analysis_tool_path(v):
            record('sha256', v.lower(), machine, src_file, context)

    # — SHA1 (40 hex chars) — exclude positions already matched by SHA256
    sha256_spans = {m.span() for m in RE_SHA256.finditer(cell)}
    for m in RE_SHA1.finditer(cell):
        span = m.span()
        # make sure this 40-char match is NOT a substring of a sha256 match
        inside_sha256 = any(
            s_start <= span[0] and span[1] <= s_end
            for (s_start, s_end) in sha256_spans
        )
        if inside_sha256:
            continue
        v = m.group(0)
        if not is_trivial_hash(v) and not is_analysis_tool_path(v):
            record('sha1', v.lower(), machine, src_file, context)

    # — MD5 (32 hex chars) — exclude positions already in SHA1/SHA256 matches
    sha1_spans   = {m.span() for m in RE_SHA1.finditer(cell)}
    all_long_spans = sha256_spans | sha1_spans
    for m in RE_MD5_RAW.finditer(cell):
        span = m.span()
        inside_longer = any(
            s_start <= span[0] and span[1] <= s_end
            for (s_start, s_end) in all_long_spans
        )
        if inside_longer:
            continue
        v = m.group(0)
        if not is_trivial_hash(v) and not is_analysis_tool_path(v):
            record('md5', v.lower(), machine, src_file, context)

    # — URLs —
    for m in RE_URL.finditer(cell):
        v = m.group(0).rstrip('.,;)')
        if not is_analysis_tool_path(v):
            record('url', v, machine, src_file, context)
            # also extract domain from URL
            try:
                parsed = urlparse(v)
                domain = parsed.hostname or ''
                if domain and not is_noisy_domain(domain) and not is_analysis_tool_path(domain):
                    record('domain', domain.lower(), machine, src_file, context)
            except Exception:
                pass

    # — IPv4 —
    for m in RE_IPV4.finditer(cell):
        v = m.group(0)
        if not is_noisy_ip(v) and not is_analysis_tool_path(v):
            record('ipv4', v, machine, src_file, context)

    # — Windows file paths —
    for m in RE_WINPATH.finditer(cell):
        v = m.group(0).strip()
        if v and not is_analysis_tool_path(v):
            record('filepath_windows', v, machine, src_file, context)

    # — Email addresses —
    for m in RE_EMAIL.finditer(cell):
        v = m.group(0).lower()
        if not is_analysis_tool_path(v):
            record('email', v, machine, src_file, context)

# ── VirusTotal lookup ─────────────────────────────────────────────────────────

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_DELAY   = float(os.environ.get("VT_DELAY", "15"))  # seconds between requests (public=15, premium=1)
VT_LIMIT   = int(os.environ.get("VT_LIMIT", "20"))    # max hashes to query per run

VT_MAX_RETRIES = 3

def vt_lookup(hash_val: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
    req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY})
    for attempt in range(1, VT_MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious  = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total      = sum(stats.values()) if stats else 0
                name       = attrs.get("meaningful_name", "") or ""
                verdict    = "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")
                return {"verdict": verdict, "malicious": malicious,
                        "suspicious": suspicious, "total": total, "name": name}
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = int(e.headers.get("Retry-After", 60))
                print(f"  [VT rate-limit] 429 on {hash_val[:16]}… — waiting {wait}s (attempt {attempt}/{VT_MAX_RETRIES})", flush=True)
                time.sleep(wait)
                continue
            verdict = "NOT_FOUND" if e.code == 404 else f"HTTP_{e.code}"
            return {"verdict": verdict, "malicious": 0, "suspicious": 0, "total": 0, "name": ""}
        except Exception as e:
            return {"verdict": "ERROR", "malicious": 0, "suspicious": 0, "total": 0, "name": str(e)[:40]}
    return {"verdict": "RATE_LIMITED", "malicious": 0, "suspicious": 0, "total": 0, "name": ""}

# ── discover all CSVs ─────────────────────────────────────────────────────────

csv_files = []
for root, dirs, files in os.walk(ANALYSIS_DIR):
    for fname in files:
        if fname.lower().endswith('.csv'):
            csv_files.append(os.path.join(root, fname))

csv_files.sort()
print(f"[ioc_extractor] Found {len(csv_files)} CSV file(s) under {ANALYSIS_DIR}")

files_processed = 0
files_skipped   = 0

for fpath in csv_files:
    machine  = extract_machine(fpath)
    src_file = os.path.basename(fpath)

    # Skip the output file itself if it somehow already exists
    if os.path.abspath(fpath) == os.path.abspath(IOC_CSV):
        continue

    try:
        with open(fpath, 'r', encoding='utf-8-sig', errors='replace') as fh:
            # Quick binary sniff — skip files with high density of null bytes
            sample = fh.read(4096)
            null_ratio = sample.count('\x00') / max(len(sample), 1)
            if null_ratio > 0.10:
                files_skipped += 1
                print(f"  [SKIP-binary] {fpath}")
                continue
            fh.seek(0)

            try:
                reader = csv.reader(fh)
                for row in reader:
                    for cell in row:
                        extract_iocs_from_cell(cell, machine, src_file)
            except csv.Error as csv_err:
                print(f"  [WARN-csv] {fpath}: {csv_err}")
                files_skipped += 1
                continue

        files_processed += 1

    except (OSError, UnicodeDecodeError) as e:
        print(f"  [WARN-open] {fpath}: {e}")
        files_skipped += 1
        continue

print(f"[ioc_extractor] Processed: {files_processed}  Skipped: {files_skipped}")

# ── write ioc_master.csv ──────────────────────────────────────────────────────

TYPE_ORDER = ['ipv4', 'url', 'domain', 'md5', 'sha1', 'sha256',
              'filepath_windows', 'email']

def type_sort_key(item):
    ioc_type, _ = item[0]
    try:
        t_idx = TYPE_ORDER.index(ioc_type)
    except ValueError:
        t_idx = len(TYPE_ORDER)
    count = item[1]['count']
    return (t_idx, -count)

sorted_iocs = sorted(ioc_data.items(), key=type_sort_key)

with open(IOC_CSV, 'w', newline='', encoding='utf-8') as out_fh:
    writer = csv.writer(out_fh)
    writer.writerow([
        'ioc_type', 'ioc_value', 'count',
        'machines', 'source_files', 'first_seen_context'
    ])
    for (ioc_type, ioc_value), entry in sorted_iocs:
        machines_str     = ','.join(sorted(entry['machines']))
        source_files_str = ','.join(entry['source_files'][:5])
        writer.writerow([
            ioc_type,
            ioc_value,
            entry['count'],
            machines_str,
            source_files_str,
            entry['first_context']
        ])

total_unique = len(sorted_iocs)
print(f"[ioc_extractor] Wrote {total_unique} unique IOCs → {IOC_CSV}")

# ── per-type counts ───────────────────────────────────────────────────────────

type_counts = defaultdict(int)
for (ioc_type, _), _ in sorted_iocs:
    type_counts[ioc_type] += 1

# ── write ioc_summary.txt ─────────────────────────────────────────────────────

def top_iocs_for_type(ioc_type, n=10):
    entries = [
        (ioc_value, entry)
        for (t, ioc_value), entry in sorted_iocs
        if t == ioc_type
    ]
    entries.sort(key=lambda x: -x[1]['count'])
    return entries[:n]

def least_iocs_for_type(ioc_type, n=10):
    entries = [
        (ioc_value, entry)
        for (t, ioc_value), entry in sorted_iocs
        if t == ioc_type
    ]
    entries.sort(key=lambda x: x[1]['count'])
    return entries[:n]

lines = []
lines.append("IOC Extraction Summary — jackofallhacks")
lines.append("=" * 40)
lines.append(f"Total unique IOCs: {total_unique}")
lines.append("")

label_map = {
    'ipv4': 'ipv4',
    'url': 'url',
    'domain': 'domain',
    'md5': 'md5',
    'sha1': 'sha1',
    'sha256': 'sha256',
    'filepath_windows': 'filepath',
    'email': 'email',
}

for ioc_type in TYPE_ORDER:
    label = label_map.get(ioc_type, ioc_type)
    cnt   = type_counts.get(ioc_type, 0)
    lines.append(f"  {label:<10}: {cnt}")

lines.append("")

# TOP / LEAST IPs
top_ips = top_iocs_for_type('ipv4', 10)
if top_ips:
    lines.append("TOP IPs BY FREQUENCY:")
    for v, entry in top_ips:
        machines_str = ','.join(sorted(entry['machines'])) or '-'
        lines.append(f"  {v:<20}  (count={entry['count']}, machines={machines_str})")
    lines.append("")
least_ips = least_iocs_for_type('ipv4', 10)
if least_ips:
    lines.append("LEAST FREQUENT IPs:")
    for v, entry in least_ips:
        machines_str = ','.join(sorted(entry['machines'])) or '-'
        lines.append(f"  {v:<20}  (count={entry['count']}, machines={machines_str})")
    lines.append("")

# TOP / LEAST URLs
top_urls = top_iocs_for_type('url', 10)
if top_urls:
    lines.append("TOP URLs BY FREQUENCY:")
    for v, entry in top_urls:
        machines_str = ','.join(sorted(entry['machines'])) or '-'
        lines.append(f"  {v[:80]:<80}  (count={entry['count']}, machines={machines_str})")
    lines.append("")
least_urls = least_iocs_for_type('url', 10)
if least_urls:
    lines.append("LEAST FREQUENT URLs:")
    for v, entry in least_urls:
        machines_str = ','.join(sorted(entry['machines'])) or '-'
        lines.append(f"  {v[:80]:<80}  (count={entry['count']}, machines={machines_str})")
    lines.append("")

# TOP / LEAST Domains
top_domains = top_iocs_for_type('domain', 10)
if top_domains:
    lines.append("TOP DOMAINS BY FREQUENCY:")
    for v, entry in top_domains:
        machines_str = ','.join(sorted(entry['machines'])) or '-'
        lines.append(f"  {v:<40}  (count={entry['count']}, machines={machines_str})")
    lines.append("")
least_domains = least_iocs_for_type('domain', 10)
if least_domains:
    lines.append("LEAST FREQUENT DOMAINS:")
    for v, entry in least_domains:
        machines_str = ','.join(sorted(entry['machines'])) or '-'
        lines.append(f"  {v:<40}  (count={entry['count']}, machines={machines_str})")
    lines.append("")

# TOP / LEAST Hashes + VT for SHA256
for hash_type in ('sha256', 'sha1', 'md5'):
    top_hashes = top_iocs_for_type(hash_type, 5)
    if top_hashes:
        lines.append(f"TOP {hash_type.upper()} HASHES BY FREQUENCY:")
        for v, entry in top_hashes:
            machines_str = ','.join(sorted(entry['machines'])) or '-'
            lines.append(f"  {v}  (count={entry['count']}, machines={machines_str})")
        lines.append("")
    least_hashes = least_iocs_for_type(hash_type, 5)
    if least_hashes:
        lines.append(f"LEAST FREQUENT {hash_type.upper()} HASHES:")
        for v, entry in least_hashes:
            machines_str = ','.join(sorted(entry['machines'])) or '-'
            lines.append(f"  {v}  (count={entry['count']}, machines={machines_str})")
        lines.append("")
    if hash_type == 'sha256':
        all_sha256 = [
            (v, e) for (t, v), e in sorted_iocs if t == 'sha256'
        ]
        all_sha256.sort(key=lambda x: -x[1]['count'])
        if VT_API_KEY and all_sha256:
            lines.append(f"VIRUSTOTAL SHA256 LOOKUPS (top {min(VT_LIMIT, len(all_sha256))}):")
            for v, entry in all_sha256[:VT_LIMIT]:
                result = vt_lookup(v)
                machines_str = ','.join(sorted(entry['machines'])) or '-'
                det = f"{result['malicious']}/{result['total']}" if result['total'] else "-/-"
                name_str = f"  [{result['name']}]" if result['name'] else ""
                lines.append(f"  {v}  [{result['verdict']}] {det}{name_str}  (machines={machines_str})")
                time.sleep(VT_DELAY)
            lines.append("")
        elif all_sha256:
            lines.append("VIRUSTOTAL SHA256 LOOKUPS: n/a")
            lines.append("")

# TOP / LEAST Emails
top_emails = top_iocs_for_type('email', 10)
if top_emails:
    lines.append("TOP EMAIL ADDRESSES BY FREQUENCY:")
    for v, entry in top_emails:
        machines_str = ','.join(sorted(entry['machines'])) or '-'
        lines.append(f"  {v:<50}  (count={entry['count']}, machines={machines_str})")
    lines.append("")
least_emails = least_iocs_for_type('email', 10)
if least_emails:
    lines.append("LEAST FREQUENT EMAIL ADDRESSES:")
    for v, entry in least_emails:
        machines_str = ','.join(sorted(entry['machines'])) or '-'
        lines.append(f"  {v:<50}  (count={entry['count']}, machines={machines_str})")
    lines.append("")

# TOP / LEAST Windows paths
top_paths = top_iocs_for_type('filepath_windows', 10)
if top_paths:
    lines.append("TOP WINDOWS FILE PATHS BY FREQUENCY:")
    for v, entry in top_paths:
        machines_str = ','.join(sorted(entry['machines'])) or '-'
        lines.append(f"  {v[:80]:<80}  (count={entry['count']}, machines={machines_str})")
    lines.append("")
least_paths = least_iocs_for_type('filepath_windows', 10)
if least_paths:
    lines.append("LEAST FREQUENT WINDOWS FILE PATHS:")
    for v, entry in least_paths:
        machines_str = ','.join(sorted(entry['machines'])) or '-'
        lines.append(f"  {v[:80]:<80}  (count={entry['count']}, machines={machines_str})")
    lines.append("")

lines.append(f"Files processed : {files_processed}")
lines.append(f"Files skipped   : {files_skipped}")
lines.append(f"Generated       : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")

summary_text = '\n'.join(lines)
with open(IOC_SUMMARY, 'w', encoding='utf-8') as sf:
    sf.write(summary_text + '\n')

print(f"[ioc_extractor] Summary written → {IOC_SUMMARY}")
print(summary_text)
PYEOF

# ─── VT API key prompt ───────────────────────────────────────────────────────

if [[ -z "${VT_API_KEY:-}" ]]; then
    printf "\nWould you like to input a VirusTotal API key? [y/N]: " >/dev/tty
    read -r _vt_answer </dev/tty
    if [[ "${_vt_answer,,}" =~ ^y ]]; then
        printf "Enter VirusTotal API key: " >/dev/tty
        read -r VT_API_KEY </dev/tty
        export VT_API_KEY
    fi
fi

# ─── run ─────────────────────────────────────────────────────────────────────

status "RUN" "Scanning all CSVs under ${ANALYSIS_DIR} ..."

python3 "${TMPPY}" "${ANALYSIS_DIR}" "${IOC_CSV}" "${IOC_SUMMARY}"
PY_RC=$?

if [[ ${PY_RC} -ne 0 ]]; then
    status "ERROR" "Python extractor exited with code ${PY_RC}"
    log_cmd "ALL" "ioc_extractor.py" \
        "python3 ${TMPPY} ${ANALYSIS_DIR} ${IOC_CSV} ${IOC_SUMMARY}" \
        "Extract IPs/URLs/domains/hashes/paths from all analysis CSVs" \
        "analysis/ioc_master.csv" \
        "FAILED (exit ${PY_RC})"
    exit ${PY_RC}
fi

# ─── result stats ────────────────────────────────────────────────────────────

TOTAL_ROWS=$(( $(wc -l < "${IOC_CSV}" 2>/dev/null) - 1 ))
RESULT_MSG="Wrote ${TOTAL_ROWS} unique IOCs → ioc_master.csv; summary → ioc_summary.txt"

status "DONE" "${RESULT_MSG}"

# ─── log ─────────────────────────────────────────────────────────────────────

log_cmd "ALL" "ioc_extractor.py" \
    "python3 ${TMPPY} ${ANALYSIS_DIR} ${IOC_CSV} ${IOC_SUMMARY}" \
    "Extract IPs/URLs/domains/hashes/paths from all analysis CSVs" \
    "analysis/ioc_master.csv" \
    "${RESULT_MSG}"

echo ""
section "Phase 9 — Complete"
echo ""
