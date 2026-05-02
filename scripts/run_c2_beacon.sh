#!/usr/bin/env bash
# run_c2_beacon.sh — Phase 10: C2 Beacon Detection
#
# Statistically detects C2 beaconing behaviour by analysing inter-request
# intervals from IIS access logs.  Input priority:
#   1. iisGeolocate CSV output from Phase 5 (analysis/<MACHINE>/Execution/IIS/*.csv)
#   2. Raw IIS W3C log files  (<drive_root>/inetpub/logs/LogFiles/W3SVC*/*.log)
#
# Output: analysis/<MACHINE>/Execution/IIS/c2_beacon.csv
#         (sorted by BeaconScore DESC; BEACON_LIKELY / BEACON_POSSIBLE IPs
#          also printed to stdout as one-line summaries)
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

run_tool() {
    set +e; out=$(eval "$1" 2>&1); rc=$?; set -e
    echo "${out}"; return ${rc}
}

# Returns 0 if at least one CSV matching PATTERN exists under DIR with >1 line
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

# ─── machine discovery (same anchor as all other phases) ─────────────────────

mapfile -t DRIVE_ROOTS < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name '$MFT' -print \
    | sort | xargs -I{} dirname {}
)

echo "════════════════════════════════════════════════════"
echo " C2 Beacon Detection — jackofallhacks"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ─── embedded Python beacon analyser ─────────────────────────────────────────

PY_SCRIPT=$(mktemp /tmp/c2_beacon_XXXXXX.py)
trap 'rm -f "${PY_SCRIPT}"' EXIT INT TERM

cat > "${PY_SCRIPT}" << 'PYEOF'
#!/usr/bin/env python3
"""
c2_beacon_analyser.py

Usage:
  python3 <script> --input-csv CSV_OR_DIR --output-dir DIR --machine MACHINE

  --input-csv  : path to a single iisGeolocate CSV, a directory containing
                 iisGeolocate CSVs, or a directory of raw IIS W3C log files
  --output-dir : directory to write c2_beacon.csv into
  --machine    : machine label written into every output row
"""

import argparse
import csv
import math
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ── Known C2 check-in intervals (seconds) ────────────────────────────────────
KNOWN_C2_INTERVALS = [30, 60, 120, 300, 600, 900, 1800, 3600]
C2_MATCH_TOLERANCE = 0.10   # within 10 %

# ── Generic / empty user-agent fragments that suggest automation ──────────────
GENERIC_UA_PATTERNS = re.compile(
    r'(^$|^\-$|python|curl|go-http|java|libwww|wget|nikto|nmap|masscan|zgrab)',
    re.IGNORECASE
)

# ── Output CSV columns ────────────────────────────────────────────────────────
OUTPUT_FIELDS = [
    'SourceIP', 'TotalRequests', 'UniqueURIs', 'UniqueUserAgents',
    'MostCommonURI', 'MostCommonUserAgent',
    'MeanIntervalSec', 'MedianIntervalSec', 'StdDevSec', 'CoeffVariation',
    'BeaconScore', 'Classification', 'MatchedC2Interval',
    'FirstSeen', 'LastSeen', 'Machine',
]


# ── Timestamp parsing helpers ─────────────────────────────────────────────────

def _try_parse_ts(value: str) -> datetime | None:
    """Try a handful of common IIS / iisGeolocate timestamp formats."""
    value = value.strip()
    for fmt in (
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S.%f',
        '%m/%d/%Y %H:%M:%S',
        '%d/%b/%Y:%H:%M:%S %z',
    ):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


# ── iisGeolocate CSV reader ───────────────────────────────────────────────────

def load_iisgeo_csv(path: str):
    """
    Return list of dicts with keys: timestamp (datetime), ip (str),
    uri (str), user_agent (str), status (int).
    """
    records = []
    with open(path, newline='', encoding='utf-8-sig') as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            return records
        fields_lower = {f.lower(): f for f in reader.fieldnames}

        # Detect timestamp column(s)
        ts_col = None
        date_col = None
        time_col = None
        for candidate in ('datetime', 'timestamp'):
            if candidate in fields_lower:
                ts_col = fields_lower[candidate]
                break
        if ts_col is None:
            for candidate in ('date',):
                if candidate in fields_lower:
                    date_col = fields_lower[candidate]
                    break
            for candidate in ('time',):
                if candidate in fields_lower:
                    time_col = fields_lower[candidate]
                    break

        # Detect IP column
        ip_col = None
        for candidate in ('c-ip', 'clientip', 'client_ip', 'sourceip',
                           'c_ip', 'ipaddress', 'ip', 'clientipaddress'):
            if candidate in fields_lower:
                ip_col = fields_lower[candidate]
                break

        # Detect URI column
        uri_col = None
        for candidate in ('cs-uri-stem', 'uristem', 'uri-stem', 'uri',
                           'cs_uri_stem', 'csuri', 'uripath', 'path'):
            if candidate in fields_lower:
                uri_col = fields_lower[candidate]
                break

        # Detect user-agent column
        ua_col = None
        for candidate in ('cs(user-agent)', 'useragent', 'user-agent',
                           'cs_user_agent', 'ua', 'browser'):
            if candidate in fields_lower:
                ua_col = fields_lower[candidate]
                break

        # Detect status column
        status_col = None
        for candidate in ('sc-status', 'scstatus', 'status', 'httpstatus',
                           'sc_status', 'responsecode'):
            if candidate in fields_lower:
                status_col = fields_lower[candidate]
                break

        for row in reader:
            # Build timestamp
            ts = None
            if ts_col:
                ts = _try_parse_ts(row.get(ts_col, ''))
            elif date_col and time_col:
                combined = (row.get(date_col, '') + ' ' +
                            row.get(time_col, '')).strip()
                ts = _try_parse_ts(combined)
            elif date_col:
                ts = _try_parse_ts(row.get(date_col, ''))
            if ts is None:
                continue

            ip  = row.get(ip_col, '').strip()  if ip_col  else ''
            uri = row.get(uri_col, '').strip() if uri_col else ''
            ua  = row.get(ua_col, '').strip()  if ua_col  else ''
            try:
                sc = int(row.get(status_col, 0)) if status_col else 0
            except (ValueError, TypeError):
                sc = 0

            if not ip or ip in ('-', ''):
                continue

            records.append({'timestamp': ts, 'ip': ip, 'uri': uri,
                             'user_agent': ua, 'status': sc})
    return records


# ── Raw W3C IIS log reader ────────────────────────────────────────────────────

def load_raw_w3c(path: str):
    """Parse a single raw IIS W3C log file."""
    records = []
    fields = []
    with open(path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            line = line.rstrip('\r\n')
            if line.startswith('#Fields:'):
                fields = line[len('#Fields:'):].strip().split()
                continue
            if line.startswith('#') or not line.strip():
                continue
            if not fields:
                continue
            parts = line.split()
            if len(parts) < len(fields):
                continue
            row = dict(zip(fields, parts))

            date_str = row.get('date', '')
            time_str = row.get('time', '')
            ts = _try_parse_ts(f"{date_str} {time_str}")
            if ts is None:
                continue

            ip  = row.get('c-ip', '').strip()
            uri = row.get('cs-uri-stem', '').strip()
            ua  = row.get('cs(User-Agent)', '').strip()
            try:
                sc = int(row.get('sc-status', 0))
            except (ValueError, TypeError):
                sc = 0

            if not ip or ip in ('-', ''):
                continue

            records.append({'timestamp': ts, 'ip': ip, 'uri': uri,
                             'user_agent': ua, 'status': sc})
    return records


# ── Statistical beacon analysis ───────────────────────────────────────────────

def analyse_ip(ip: str, reqs: list) -> dict:
    reqs.sort(key=lambda r: r['timestamp'])
    ts_list = [r['timestamp'] for r in reqs]
    intervals = [(ts_list[i+1] - ts_list[i]).total_seconds()
                 for i in range(len(ts_list) - 1)]

    n = len(reqs)
    uri_counts  = Counter(r['uri']        for r in reqs)
    ua_counts   = Counter(r['user_agent'] for r in reqs)
    status_list = [r['status']            for r in reqs]

    most_common_uri = uri_counts.most_common(1)[0][0] if uri_counts else ''
    most_common_ua  = ua_counts.most_common(1)[0][0]  if ua_counts  else ''
    unique_uris = len(uri_counts)
    unique_uas  = len(ua_counts)

    # Error-rate: 4xx / 5xx
    error_count = sum(1 for s in status_list if s >= 400)
    error_ratio = error_count / n if n else 0.0

    # Interval statistics
    mean_iv = median_iv = std_iv = cv = 0.0
    if intervals:
        mean_iv   = sum(intervals) / len(intervals)
        sorted_iv = sorted(intervals)
        mid       = len(sorted_iv) // 2
        if len(sorted_iv) % 2 == 0:
            median_iv = (sorted_iv[mid - 1] + sorted_iv[mid]) / 2.0
        else:
            median_iv = sorted_iv[mid]
        if len(intervals) > 1:
            variance = sum((x - mean_iv) ** 2 for x in intervals) / len(intervals)
            std_iv   = math.sqrt(variance)
        cv = std_iv / mean_iv if mean_iv > 0 else 0.0

    # ── Beacon scoring ────────────────────────────────────────────────────────
    score = 0

    # CV-based regularity bonus
    if cv < 0.15:
        score += 40
    elif cv < 0.30:
        score += 25
    elif cv < 0.50:
        score += 15

    # Typical C2 check-in range: 30 s – 3600 s
    if intervals and 30 <= mean_iv <= 3600:
        score += 20

    # Narrow URI footprint
    if unique_uris <= 2:
        score += 15

    # Generic / suspicious user-agent
    if GENERIC_UA_PATTERNS.search(most_common_ua):
        score += 10

    # Noisy-scanner penalty
    if error_ratio > 0.50:
        score -= 10

    # ── Known C2 interval matching ────────────────────────────────────────────
    matched_interval = ''
    if intervals:
        for c2_iv in KNOWN_C2_INTERVALS:
            if abs(median_iv - c2_iv) / c2_iv <= C2_MATCH_TOLERANCE:
                matched_interval = str(c2_iv)
                break

    # ── Classification ────────────────────────────────────────────────────────
    if score >= 50:
        classification = 'BEACON_LIKELY'
    elif score >= 30:
        classification = 'BEACON_POSSIBLE'
    else:
        classification = 'NORMAL'

    first_seen = ts_list[0].strftime('%Y-%m-%d %H:%M:%S UTC')
    last_seen  = ts_list[-1].strftime('%Y-%m-%d %H:%M:%S UTC')

    return {
        'SourceIP':           ip,
        'TotalRequests':      n,
        'UniqueURIs':         unique_uris,
        'UniqueUserAgents':   unique_uas,
        'MostCommonURI':      most_common_uri,
        'MostCommonUserAgent': most_common_ua,
        'MeanIntervalSec':    round(mean_iv,   3),
        'MedianIntervalSec':  round(median_iv, 3),
        'StdDevSec':          round(std_iv,    3),
        'CoeffVariation':     round(cv,        4),
        'BeaconScore':        score,
        'Classification':     classification,
        'MatchedC2Interval':  matched_interval,
        'FirstSeen':          first_seen,
        'LastSeen':           last_seen,
        'Machine':            '',   # filled in by caller
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input-csv',  required=True)
    ap.add_argument('--output-dir', required=True)
    ap.add_argument('--machine',    required=True)
    args = ap.parse_args()

    input_path = args.input_csv
    output_dir = args.output_dir
    machine    = args.machine

    os.makedirs(output_dir, exist_ok=True)
    output_csv = os.path.join(output_dir, 'c2_beacon.csv')

    # ── Collect all request records ───────────────────────────────────────────
    records = []

    if os.path.isdir(input_path):
        # Walk the directory looking for .csv or .log files
        for root_d, dirs, files in os.walk(input_path):
            dirs.sort()
            for fname in sorted(files):
                fpath = os.path.join(root_d, fname)
                if fname.lower().endswith('.csv'):
                    try:
                        batch = load_iisgeo_csv(fpath)
                        records.extend(batch)
                    except Exception as e:
                        print(f"  WARN: could not read CSV {fpath}: {e}",
                              file=sys.stderr)
                elif fname.lower().endswith('.log'):
                    try:
                        batch = load_raw_w3c(fpath)
                        records.extend(batch)
                    except Exception as e:
                        print(f"  WARN: could not read log {fpath}: {e}",
                              file=sys.stderr)
    elif os.path.isfile(input_path):
        if input_path.lower().endswith('.csv'):
            records = load_iisgeo_csv(input_path)
        else:
            records = load_raw_w3c(input_path)
    else:
        print(f"ERROR: input path does not exist: {input_path}", file=sys.stderr)
        sys.exit(1)

    if not records:
        print("ERROR: no parseable request records found", file=sys.stderr)
        sys.exit(2)

    # ── Group by source IP ────────────────────────────────────────────────────
    by_ip = defaultdict(list)
    for r in records:
        by_ip[r['ip']].append(r)

    # ── Analyse each IP with >= 5 requests ────────────────────────────────────
    results = []
    for ip, reqs in by_ip.items():
        if len(reqs) < 5:
            continue
        row = analyse_ip(ip, reqs)
        row['Machine'] = machine
        results.append(row)

    # ── Sort by BeaconScore DESC ──────────────────────────────────────────────
    results.sort(key=lambda r: r['BeaconScore'], reverse=True)

    # ── Write output CSV ──────────────────────────────────────────────────────
    with open(output_csv, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(results)

    # ── Print beacon summaries to stdout ──────────────────────────────────────
    beacon_likely   = [r for r in results if r['Classification'] == 'BEACON_LIKELY']
    beacon_possible = [r for r in results if r['Classification'] == 'BEACON_POSSIBLE']

    for r in beacon_likely + beacon_possible:
        tag    = r['Classification']
        ip     = r['SourceIP']
        total  = r['TotalRequests']
        mean_s = r['MeanIntervalSec']
        cv_val = r['CoeffVariation']
        uri    = r['MostCommonURI']
        print(f"[{tag}] {ip} — {total} requests, "
              f"mean={mean_s}s, CV={cv_val}, URI={uri}")

    # ── Summary counts for bash layer to consume ──────────────────────────────
    print(f"__SUMMARY__ likely={len(beacon_likely)} "
          f"possible={len(beacon_possible)} "
          f"total_ips={len(results)} "
          f"output={output_csv}")


if __name__ == '__main__':
    main()
PYEOF

# ═════════════════════════════════════════════════════════════════════════════
section "Phase 10 — C2 Beacon Detection"
# ═════════════════════════════════════════════════════════════════════════════

overall_likely=0
overall_possible=0

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')

    machine_header "${machine} (drive ${drive}:)"

    iis_out_dir="${ANALYSIS_DIR}/${machine}/Execution/IIS"
    beacon_csv="${iis_out_dir}/c2_beacon.csv"

    # ── Skip guard ────────────────────────────────────────────────────────────
    if [[ -f "${beacon_csv}" ]] && [[ $(wc -l < "${beacon_csv}" 2>/dev/null) -gt 1 ]]; then
        status "SKIP" "c2_beacon.csv already exists — delete to re-run"
        continue
    fi

    # ── Source priority 1: iisGeolocate CSV output from Phase 5 ──────────────
    input_arg=""
    input_desc=""

    if csv_has_data "${iis_out_dir}"; then
        # Exclude any previously generated beacon CSV itself
        geo_csv=$(find "${iis_out_dir}" -maxdepth 1 -name "*.csv" \
                       ! -name "c2_beacon.csv" -size +100c 2>/dev/null | head -1)
        if [[ -n "${geo_csv}" ]]; then
            input_arg="${geo_csv}"
            input_desc="iisGeolocate CSV: ${geo_csv##*/}"
        fi
    fi

    # ── Source priority 2: raw W3C log directory ──────────────────────────────
    if [[ -z "${input_arg}" ]]; then
        raw_iis_dir=$(find "${drive_root}" -type d -ipath "*/LogFiles/W3SVC*" \
                          2>/dev/null | head -1)
        if [[ -n "${raw_iis_dir}" ]]; then
            log_count=$(find "${raw_iis_dir}" -name "*.log" 2>/dev/null | wc -l)
            if [[ ${log_count} -gt 0 ]]; then
                input_arg="${raw_iis_dir}"
                input_desc="raw W3C logs (${log_count} file(s)): ${raw_iis_dir}"
            fi
        fi
    fi

    if [[ -z "${input_arg}" ]]; then
        status "SKIP" "No IIS data found (Phase 5 CSV not present and no W3SVC log directory)"
        continue
    fi

    status "INPUT" "${input_desc}"

    mkdir -p "${iis_out_dir}"

    cmd="python3 '${PY_SCRIPT}' --input-csv '${input_arg}' --output-dir '${iis_out_dir}' --machine '${machine}'"
    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?

    if [[ ${rc} -eq 1 && "${tool_out}" == *"no parseable"* ]]; then
        status "SKIP" "No parseable request records in input — ${input_desc}"
        continue
    fi

    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "Beacon analyser exited ${rc}"
        echo "${tool_out}" | sed 's/^/    /'
        continue
    fi

    # ── Print per-IP beacon summaries (already formatted by Python) ───────────
    beacon_lines=$(echo "${tool_out}" | grep -v "^__SUMMARY__" || true)
    if [[ -n "${beacon_lines}" ]]; then
        echo "${beacon_lines}"
    fi

    # ── Parse summary line ────────────────────────────────────────────────────
    summary_line=$(echo "${tool_out}" | grep "^__SUMMARY__" || true)
    likely_count=0
    possible_count=0
    total_ips=0
    if [[ -n "${summary_line}" ]]; then
        likely_count=$(echo   "${summary_line}" | grep -oP '(?<=likely=)\d+'   || echo 0)
        possible_count=$(echo "${summary_line}" | grep -oP '(?<=possible=)\d+' || echo 0)
        total_ips=$(echo      "${summary_line}" | grep -oP '(?<=total_ips=)\d+'|| echo 0)
    fi

    overall_likely=$(( overall_likely   + likely_count   ))
    overall_possible=$(( overall_possible + possible_count ))

    status "OK" "${total_ips} IPs analysed — BEACON_LIKELY: ${likely_count}, BEACON_POSSIBLE: ${possible_count} → ${beacon_csv##*/}"

    log_cmd "${machine}" \
        "C2 Beacon Analyser — Phase 10 (${input_desc})" \
        "${cmd}" \
        "Statistical C2 beaconing detection via inter-request interval analysis (CV, mean, known C2 intervals) on IIS access log data" \
        "${beacon_csv}" \
        "${total_ips} IPs analysed; BEACON_LIKELY=${likely_count}, BEACON_POSSIBLE=${possible_count}"
done

echo ""
echo "════════════════════════════════════════════════════"
echo " Phase 10 complete."
printf "  BEACON_LIKELY   : %d IP(s)\n"   "${overall_likely}"
printf "  BEACON_POSSIBLE : %d IP(s)\n"   "${overall_possible}"
echo ""
echo " Output files:"
find "${ANALYSIS_DIR}" -name "c2_beacon.csv" 2>/dev/null | sort | awk '{print "  "$0}'
echo "════════════════════════════════════════════════════"
