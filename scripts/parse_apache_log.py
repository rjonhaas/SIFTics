#!/usr/bin/env python3
"""parse_apache_log.py — Parse Apache combined/common access log format.

Handles empty or missing log files gracefully (header-only CSV, prints 0).
Usage: python3 parse_apache_log.py <log_file> <machine> <output_csv>
Prints row_count to stdout.
"""

import sys
import csv
import re
import os
from datetime import datetime, timezone

COMBINED_RE = re.compile(
    r'(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3}|-)\s+(\S+)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'
)
APACHE_TS = '%d/%b/%Y:%H:%M:%S %z'

FIELDS = ['Machine', 'Timestamp_UTC', 'SourceIP', 'Username', 'Method',
          'URI', 'Protocol', 'StatusCode', 'ResponseBytes',
          'Referer', 'UserAgent', 'Flags']


def parse_ts(s: str) -> str:
    try:
        return datetime.strptime(s, APACHE_TS).astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return s


def classify(uri: str, status: str, ua: str) -> str:
    flags = []
    if re.search(r'(?:\.\./|%2e%2e|[;&|`$])', uri, re.IGNORECASE):
        flags.append('TRAVERSAL_OR_INJECTION')
    if re.search(r'\b(cmd|exec|shell|passwd|shadow)\b', uri, re.IGNORECASE):
        flags.append('SENSITIVE_PATH')
    if re.search(r'\b(sqlmap|nikto|nmap|masscan|nuclei|dirbuster)\b',
                 ua, re.IGNORECASE):
        flags.append('SCANNER_UA')
    if status.startswith('4'):
        flags.append('CLIENT_ERROR')
    elif status.startswith('5'):
        flags.append('SERVER_ERROR')
    return '; '.join(flags)


def write_header_only(out_csv: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        csv.DictWriter(f, fieldnames=FIELDS).writeheader()


def main():
    if len(sys.argv) != 4:
        print(f'Usage: {sys.argv[0]} <log_file> <machine> <output_csv>',
              file=sys.stderr)
        sys.exit(1)

    log_file, machine, out_csv = sys.argv[1:]

    if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
        write_header_only(out_csv)
        print(0)
        return

    rows = []
    with open(log_file, 'r', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line.strip():
                continue
            m = COMBINED_RE.match(line)
            if not m:
                continue
            src_ip  = m.group(1)
            user    = m.group(2)
            ts      = parse_ts(m.group(3))
            request = m.group(4)
            status  = m.group(5) or '-'
            nbytes  = m.group(6) or '-'
            referer = m.group(7) or ''
            ua      = m.group(8) or ''

            parts  = request.split(' ', 2)
            method = parts[0] if parts else ''
            uri    = parts[1] if len(parts) > 1 else request
            proto  = parts[2] if len(parts) > 2 else ''

            rows.append({
                'Machine': machine, 'Timestamp_UTC': ts,
                'SourceIP': src_ip, 'Username': user,
                'Method': method, 'URI': uri, 'Protocol': proto,
                'StatusCode': status, 'ResponseBytes': nbytes,
                'Referer': referer, 'UserAgent': ua,
                'Flags': classify(uri, status, ua),
            })

    os.makedirs(os.path.dirname(os.path.abspath(out_csv)), exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    print(len(rows))


if __name__ == '__main__':
    main()
