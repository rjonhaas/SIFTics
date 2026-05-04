#!/usr/bin/env python3
"""parse_bash_history.py — Categorize bash history entries with IOC extraction.

Usage: python3 parse_bash_history.py <history_file> <machine> <username> <output_csv>
Prints row_count to stdout on success.
"""

import sys
import csv
import re
import os

# Priority-ordered category rules — first match wins
CATEGORY_RULES = [
    ('FLAG',             [r'\bflag\b', r'flag<', r'<[a-zA-Z][a-zA-Z _]+>']),
    ('CREDENTIAL_ACCESS',[r'\bmimikatz\b', r'\bhashdump\b', r'\b/etc/shadow\b',
                          r'\bsecretsdump\b', r'\bpwdump\b', r'\bsavedump\b',
                          r'\bcredential\b']),
    ('TOOL_EXECUTION',   [r'\bmsfconsole\b', r'\bmsfdb\b', r'\bbinwalk\b',
                          r'\bnmap\b', r'\baircrack\b', r'\bhydra\b',
                          r'\bjohn\b', r'\bhashcat\b', r'\bmetasploit\b',
                          r'\bburpsuite\b', r'\bnikto\b', r'\bsqlmap\b']),
    ('DOWNLOAD',         [r'\bwget\b', r'\bcurl\b', r'\bapt-get\s+install\b',
                          r'\bapt\s+install\b', r'\bgit\s+clone\b',
                          r'\bpip\s+install\b', r'\byum\s+install\b']),
    ('ANTI_FORENSICS',   [r'\brm\s+-[rf]+\b', r'\bhistory\s*-c\b', r'\bshred\b',
                          r'\bhistory\s*>\s', r'\bunset\s+HIST']),
    ('FILE_CREATION',    [r'\btouch\b', r'\bmkdir\b', r'\bvim\b', r'\bnano\b',
                          r'\bgedit\b', r'\bcp\s+\S', r'\bmv\s+\S']),
    ('RECON',            [r'\bifconfig\b', r'\bip\s+(a|addr|route|link)\b',
                          r'\bnetstat\b', r'\bwhoami\b', r'\bps\s+(aux|ef)\b',
                          r'\bhostname\b', r'\buname\b', r'\bwall\b',
                          r'\barp\b', r'\broute\b']),
    ('SERVICE',          [r'\bsystemctl\b', r'\bservice\b', r'\bcrontab\b',
                          r'\bvisudo\b', r'\bsudo\b']),
    ('ENCODING',         [r'\bbase64\b', r'\bopenssl\b', r'\bxxd\b',
                          r'\bhexdump\b', r'\bpython.*encode\b',
                          r'\bpython.*decode\b']),
    ('PACKAGE_MGMT',     [r'\bapt-get\b', r'\bapt\b', r'\byum\b',
                          r'\bdnf\b', r'\bpacman\b']),
]

IOC_PATTERNS = [
    (r'\b(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)\b', 'IP'),
    (r'(https?://\S+)', 'URL'),
    (r'(flag\{[^}]+\}|flag<[^>]+>|<[A-Za-z][A-Za-z ]+>)', 'FLAG_VALUE'),
    (r'(?:password|passwd|secret|key)\s*[=:]\s*(\S+)', 'SECRET'),
]


def categorize(cmd: str) -> str:
    for cat, patterns in CATEGORY_RULES:
        for p in patterns:
            if re.search(p, cmd, re.IGNORECASE):
                return cat
    return 'GENERAL'


def extract_iocs(cmd: str) -> str:
    notes = []
    for pattern, label in IOC_PATTERNS:
        for m in re.finditer(pattern, cmd, re.IGNORECASE):
            val = m.group(1) if m.lastindex else m.group(0)
            notes.append(f'{label}:{val[:80]}')
    return '; '.join(notes)


def main():
    if len(sys.argv) != 5:
        print(f'Usage: {sys.argv[0]} <history_file> <machine> <username> <output_csv>',
              file=sys.stderr)
        sys.exit(1)

    hist_file, machine, username, out_csv = sys.argv[1:]

    if not os.path.exists(hist_file):
        print(f'ERROR: {hist_file} not found', file=sys.stderr)
        sys.exit(1)

    rows = []
    with open(hist_file, 'r', errors='replace') as f:
        for lineno, raw in enumerate(f, 1):
            cmd = raw.rstrip('\n')
            if not cmd.strip():
                continue
            rows.append({
                'Machine':    machine,
                'Username':   username,
                'LineNumber': lineno,
                'Command':    cmd,
                'Category':   categorize(cmd),
                'IOC_Note':   extract_iocs(cmd),
            })

    out_dir = os.path.dirname(os.path.abspath(out_csv))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    fields = ['Machine', 'Username', 'LineNumber', 'Command', 'Category', 'IOC_Note']
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    print(len(rows))


if __name__ == '__main__':
    main()
