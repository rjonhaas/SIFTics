#!/usr/bin/env bash
# run_ransomware.sh — Phase 12: Ransomware & Exfiltration Indicators
#
# Reads MFT CSVs produced by Phase 1 and analyses them for:
#   A. Archive files — extensions used for staging/exfiltration
#   B. Ransom notes  — filename patterns matching known note naming conventions
#   C. Encrypted extensions — bulk unknown extensions + known ransomware suffixes
#
# Output (per machine):
#   analysis/<MACHINE>/Ransomware/<MACHINE>_archives.csv
#   analysis/<MACHINE>/Ransomware/<MACHINE>_ransom_notes.csv
#   analysis/<MACHINE>/Ransomware/<MACHINE>_suspicious_extensions.csv
#   analysis/<MACHINE>/Ransomware/<MACHINE>_extension_summary.csv
#
# Cross-machine:
#   analysis/ransomware_summary.txt
#
# Logging: appends to analysis/commands.txt

set -uo pipefail

CASE_ROOT="/cases/jackofallhacks"
ANALYSIS_DIR="${CASE_ROOT}/analysis"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")
SUMMARY_OUT="${ANALYSIS_DIR}/ransomware_summary.txt"

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

section()        { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
machine_header() { echo ""; echo "  ── $* ──"; }
status()         { printf "  [%-10s] %s\n" "$1" "$2"; }

csv_has_data() {
    local dir="$1" pattern="${2:-*.csv}"
    [[ -d "${dir}" ]] || return 1
    while IFS= read -r f; do
        [[ $(wc -l < "${f}" 2>/dev/null) -gt 1 ]] && return 0
    done < <(find "${dir}" -maxdepth 2 -name "${pattern}" -size +10c 2>/dev/null)
    return 1
}

mapfile -t DRIVE_ROOTS < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name '$MFT' -print \
    | sort | xargs -I{} dirname {}
)

echo "════════════════════════════════════════════════════"
echo " Phase 12 — Ransomware & Exfiltration Indicators"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ─── temp Python file ────────────────────────────────────────────────────────

TMPPY=$(mktemp /tmp/ransomware_XXXXXX.py)
trap 'rm -f "${TMPPY}"' EXIT INT TERM

cat > "${TMPPY}" << 'PYEOF'
#!/usr/bin/env python3
import csv
import datetime
import os
import re
import sys
from collections import defaultdict

MFT_CSV     = sys.argv[1]   # path to <MACHINE>_<DRIVE>_MFT.csv
OUT_DIR     = sys.argv[2]   # analysis/<MACHINE>/Ransomware/
MACHINE     = sys.argv[3]   # e.g. DC01
DRIVE       = sys.argv[4]   # e.g. C

os.makedirs(OUT_DIR, exist_ok=True)

# ── extension lists ───────────────────────────────────────────────────────────

EXFIL_ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.tbz2',
    '.cab', '.iso', '.img', '.lz', '.lzma', '.xz', '.txz',
    '.ace', '.arj', '.z', '.lzh', '.lha', '.alz', '.egg',
    '.wim', '.swm', '.esd',
}

KNOWN_RANSOMWARE_EXTENSIONS = {
    '.encrypted', '.locked', '.crypted', '.crypt', '.enc', '.encode',
    '.ecc', '.ezz', '.exx', '.zzz', '.xyz', '.aaa', '.abc', '.ccc',
    '.vvv', '.xxx', '.ttt', '.micro', '.enciph', '.cryptolocker',
    '.crinf', '.r5a', '.xrnt', '.xtbl', '.pzdc', '.good', '.rdm',
    '.rrk', '.encryptedrsa', '.crjoker', '.lechiffre', '.0x0',
    '.bleep', '.1999', '.vault', '.ha3', '.toxcrypt', '.magic',
    '.supercrypt', '.ctbl', '.ctb2', '.locky', '.zepto', '.odin',
    '.shit', '.thor', '.aesir', '.zzzzz', '.osiris', '.diablo6',
    '.lukitus', '.yk0', '.ykcol', '.wallet', '.onion', '.wncry',
    '.wncryt', '.wcry', '.wncrypt', '.cerber', '.cerber2', '.cerber3',
    '.arena', '.cobra', '.globe', '.hercules', '.dharma', '.btc',
    '.karma', '.0day', '.java', '.ryuk', '.ryk', '.maze', '.sekhmet',
    '.egregor', '.babuk', '.revil', '.sodinokibi', '.lockbit', '.clop',
    '.cl0p', '.mailto', '.stop', '.djvu', '.tfude', '.tro', '.rumba',
    '.adobe', '.vegas', '.coharos', '.shadow', '.phoenix', '.devos',
    '.harma', '.cosakos', '.lezp', '.lezp2', '.rgss3a',
}

KNOWN_BENIGN_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.drv', '.ocx', '.scr', '.cpl', '.msi',
    '.msp', '.inf', '.cat', '.mui', '.mun', '.ax', '.acm',
    '.ini', '.cfg', '.conf', '.config', '.reg', '.xml', '.json',
    '.yaml', '.yml', '.toml', '.properties', '.env',
    '.txt', '.log', '.csv', '.md', '.rst', '.nfo', '.diz',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.odt', '.ods', '.odp', '.pdf', '.rtf', '.pub',
    '.html', '.htm', '.css', '.js', '.ts', '.jsx', '.tsx',
    '.php', '.asp', '.aspx', '.wasm', '.map',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
    '.tif', '.tiff', '.webp', '.raw', '.psd',
    '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wav', '.flac',
    '.aac', '.wma', '.wmv', '.m4v', '.m4a', '.ogg',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.cab',
    '.iso', '.img', '.wim',
    '.py', '.rb', '.go', '.java', '.cs', '.cpp', '.c', '.h',
    '.rs', '.sh', '.bat', '.cmd', '.ps1', '.vbs', '.wsf',
    '.pdb', '.lib', '.obj', '.pch', '.idb', '.exp', '.ilk',
    '.lnk', '.pf', '.evtx', '.evt', '.etl',
    '.hve', '.dat', '.hive', '.sav',
    '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.edb',
    '.ttf', '.otf', '.woff', '.woff2', '.fon', '.eot',
    '.cer', '.crt', '.pem', '.pfx', '.p12', '.key', '.pub', '.asc',
    '.tmp', '.bak', '.old', '.orig', '.swp',
    '.manifest', '.resource', '.resx', '.resources',
    '.nls', '.bin', '.pak', '.mui', '.etw',
    '.mof', '.sdb', '.p7b', '.p7c', '.p7s',
    '',
}

# ── ransom note detection ─────────────────────────────────────────────────────

RANSOM_NOTE_STEMS = {
    'readme', 'decrypt', 'howto', 'how_to', 'how-to',
    'your_files', 'yourfiles', 'help_decrypt', 'helpdecrypt',
    'attention', 'recover', 'restore', 'files_encrypted',
    'filesencrypted', 'all_files', 'allfiles', 'ransom',
    'instruction', 'instructions', 'important', 'message',
    'contact', 'payment', 'unlock', '_readme', '!readme',
    'help_me', 'help-me', 'read_me', 'read-me', 'read_this',
    'open_me', 'open-me', 'what_happened', 'whathappened',
    'your_data', 'recover_files', 'recoverfiles', 'info',
    'help', 'note', 'warning', 'alert',
}

RANSOM_NOTE_STEM_PATTERNS = [
    re.compile(r'^[!@#$%\-_=+]{2,}', re.I),  # starts with repeated symbols
    re.compile(r'^@.+@', re.I),               # @something@ pattern
    re.compile(r'encrypt', re.I),
    re.compile(r'decrypt', re.I),
    re.compile(r'ransom', re.I),
    re.compile(r'locked?', re.I),
    re.compile(r'recover', re.I),
    re.compile(r'restore', re.I),
    re.compile(r'readme', re.I),
]

RANSOM_NOTE_EXTENSIONS = {'.txt', '.html', '.htm', '.hta', '.url'}


def is_ransom_note(filename: str) -> bool:
    fname_lower = filename.lower()
    stem, _, ext = filename.rpartition('.')
    ext_with_dot = '.' + ext.lower() if ext else ''

    if ext_with_dot not in RANSOM_NOTE_EXTENSIONS:
        return False

    stem_clean = re.sub(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~ ]', '', stem.lower())

    if stem_clean in RANSOM_NOTE_STEMS:
        return True

    for pattern in RANSOM_NOTE_STEM_PATTERNS:
        if pattern.search(stem):
            return True

    return False


# ── helpers ───────────────────────────────────────────────────────────────────

NTFS_NULL_TS = '2001-01-01 00:00:00'  # zeroed 64-bit FILETIME written by MFTECmd
TS_FLOOR     = '2010-01-01'           # reject anything older as a sentinel/corrupt value

def valid_ts(ts: str) -> bool:
    if not ts:
        return False
    if ts.startswith(NTFS_NULL_TS):
        return False
    if ts < TS_FLOOR:
        return False
    return True

# paths that are almost certainly benign regardless of filename/extension
SYSTEM_PATH_PREFIXES = (
    '\\windows\\',
    '\\program files\\',
    '\\program files (x86)\\',
    '\\programdata\\microsoft\\',
    '\\programdata\\packages\\',
)

def is_system_path(path: str) -> bool:
    p = path.lower().replace('/', '\\')
    return any(p.startswith(pfx) or ('\\' + pfx.lstrip('\\')) in p
               for pfx in SYSTEM_PATH_PREFIXES)

# ── read MFT CSV ──────────────────────────────────────────────────────────────

print(f"  [read] {os.path.basename(MFT_CSV)} ({os.path.getsize(MFT_CSV)/1_048_576:.1f} MB)", flush=True)

archives      = []   # (path, filename, ext, size, modified, created)
ransom_notes  = []   # (path, filename, ext, size, created, modified)
ext_counts    = defaultdict(int)
ext_first_ts  = {}
ext_last_ts   = {}
ext_sizes     = defaultdict(int)
total_rows    = 0
skipped_dirs  = 0

try:
    with open(MFT_CSV, 'r', encoding='utf-8-sig', errors='replace') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            total_rows += 1

            if row.get('IsDirectory', '').strip().lower() == 'true':
                skipped_dirs += 1
                continue

            filename  = row.get('FileName', '').strip()
            extension = row.get('Extension', '').strip().lower()
            parent    = row.get('ParentPath', '').strip()
            size_str  = row.get('FileSize', '0').strip()
            modified  = row.get('LastModified0x10', '').strip()
            created   = row.get('Created0x10', '').strip()

            try:
                size = int(size_str) if size_str else 0
            except ValueError:
                size = 0

            full_path = f"{parent}\\{filename}" if parent else filename
            in_system = is_system_path(full_path)

            # ── A: archive inventory (skip system paths) ──────────────────────
            if extension in EXFIL_ARCHIVE_EXTENSIONS and not in_system:
                archives.append({
                    'machine': MACHINE,
                    'drive': DRIVE,
                    'path': full_path,
                    'filename': filename,
                    'extension': extension,
                    'size_bytes': size,
                    'created_utc': created,
                    'modified_utc': modified,
                })

            # ── B: ransom note detection (skip system paths) ──────────────────
            if is_ransom_note(filename) and not in_system:
                ransom_notes.append({
                    'machine': MACHINE,
                    'drive': DRIVE,
                    'path': full_path,
                    'filename': filename,
                    'extension': extension,
                    'size_bytes': size,
                    'created_utc': created,
                    'modified_utc': modified,
                })

            # ── C: extension tracking (valid timestamps only) ─────────────────
            if extension:
                ext_counts[extension] += 1
                ext_sizes[extension]  += size
                if valid_ts(modified):
                    if extension not in ext_first_ts or modified < ext_first_ts[extension]:
                        ext_first_ts[extension] = modified
                    if extension not in ext_last_ts or modified > ext_last_ts[extension]:
                        ext_last_ts[extension] = modified

except Exception as e:
    print(f"  [ERROR] Failed reading MFT: {e}", flush=True)
    sys.exit(1)

print(f"  [ok   ] {total_rows:,} rows — {skipped_dirs:,} dirs skipped", flush=True)

# ── write A: archive CSV ──────────────────────────────────────────────────────

archive_csv = os.path.join(OUT_DIR, f"{MACHINE}_{DRIVE}_archives.csv")
with open(archive_csv, 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=[
        'machine','drive','filename','extension','size_bytes','path','created_utc','modified_utc'
    ])
    w.writeheader()
    for row in sorted(archives, key=lambda x: x['modified_utc'], reverse=True):
        w.writerow(row)
print(f"  [A    ] {len(archives):,} archive files → {os.path.basename(archive_csv)}", flush=True)

# ── write B: ransom notes CSV ─────────────────────────────────────────────────

notes_csv = os.path.join(OUT_DIR, f"{MACHINE}_{DRIVE}_ransom_notes.csv")
with open(notes_csv, 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=[
        'machine','drive','filename','extension','size_bytes','path','created_utc','modified_utc'
    ])
    w.writeheader()
    for row in sorted(ransom_notes, key=lambda x: x['created_utc']):
        w.writerow(row)
print(f"  [B    ] {len(ransom_notes):,} ransom note candidate(s) → {os.path.basename(notes_csv)}", flush=True)

# ── C: suspicious extension analysis ─────────────────────────────────────────

suspicious = []
for ext, count in ext_counts.items():
    ext_lower = ext.lower()
    is_known_ransom = ext_lower in KNOWN_RANSOMWARE_EXTENSIONS
    is_benign       = ext_lower in KNOWN_BENIGN_EXTENSIONS
    is_bulk_unknown = not is_benign and count >= 20

    if is_known_ransom or is_bulk_unknown:
        suspicious.append({
            'machine':        MACHINE,
            'drive':          DRIVE,
            'extension':      ext,
            'file_count':     count,
            'total_bytes':    ext_sizes[ext],
            'first_modified': ext_first_ts.get(ext, ''),
            'last_modified':  ext_last_ts.get(ext, ''),
            'known_ransomware': 'YES' if is_known_ransom else 'no',
            'assessment':     'KNOWN_RANSOMWARE_EXT' if is_known_ransom else 'BULK_UNKNOWN',
        })

suspicious.sort(key=lambda x: (x['known_ransomware'] != 'YES', -x['file_count']))

susp_csv = os.path.join(OUT_DIR, f"{MACHINE}_{DRIVE}_suspicious_extensions.csv")
with open(susp_csv, 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=[
        'machine','drive','extension','file_count','total_bytes',
        'first_modified','last_modified','known_ransomware','assessment',
    ])
    w.writeheader()
    for row in suspicious:
        w.writerow(row)
print(f"  [C    ] {len(suspicious):,} suspicious extension(s) → {os.path.basename(susp_csv)}", flush=True)

# ── write extension summary CSV (all extensions, sorted by count) ─────────────

summary_csv = os.path.join(OUT_DIR, f"{MACHINE}_{DRIVE}_extension_summary.csv")
with open(summary_csv, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    w.writerow(['machine','drive','extension','file_count','total_bytes',
                'first_modified','last_modified','category'])
    for ext, count in sorted(ext_counts.items(), key=lambda x: -x[1]):
        if ext.lower() in KNOWN_RANSOMWARE_EXTENSIONS:
            cat = 'RANSOMWARE'
        elif ext.lower() in EXFIL_ARCHIVE_EXTENSIONS:
            cat = 'ARCHIVE'
        elif ext.lower() in KNOWN_BENIGN_EXTENSIONS:
            cat = 'benign'
        else:
            cat = 'UNKNOWN'
        w.writerow([MACHINE, DRIVE, ext, count, ext_sizes[ext],
                    ext_first_ts.get(ext,''), ext_last_ts.get(ext,''), cat])
print(f"  [sum  ] {len(ext_counts):,} distinct extensions → {os.path.basename(summary_csv)}", flush=True)

# ── earliest timestamp across all findings ────────────────────────────────────

all_ts = []
for r in archives + ransom_notes:
    if valid_ts(r.get('created_utc',  '')): all_ts.append(r['created_utc'])
    if valid_ts(r.get('modified_utc', '')): all_ts.append(r['modified_utc'])
for ext in suspicious:
    if valid_ts(ext.get('first_modified', '')): all_ts.append(ext['first_modified'])

earliest_ts = min(all_ts) if all_ts else ''

# ── print machine result summary ──────────────────────────────────────────────

print(f"  [done ] archives={len(archives)}  notes={len(ransom_notes)}  suspicious_exts={len(suspicious)}  earliest={earliest_ts}", flush=True)

# write machine result as single line for bash to capture
print(f"RESULT:{MACHINE}:{len(archives)}:{len(ransom_notes)}:{len(suspicious)}:{earliest_ts}", flush=True)

PYEOF

# ─── per-machine loop ─────────────────────────────────────────────────────────

section "A/B/C — Analysing MFT per machine"

declare -A MACHINE_RESULTS

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    mft_csv="${ANALYSIS_DIR}/${machine}/${machine}_${drive}_MFT.csv"
    out_dir="${ANALYSIS_DIR}/${machine}/Ransomware"

    machine_header "${machine} (drive ${drive}:)"

    if [[ ! -f "${mft_csv}" ]]; then
        status "MISSING" "No MFT CSV — run Phase 1 (run_ntfs.sh) first"
        continue
    fi

    if csv_has_data "${out_dir}" "${machine}_${drive}_archives.csv"; then
        status "SKIP" "Output already exists — delete ${out_dir} to re-run"
        a_count=$(awk -F',' 'NR>1{c++}END{print c+0}' "${out_dir}/${machine}_${drive}_archives.csv" 2>/dev/null || echo 0)
        n_count=$(awk -F',' 'NR>1{c++}END{print c+0}' "${out_dir}/${machine}_${drive}_ransom_notes.csv" 2>/dev/null || echo 0)
        s_count=$(awk -F',' 'NR>1{c++}END{print c+0}' "${out_dir}/${machine}_${drive}_suspicious_extensions.csv" 2>/dev/null || echo 0)
        # earliest timestamp from existing CSVs (created_utc col = field 7)
        e_ts=$(tail -n +2 "${out_dir}/${machine}_${drive}_archives.csv" "${out_dir}/${machine}_${drive}_ransom_notes.csv" 2>/dev/null \
            | awk -F',' '{print $7}' | grep -v '^$' | sort | head -1)
        MACHINE_RESULTS["${machine}"]="${a_count}:${n_count}:${s_count}:${e_ts}"
        continue
    fi

    mkdir -p "${out_dir}"

    result_line=$(python3 "${TMPPY}" "${mft_csv}" "${out_dir}" "${machine}" "${drive}" 2>&1 \
        | tee /dev/stderr \
        | grep "^RESULT:" | tail -1) || true

    if [[ -n "${result_line}" ]]; then
        # RESULT:<MACHINE>:<archives>:<notes>:<suspicious>:<earliest_ts>
        IFS=':' read -r _ _ a_count n_count s_count e_ts <<< "${result_line}"
        MACHINE_RESULTS["${machine}"]="${a_count}:${n_count}:${s_count}:${e_ts}"
        log_cmd "${machine}" "run_ransomware.py" \
            "python3 ${TMPPY} ${mft_csv} ${out_dir} ${machine} ${drive}" \
            "Archive inventory, ransom note detection, encrypted extension analysis from MFT" \
            "${out_dir}/" \
            "archives=${a_count} notes=${n_count} suspicious_exts=${s_count} earliest=${e_ts}"
    else
        status "ERROR" "Python analyser produced no result line"
        MACHINE_RESULTS["${machine}"]="ERR:ERR:ERR:"
    fi
done

# ─── cross-machine summary ────────────────────────────────────────────────────

section "Summary"

{
    echo "Ransomware & Exfiltration Indicator Summary — jackofallhacks"
    echo "============================================================"
    echo "Generated : $(date -u)"
    echo ""
    printf "  %-8s  %-10s  %-12s  %-16s  %-26s\n" "Machine" "Archives" "Ransom Notes" "Suspicious Exts" "Earliest Indicator (UTC)"
    echo "  ─────────────────────────────────────────────────────────────────────────────"

    total_archives=0; total_notes=0; total_susp=0; overall_earliest=""
    for drive_root in "${DRIVE_ROOTS[@]}"; do
        machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
        if [[ -n "${MACHINE_RESULTS[${machine}]:-}" ]]; then
            IFS=':' read -r a n s e_ts <<< "${MACHINE_RESULTS[${machine}]}"
            printf "  %-8s  %-10s  %-12s  %-16s  %-26s\n" "${machine}" "${a}" "${n}" "${s}" "${e_ts}"
            [[ "${a}" =~ ^[0-9]+$ ]] && total_archives=$(( total_archives + a )) || true
            [[ "${n}" =~ ^[0-9]+$ ]] && total_notes=$(( total_notes + n ))       || true
            [[ "${s}" =~ ^[0-9]+$ ]] && total_susp=$(( total_susp + s ))         || true
            if [[ -n "${e_ts}" ]]; then
                if [[ -z "${overall_earliest}" ]] || [[ "${e_ts}" < "${overall_earliest}" ]]; then
                    overall_earliest="${e_ts}"
                    overall_earliest_machine="${machine}"
                fi
            fi
        fi
    done

    echo "  ─────────────────────────────────────────────────────────────────────────────"
    printf "  %-8s  %-10s  %-12s  %-16s\n" "TOTAL" "${total_archives}" "${total_notes}" "${total_susp}"
    if [[ -n "${overall_earliest:-}" ]]; then
        echo ""
        echo "  First indicator : ${overall_earliest} UTC on ${overall_earliest_machine}"
    fi
    echo ""

    if [[ ${total_notes} -gt 0 ]]; then
        echo "  [HIGH] Ransom note candidates detected (${total_notes})."
        echo "         Review <MACHINE>/Ransomware/*_ransom_notes.csv for filenames and paths."
    fi
    if [[ ${total_susp} -gt 0 ]]; then
        echo "  [HIGH] Suspicious/encrypted extensions detected (${total_susp} distinct)."
        echo "         Cross-reference timestamps for mass-modification windows."
    fi
    if [[ ${total_archives} -gt 0 ]]; then
        echo "  [MED ] Archive files found (${total_archives} total)."
        echo "         Review <MACHINE>/Ransomware/*_archives.csv for exfil staging paths."
    fi
    echo ""
    echo "Output root:"
    for drive_root in "${DRIVE_ROOTS[@]}"; do
        machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
        [[ -d "${ANALYSIS_DIR}/${machine}/Ransomware" ]] && \
            echo "  ${ANALYSIS_DIR}/${machine}/Ransomware/"
    done

} | tee "${SUMMARY_OUT}"

echo ""
section "Phase 12 — Complete"
echo ""
