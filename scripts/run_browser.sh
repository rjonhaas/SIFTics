#!/usr/bin/env bash
# DAEDALUS:HANDLES browser_chrome browser_edge browser_firefox browser_ie_legacy
# run_browser.sh — Phase 11: Browser & User Behavior Artifacts
#
# Sections:
#   A. Zone.Identifier / Mark of the Web  (from Phase 1 MFT CSVs)
#   B. Chrome / Edge Chromium History     (SQLite — urls, visits, downloads)
#   C. Firefox places.sqlite              (SQLite — moz_historyvisits, moz_annos)
#   D. IE / Edge Legacy WebCacheV01.dat   (ESE via esedbexport)
#
# Output : analysis/<MACHINE>/Browser/
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

ESEDBEXPORT="/usr/bin/esedbexport"

SKIP_USERS="Default|LocalService|NetworkService|DefaultAccount|WDAGUtilityAccount"

# ─── Python temp-file trap ───────────────────────────────────────────────────
PY_SCRIPT=$(mktemp /tmp/run_browser_XXXXXX.py)
trap 'rm -f "${PY_SCRIPT}"' EXIT

# ─── helpers ────────────────────────────────────────────────────────────────

log_cmd() {
    local machine="$1" tool="$2" cmd="$3" purpose="$4" output="$5" result="$6"
    cat >> "${COMMAND_LOG}" <<EOF

[${TIMESTAMP}] ${machine} | ${tool} | Browser
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

# csv_has_data DIR [PATTERN] — true if any matching CSV under DIR has >1 line
csv_has_data() {
    local dir="$1" pattern="${2:-*.csv}"
    [[ -d "${dir}" ]] || return 1
    while IFS= read -r f; do
        [[ $(wc -l < "${f}" 2>/dev/null) -gt 1 ]] && return 0
    done < <(find "${dir}" -maxdepth 2 -name "${pattern}" -size +100c 2>/dev/null)
    return 1
}

section()        { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
machine_header() { echo ""; echo "  ── $* ──"; }
status()         { printf "  [%-10s] %s\n" "$1" "$2"; }

# ─── discover drive roots ────────────────────────────────────────────────────

mapfile -t DRIVE_ROOTS < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name '$MFT' -print \
    | sort | xargs -I{} dirname {}
)

echo "════════════════════════════════════════════════════"
echo " Browser & User Behavior Artifacts — jackofallhacks"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ════════════════════════════════════════════════════════════════════════════
section "A. Zone.Identifier / Mark of the Web (from MFT CSVs)"
# ════════════════════════════════════════════════════════════════════════════

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    out_dir="${ANALYSIS_DIR}/${machine}/Browser"
    out_file="${out_dir}/${machine}_A_ZoneIdentifier.csv"

    machine_header "${machine} (drive ${drive}:)"

    # Locate MFT CSV(s) for this machine
    mapfile -t mft_csvs < <(
        find "${ANALYSIS_DIR}/${machine}" -maxdepth 1 -name "*_MFT.csv" 2>/dev/null | sort
    )

    if [[ ${#mft_csvs[@]} -eq 0 ]]; then
        status "MISSING" "No *_MFT.csv found under ${ANALYSIS_DIR}/${machine} — run Phase 1 first"
        continue
    fi

    if [[ -f "${out_file}" ]] && [[ $(wc -l < "${out_file}" 2>/dev/null) -gt 1 ]]; then
        rows=$(( $(wc -l < "${out_file}") - 1 ))
        status "SKIP" "Already exists: ${rows} rows (${out_file##*/})"
        continue
    fi

    mkdir -p "${out_dir}"

    # Build quoted list of MFT CSV paths for Python
    mft_csv_list=$(printf '"%s",' "${mft_csvs[@]}")
    mft_csv_list="[${mft_csv_list%,}]"

    cat > "${PY_SCRIPT}" <<'PYEOF'
import sys, csv, re, os

mft_files = MFT_FILE_LIST_PLACEHOLDER
machine   = MACHINE_PLACEHOLDER
out_file  = OUT_FILE_PLACEHOLDER

ZONE_LABELS = {
    '0': 'Local',
    '1': 'Intranet',
    '2': 'Trusted',
    '3': 'Internet',
    '4': 'Restricted',
}

rows_written = 0

with open(out_file, 'w', newline='', encoding='utf-8') as fout:
    writer = csv.writer(fout)
    writer.writerow([
        'Machine', 'ParentPath', 'FileName', 'Extension', 'FileSize',
        'Created0x10', 'LastModified0x10',
        'ZoneId', 'ZoneLabel', 'ReferrerUrl', 'HostUrl', 'RawZoneContents',
    ])

    for mft_path in mft_files:
        if not os.path.isfile(mft_path):
            continue
        try:
            with open(mft_path, 'r', encoding='utf-8-sig', errors='replace') as fin:
                reader = csv.DictReader(fin)
                for record in reader:
                    raw = record.get('ZoneIdContents', '')
                    if not raw:
                        continue

                    # Normalise escape sequences (eol may be literal \n or real newline)
                    text = raw.replace('\\n', '\n').replace('\\r', '\n')

                    zone_id      = ''
                    referrer_url = ''
                    host_url     = ''

                    for line in text.splitlines():
                        line = line.strip()
                        m = re.match(r'^ZoneId\s*=\s*(\d+)', line, re.IGNORECASE)
                        if m:
                            zone_id = m.group(1)
                            continue
                        m = re.match(r'^ReferrerUrl\s*=\s*(.*)', line, re.IGNORECASE)
                        if m:
                            referrer_url = m.group(1).strip()
                            continue
                        m = re.match(r'^HostUrl\s*=\s*(.*)', line, re.IGNORECASE)
                        if m:
                            host_url = m.group(1).strip()
                            continue

                    zone_label = ZONE_LABELS.get(zone_id, zone_id)

                    writer.writerow([
                        machine,
                        record.get('ParentPath', ''),
                        record.get('FileName', ''),
                        record.get('Extension', ''),
                        record.get('FileSize', ''),
                        record.get('Created0x10', ''),
                        record.get('LastModified0x10', ''),
                        zone_id,
                        zone_label,
                        referrer_url,
                        host_url,
                        raw,
                    ])
                    rows_written += 1
        except Exception as e:
            print(f"WARNING: could not parse {mft_path}: {e}", file=sys.stderr)

print(rows_written)
PYEOF

    # Substitute placeholders
    sed -i "s|MFT_FILE_LIST_PLACEHOLDER|${mft_csv_list}|g" "${PY_SCRIPT}"
    sed -i "s|MACHINE_PLACEHOLDER|\"${machine}\"|g" "${PY_SCRIPT}"
    sed -i "s|OUT_FILE_PLACEHOLDER|\"${out_file}\"|g" "${PY_SCRIPT}"

    cmd="python3 '${PY_SCRIPT}'"
    py_out=$(run_tool "${cmd}") && rc=0 || rc=$?

    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "Python exited ${rc}: ${py_out}"
        continue
    fi

    rows="${py_out}"
    if [[ -z "${rows}" || "${rows}" == "0" ]]; then
        status "EMPTY" "No ZoneIdContents entries found in MFT CSVs"
        rm -f "${out_file}"
        continue
    fi

    internet_rows=$(awk -F',' 'NR>1 && $8=="3"' "${out_file}" 2>/dev/null | wc -l || echo "?")
    status "OK" "${rows} total MotW entries (${internet_rows} ZoneId=3/Internet) → ${out_file##*/}"
    log_cmd "${machine}" "Python/MFT ZoneIdentifier" \
        "python3 [embedded] — parse ZoneIdContents from MFT CSVs" \
        "Extract MotW fields from ${mft_csv_list}" \
        "${out_file}" \
        "${rows} rows, ${internet_rows} Internet-zone"
done

# ════════════════════════════════════════════════════════════════════════════
section "B. Chrome / Edge Chromium History (SQLite)"
# ════════════════════════════════════════════════════════════════════════════

# Embedded Python for Chromium SQLite parsing
cat > "${PY_SCRIPT}" <<'PYEOF'
import sys, csv, shutil, tempfile, sqlite3, os
from datetime import datetime, timedelta, timezone

# Chrome/Edge timestamp: microseconds since 1601-01-01 UTC
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

def chrome_ts(ts):
    try:
        val = int(ts)
        if val > 0:
            return (CHROME_EPOCH + timedelta(microseconds=val)).strftime('%Y-%m-%dT%H:%M:%SZ')
    except (TypeError, ValueError, OverflowError):
        pass
    return ''

def parse_transition(t):
    # Low 8 bits are core transition type
    try:
        return str(int(t) & 0xFF)
    except (TypeError, ValueError):
        return str(t)

db_path  = sys.argv[1]
machine  = sys.argv[2]
browser  = sys.argv[3]
username = sys.argv[4]
hist_out = sys.argv[5]
dl_out   = sys.argv[6]

tmp = tempfile.mktemp(suffix='.db')
try:
    shutil.copy2(db_path, tmp)

    # Also copy WAL/shm if present (avoid dirty-read artefacts)
    for ext in ('-wal', '-shm'):
        src = db_path + ext
        if os.path.isfile(src):
            shutil.copy2(src, tmp + ext)

    conn = sqlite3.connect(f'file:{tmp}?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row

    hist_rows  = 0
    dl_rows    = 0

    # ── History ──────────────────────────────────────────────────────────
    try:
        cur = conn.execute('''
            SELECT u.url,
                   u.title,
                   v.visit_time,
                   u.visit_count,
                   v.transition
            FROM   visits v
            JOIN   urls   u ON v.url = u.id
            ORDER  BY v.visit_time
        ''')
        with open(hist_out, 'w', newline='', encoding='utf-8') as fh:
            w = csv.writer(fh)
            w.writerow(['Machine', 'Browser', 'Username', 'VisitTime_UTC',
                        'URL', 'Title', 'VisitCount', 'TransitionType'])
            for row in cur:
                w.writerow([
                    machine, browser, username,
                    chrome_ts(row['visit_time']),
                    row['url'] or '',
                    (row['title'] or '').replace('\x00', ''),
                    row['visit_count'] or 0,
                    parse_transition(row['transition']),
                ])
                hist_rows += 1
    except sqlite3.OperationalError as e:
        print(f'WARNING: history query failed: {e}', file=sys.stderr)

    # ── Downloads ────────────────────────────────────────────────────────
    try:
        cur = conn.execute('''
            SELECT target_path,
                   tab_url,
                   referrer,
                   start_time,
                   total_bytes,
                   state
            FROM   downloads
            ORDER  BY start_time
        ''')
        with open(dl_out, 'w', newline='', encoding='utf-8') as fh:
            w = csv.writer(fh)
            w.writerow(['Machine', 'Browser', 'Username', 'StartTime_UTC',
                        'TargetPath', 'SourceURL', 'ReferrerURL',
                        'TotalBytes', 'State'])
            STATE_MAP = {0: 'InProgress', 1: 'Complete', 2: 'Cancelled', 4: 'Interrupted'}
            for row in cur:
                state_str = STATE_MAP.get(row['state'], str(row['state']))
                w.writerow([
                    machine, browser, username,
                    chrome_ts(row['start_time']),
                    row['target_path'] or '',
                    row['tab_url'] or '',
                    row['referrer'] or '',
                    row['total_bytes'] or 0,
                    state_str,
                ])
                dl_rows += 1
    except sqlite3.OperationalError as e:
        print(f'WARNING: downloads query failed: {e}', file=sys.stderr)

    conn.close()
    print(f'{hist_rows},{dl_rows}')

except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
finally:
    for p in [tmp, tmp + '-wal', tmp + '-shm']:
        try:
            os.unlink(p)
        except OSError:
            pass
PYEOF

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    out_dir="${ANALYSIS_DIR}/${machine}/Browser"

    machine_header "${machine} (drive ${drive}:)"

    users_dir="${drive_root}/Users"
    [[ -d "${users_dir}" ]] || { status "MISSING" "No Users/ directory"; continue; }

    found_any=0

    # ── Collect all Edge and Chrome History paths ─────────────────────────
    mapfile -t history_files < <(
        {
            find "${users_dir}" -path "*/Edge/User Data/Default/History" \
                 -not -path "*/ServiceProfiles/*" 2>/dev/null
            find "${users_dir}" -path "*/Chrome/User Data/Default/History" \
                 -not -path "*/ServiceProfiles/*" 2>/dev/null
        } | sort
    )

    for db_path in "${history_files[@]}"; do
        # Determine browser label
        if echo "${db_path}" | grep -qi "Edge"; then
            browser="Edge"
        else
            browser="Chrome"
        fi

        # Extract username (component after Users/)
        username=$(echo "${db_path}" | sed "s|${users_dir}/||" | cut -d'/' -f1)

        # Skip system accounts
        if echo "${username}" | grep -qE "^(${SKIP_USERS})$"; then
            status "SKIP" "${browser} — ${username} (system account)"
            continue
        fi

        hist_out="${out_dir}/${machine}_B_${browser}_${username}_History.csv"
        dl_out="${out_dir}/${machine}_B_${browser}_${username}_Downloads.csv"

        if [[ -f "${hist_out}" ]] && [[ $(wc -l < "${hist_out}" 2>/dev/null) -gt 1 ]]; then
            rows=$(( $(wc -l < "${hist_out}") - 1 ))
            status "SKIP" "${browser}/${username} History already exists (${rows} rows)"
            found_any=1
            continue
        fi

        mkdir -p "${out_dir}"

        cmd="python3 '${PY_SCRIPT}' '${db_path}' '${machine}' '${browser}' '${username}' '${hist_out}' '${dl_out}'"
        py_out=$(run_tool "${cmd}") && rc=0 || rc=$?

        if [[ ${rc} -ne 0 ]]; then
            status "ERROR" "${browser}/${username}: Python exited ${rc}"
            echo "${py_out}" | sed 's/^/    /'
            continue
        fi

        # py_out is "hist_rows,dl_rows"
        hist_rows=$(echo "${py_out}" | cut -d',' -f1)
        dl_rows=$(echo "${py_out}"   | cut -d',' -f2)

        [[ "${hist_rows}" == "0" ]] && rm -f "${hist_out}"
        [[ "${dl_rows}"   == "0" ]] && rm -f "${dl_out}"

        status "OK" "${browser}/${username}: ${hist_rows} history rows, ${dl_rows} download rows"
        found_any=1

        log_cmd "${machine}" "Python/sqlite3 (${browser})" \
            "python3 [embedded] '${db_path}'" \
            "Parse ${browser} browsing history and downloads for ${username}" \
            "${hist_out}, ${dl_out}" \
            "${hist_rows} history, ${dl_rows} downloads"
    done

    [[ ${found_any} -eq 0 ]] && status "MISSING" "No Chrome/Edge History databases found"
done

# ════════════════════════════════════════════════════════════════════════════
section "C. Firefox places.sqlite"
# ════════════════════════════════════════════════════════════════════════════

cat > "${PY_SCRIPT}" <<'PYEOF'
import sys, csv, shutil, tempfile, sqlite3, os, json
from datetime import datetime, timezone

# Firefox timestamp: microseconds since Unix epoch 1970-01-01 UTC
def ff_ts(us):
    try:
        val = int(us)
        if val > 0:
            return datetime.fromtimestamp(val / 1_000_000, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except (TypeError, ValueError, OverflowError):
        pass
    return ''

db_path  = sys.argv[1]
machine  = sys.argv[2]
username = sys.argv[3]
hist_out = sys.argv[4]
dl_out   = sys.argv[5]

tmp = tempfile.mktemp(suffix='.db')
try:
    shutil.copy2(db_path, tmp)
    for ext in ('-wal', '-shm'):
        src = db_path + ext
        if os.path.isfile(src):
            shutil.copy2(src, tmp + ext)

    conn = sqlite3.connect(f'file:{tmp}?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row

    hist_rows = 0
    dl_rows   = 0

    # ── History ──────────────────────────────────────────────────────────
    try:
        cur = conn.execute('''
            SELECT v.visit_date,
                   p.url,
                   p.title,
                   p.visit_count
            FROM   moz_historyvisits v
            JOIN   moz_places       p ON v.place_id = p.id
            ORDER  BY v.visit_date
        ''')
        with open(hist_out, 'w', newline='', encoding='utf-8') as fh:
            w = csv.writer(fh)
            w.writerow(['Machine', 'Browser', 'Username', 'VisitTime_UTC',
                        'URL', 'Title', 'VisitCount', 'TransitionType'])
            for row in cur:
                w.writerow([
                    machine, 'Firefox', username,
                    ff_ts(row['visit_date']),
                    row['url'] or '',
                    (row['title'] or '').replace('\x00', ''),
                    row['visit_count'] or 0,
                    '',  # Firefox does not expose a numeric transition type
                ])
                hist_rows += 1
    except sqlite3.OperationalError as e:
        print(f'WARNING: history query failed: {e}', file=sys.stderr)

    # ── Downloads via moz_annos ───────────────────────────────────────────
    # Firefox >= 26 stores downloads as annotations on moz_places entries.
    # Two attributes per download:
    #   downloads/destinationFileURI  → target path (file:// URI)
    #   downloads/metaData            → JSON with state, endTime, fileSize
    try:
        # Build a map: place_id -> {dest, meta}
        dl_map = {}  # place_id -> dict

        cur_attrs = conn.execute(
            "SELECT id, name FROM moz_anno_attributes WHERE name LIKE 'downloads/%'"
        )
        attr_ids = {row['name']: row['id'] for row in cur_attrs}

        dest_attr = attr_ids.get('downloads/destinationFileURI')
        meta_attr = attr_ids.get('downloads/metaData')

        if dest_attr is not None:
            cur_dest = conn.execute(
                'SELECT place_id, content FROM moz_annos WHERE anno_attribute_id = ?',
                (dest_attr,)
            )
            for row in cur_dest:
                pid = row['place_id']
                dl_map.setdefault(pid, {})['dest'] = row['content'] or ''

        if meta_attr is not None:
            cur_meta = conn.execute(
                'SELECT place_id, content, dateAdded FROM moz_annos WHERE anno_attribute_id = ?',
                (meta_attr,)
            )
            for row in cur_meta:
                pid = row['place_id']
                dl_map.setdefault(pid, {})['meta_json'] = row['content'] or '{}'
                dl_map.setdefault(pid, {})['dateAdded'] = row['dateAdded']

        if dl_map:
            # Fetch source URLs
            place_ids = list(dl_map.keys())
            placeholders = ','.join('?' * len(place_ids))
            cur_places = conn.execute(
                f'SELECT id, url FROM moz_places WHERE id IN ({placeholders})',
                place_ids
            )
            place_urls = {row['id']: row['url'] for row in cur_places}

            with open(dl_out, 'w', newline='', encoding='utf-8') as fh:
                w = csv.writer(fh)
                w.writerow(['Machine', 'Browser', 'Username', 'StartTime_UTC',
                            'TargetPath', 'SourceURL', 'ReferrerURL',
                            'TotalBytes', 'State'])
                STATE_MAP = {0: 'InProgress', 1: 'Complete', 2: 'Cancelled',
                             3: 'Blocked', 4: 'Dirty'}
                for pid, info in dl_map.items():
                    dest     = info.get('dest', '')
                    # Convert file:// URI to a readable path
                    if dest.startswith('file:///'):
                        dest = dest[8:].replace('%20', ' ').replace('/', '\\')
                    elif dest.startswith('file://'):
                        dest = dest[7:]

                    meta     = {}
                    try:
                        meta = json.loads(info.get('meta_json', '{}'))
                    except (json.JSONDecodeError, ValueError):
                        pass

                    state_num = meta.get('state', '')
                    state_str = STATE_MAP.get(state_num, str(state_num))
                    end_ms    = meta.get('endTime', 0)    # milliseconds since epoch
                    file_size = meta.get('fileSize', 0)

                    # Use dateAdded (µs) for start time; endTime (ms) for completion
                    date_added_us = info.get('dateAdded', 0)
                    start_utc = ff_ts(date_added_us) if date_added_us else ''

                    w.writerow([
                        machine, 'Firefox', username,
                        start_utc,
                        dest,
                        place_urls.get(pid, ''),
                        '',  # referrer not stored separately in moz_annos
                        file_size,
                        state_str,
                    ])
                    dl_rows += 1

    except sqlite3.OperationalError as e:
        print(f'WARNING: downloads query failed: {e}', file=sys.stderr)

    conn.close()
    print(f'{hist_rows},{dl_rows}')

except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
finally:
    for p in [tmp, tmp + '-wal', tmp + '-shm']:
        try:
            os.unlink(p)
        except OSError:
            pass
PYEOF

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    out_dir="${ANALYSIS_DIR}/${machine}/Browser"

    machine_header "${machine} (drive ${drive}:)"

    users_dir="${drive_root}/Users"
    [[ -d "${users_dir}" ]] || { status "MISSING" "No Users/ directory"; continue; }

    found_any=0

    mapfile -t places_files < <(
        find "${users_dir}" -name "places.sqlite" \
             -not -path "*/ServiceProfiles/*" 2>/dev/null | sort
    )

    for db_path in "${places_files[@]}"; do
        username=$(echo "${db_path}" | sed "s|${users_dir}/||" | cut -d'/' -f1)

        if echo "${username}" | grep -qE "^(${SKIP_USERS})$"; then
            status "SKIP" "Firefox — ${username} (system account)"
            continue
        fi

        hist_out="${out_dir}/${machine}_C_Firefox_${username}_History.csv"
        dl_out="${out_dir}/${machine}_C_Firefox_${username}_Downloads.csv"

        if [[ -f "${hist_out}" ]] && [[ $(wc -l < "${hist_out}" 2>/dev/null) -gt 1 ]]; then
            rows=$(( $(wc -l < "${hist_out}") - 1 ))
            status "SKIP" "Firefox/${username} History already exists (${rows} rows)"
            found_any=1
            continue
        fi

        mkdir -p "${out_dir}"

        cmd="python3 '${PY_SCRIPT}' '${db_path}' '${machine}' '${username}' '${hist_out}' '${dl_out}'"
        py_out=$(run_tool "${cmd}") && rc=0 || rc=$?

        if [[ ${rc} -ne 0 ]]; then
            status "ERROR" "Firefox/${username}: Python exited ${rc}"
            echo "${py_out}" | sed 's/^/    /'
            continue
        fi

        hist_rows=$(echo "${py_out}" | cut -d',' -f1)
        dl_rows=$(echo "${py_out}"   | cut -d',' -f2)

        [[ "${hist_rows}" == "0" ]] && rm -f "${hist_out}"
        [[ "${dl_rows}"   == "0" ]] && rm -f "${dl_out}"

        status "OK" "Firefox/${username}: ${hist_rows} history rows, ${dl_rows} download rows"
        found_any=1

        log_cmd "${machine}" "Python/sqlite3 (Firefox)" \
            "python3 [embedded] '${db_path}'" \
            "Parse Firefox browsing history and downloads for ${username}" \
            "${hist_out}, ${dl_out}" \
            "${hist_rows} history, ${dl_rows} downloads"
    done

    [[ ${found_any} -eq 0 ]] && status "MISSING" "No Firefox places.sqlite databases found"
done

# ════════════════════════════════════════════════════════════════════════════
section "D. IE / Edge Legacy — WebCacheV01.dat (esedbexport)"
# ════════════════════════════════════════════════════════════════════════════

# Embedded Python to parse esedbexport TSV output
cat > "${PY_SCRIPT}" <<'PYEOF'
import sys, csv, os, glob, re

export_dir = sys.argv[1]
machine    = sys.argv[2]
username   = sys.argv[3]
out_file   = sys.argv[4]

# ── Step 1: Find the Containers table file ────────────────────────────────
containers_file = None
for f in glob.glob(os.path.join(export_dir, 'Containers.*')):
    containers_file = f
    break

if containers_file is None:
    print('ERROR: Containers table not found', file=sys.stderr)
    sys.exit(1)

# ── Step 2: Read Containers to find History container IDs ─────────────────
# Name column contains: 'History', 'MSHist<dates>', etc.
history_container_ids = set()
try:
    with open(containers_file, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            name = row.get('Name', '')
            # Include History containers and MSHist daily rollup containers
            if re.match(r'^(History|MSHist\d+)$', name, re.IGNORECASE):
                cid = row.get('ContainerId', '').strip()
                if cid:
                    history_container_ids.add(cid)
except Exception as e:
    print(f'ERROR reading Containers: {e}', file=sys.stderr)
    sys.exit(1)

if not history_container_ids:
    print('0')
    sys.exit(0)

# ── Step 3: Parse matching Container_<id>.* files ─────────────────────────
rows_written = 0

with open(out_file, 'w', newline='', encoding='utf-8') as fout:
    writer = csv.writer(fout)
    writer.writerow(['Machine', 'Browser', 'Username', 'AccessedTime_UTC',
                     'URL', 'Title', 'AccessCount'])

    for cid in sorted(history_container_ids):
        # File pattern: Container_<cid>.<sequence>
        pattern = os.path.join(export_dir, f'Container_{cid}.*')
        for tbl_file in sorted(glob.glob(pattern)):
            try:
                with open(tbl_file, 'r', encoding='utf-8', errors='replace') as f:
                    reader = csv.DictReader(f, delimiter='\t')
                    for row in reader:
                        url_raw = row.get('Url', '')
                        if not url_raw:
                            continue

                        # Strip "Visited: username@" prefix
                        url_clean = re.sub(r'^Visited:\s*[^@]*@', '', url_raw, flags=re.IGNORECASE)

                        # Skip non-HTTP entries (blank lines, internal markers)
                        if not url_clean or url_clean.startswith(':'):
                            continue

                        accessed = row.get('AccessedTime', '').strip()
                        # esedbexport renders timestamps as "Mon DD, YYYY HH:MM:SS.nnnnnnnnn"
                        # Convert to ISO UTC (already UTC from ESE)
                        accessed_utc = ''
                        if accessed and accessed != 'Jan 01, 1601 00:00:00.000000000':
                            try:
                                from datetime import datetime
                                # Strip nanosecond precision beyond microseconds
                                ts_str = re.sub(r'(\.\d{6})\d+', r'\1', accessed)
                                dt = datetime.strptime(ts_str, '%b %d, %Y %H:%M:%S.%f')
                                accessed_utc = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
                            except ValueError:
                                accessed_utc = accessed

                        access_count = row.get('AccessCount', '').strip()

                        writer.writerow([
                            machine,
                            'IE/EdgeLegacy',
                            username,
                            accessed_utc,
                            url_clean,
                            '',   # Title not stored separately in Container tables
                            access_count,
                        ])
                        rows_written += 1
            except Exception as e:
                print(f'WARNING: could not parse {tbl_file}: {e}', file=sys.stderr)

print(rows_written)
PYEOF

if [[ ! -x "${ESEDBEXPORT}" ]]; then
    status "MISSING" "esedbexport not found at ${ESEDBEXPORT} — skipping Section D"
else

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    drive=$(echo "${drive_root}"   | grep -oP '(?<=/)[A-Z]$')
    out_dir="${ANALYSIS_DIR}/${machine}/Browser"

    machine_header "${machine} (drive ${drive}:)"

    users_dir="${drive_root}/Users"
    [[ -d "${users_dir}" ]] || { status "MISSING" "No Users/ directory"; continue; }

    found_any=0

    mapfile -t webcache_files < <(
        find "${users_dir}" -name "WebCacheV01.dat" \
             -not -path "*/ServiceProfiles/*" 2>/dev/null | sort
    )

    for dat_path in "${webcache_files[@]}"; do
        username=$(echo "${dat_path}" | sed "s|${users_dir}/||" | cut -d'/' -f1)

        if echo "${username}" | grep -qE "^(${SKIP_USERS})$"; then
            status "SKIP" "IE/EdgeLegacy — ${username} (system account)"
            continue
        fi

        out_file="${out_dir}/${machine}_D_IELegacy_${username}_History.csv"

        if [[ -f "${out_file}" ]] && [[ $(wc -l < "${out_file}" 2>/dev/null) -gt 1 ]]; then
            rows=$(( $(wc -l < "${out_file}") - 1 ))
            status "SKIP" "IE/EdgeLegacy/${username} already exists (${rows} rows)"
            found_any=1
            continue
        fi

        mkdir -p "${out_dir}"

        # Export to a temporary directory
        ese_tmp=$(mktemp -d /tmp/webcache_XXXXXX)

        ese_cmd="${ESEDBEXPORT} -t '${ese_tmp}/webcache' '${dat_path}'"
        ese_out=$(run_tool "${ese_cmd}") && ese_rc=0 || ese_rc=$?

        export_dir="${ese_tmp}/webcache.export"
        if [[ ${ese_rc} -ne 0 ]] || [[ ! -d "${export_dir}" ]]; then
            status "ERROR" "esedbexport failed (rc=${ese_rc}) for ${username}"
            echo "${ese_out}" | tail -5 | sed 's/^/    /'
            rm -rf "${ese_tmp}"
            continue
        fi

        cmd="python3 '${PY_SCRIPT}' '${export_dir}' '${machine}' '${username}' '${out_file}'"
        py_out=$(run_tool "${cmd}") && py_rc=0 || py_rc=$?
        rm -rf "${ese_tmp}"

        if [[ ${py_rc} -ne 0 ]]; then
            status "ERROR" "IE/EdgeLegacy/${username}: Python exited ${py_rc}"
            echo "${py_out}" | sed 's/^/    /'
            continue
        fi

        rows="${py_out}"
        if [[ -z "${rows}" || "${rows}" == "0" ]]; then
            status "EMPTY" "IE/EdgeLegacy/${username}: no History entries extracted"
            rm -f "${out_file}"
            continue
        fi

        status "OK" "IE/EdgeLegacy/${username}: ${rows} history rows → ${out_file##*/}"
        found_any=1

        log_cmd "${machine}" "esedbexport + Python (IE/EdgeLegacy)" \
            "${ese_cmd}" \
            "Export WebCacheV01.dat ESE tables, then parse History containers for ${username}" \
            "${out_file}" \
            "${rows} history rows"
    done

    [[ ${found_any} -eq 0 ]] && status "MISSING" "No WebCacheV01.dat files found"
done

fi  # end esedbexport check

# ════════════════════════════════════════════════════════════════════════════
section "Summary"
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "Browser output:"

total_hist=0
total_dl=0
total_zone=0
total_ie=0

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    browser_dir="${ANALYSIS_DIR}/${machine}/Browser"
    [[ -d "${browser_dir}" ]] || continue

    # Section A
    zone_file="${browser_dir}/${machine}_A_ZoneIdentifier.csv"
    if [[ -f "${zone_file}" ]]; then
        z_rows=$(( $(wc -l < "${zone_file}") - 1 ))
        z3=$(awk -F',' 'NR>1 && $8=="3"' "${zone_file}" 2>/dev/null | wc -l || echo 0)
        printf "  %-6s  ZoneIdentifier: %d total (%d Internet/ZoneId=3)  %s\n" \
               "${machine}" "${z_rows}" "${z3}" "${zone_file}"
        total_zone=$(( total_zone + z_rows ))
    fi

    # Sections B/C history
    while IFS= read -r f; do
        [[ -f "${f}" ]] || continue
        r=$(( $(wc -l < "${f}") - 1 ))
        printf "  %-6s  History (%d rows):  %s\n" "${machine}" "${r}" "${f}"
        total_hist=$(( total_hist + r ))
    done < <(find "${browser_dir}" -maxdepth 1 \
              \( -name "*_B_*_History.csv" -o -name "*_C_*_History.csv" \) 2>/dev/null | sort)

    # Sections B/C downloads
    while IFS= read -r f; do
        [[ -f "${f}" ]] || continue
        r=$(( $(wc -l < "${f}") - 1 ))
        printf "  %-6s  Downloads (%d rows):  %s\n" "${machine}" "${r}" "${f}"
        total_dl=$(( total_dl + r ))
    done < <(find "${browser_dir}" -maxdepth 1 \
              \( -name "*_B_*_Downloads.csv" -o -name "*_C_*_Downloads.csv" \) 2>/dev/null | sort)

    # Section D
    while IFS= read -r f; do
        [[ -f "${f}" ]] || continue
        r=$(( $(wc -l < "${f}") - 1 ))
        printf "  %-6s  IE/Legacy History (%d rows):  %s\n" "${machine}" "${r}" "${f}"
        total_ie=$(( total_ie + r ))
    done < <(find "${browser_dir}" -maxdepth 1 -name "*_D_*_History.csv" 2>/dev/null | sort)
done

echo ""
echo "  Totals:"
echo "    MotW / ZoneIdentifier entries : ${total_zone}"
echo "    Browser history rows          : ${total_hist}"
echo "    Download rows                 : ${total_dl}"
echo "    IE/Legacy history rows        : ${total_ie}"
echo ""
echo " Phase 11 complete — $(date -u)"
