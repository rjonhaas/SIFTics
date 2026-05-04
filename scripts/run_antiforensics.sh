#!/usr/bin/env bash
# DAEDALUS:HANDLES win_evtx win_registry
# run_antiforensics.sh — Phase 8: Anti-Forensics Detection
#
# Sections (A–C work on Phase 3 EvtxECmd CSVs; D works on Phase 4 Prefetch
# and Phase 2 Registry/Amcache/ShimCache CSVs):
#   A. Log Clearing         — 1102 (Security log cleared), 104 (System log cleared),
#                             1100 (EventLog service shutdown), 1108 (EventLog error)
#   B. VSS / Shadow Copy    — 4688 process creation w/ shadow-delete cmdline,
#                             8194/8198 VSS errors (System log)
#   C. Defender Tampering   — 5001/5004/5007/5010/5012 (protection disabled/changed),
#                             1116/1117/3002 (malware detected/not-remediated)
#   D. Anti-Forensic Tools  — Prefetch + Amcache/ShimCache CSVs scanned for
#                             known wipe/evidence-elimination tool names
#   F. Cross-machine Timeline — all flagged evtx events merged and sorted by UTC time
#
# Input  : analysis/<MACHINE>/EventLogs/*_evtx*.csv   (Phase 3)
#          analysis/<MACHINE>/Artifacts/Prefetch/*.csv (Phase 4)
#          analysis/<MACHINE>/Registry/**/*.csv        (Phase 2)
# Output : analysis/<MACHINE>/AntiForensics/*.csv
#          analysis/antiforensics_timeline.csv  (cross-machine, sorted UTC)
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
TIMELINE_OUT="${ANALYSIS_DIR}/antiforensics_timeline.csv"

# ─── helpers ─────────────────────────────────────────────────────────────────

log_cmd() {
    local machine="$1" tool="$2" cmd="$3" purpose="$4" output="$5" result="$6"
    cat >> "${COMMAND_LOG}" <<EOF

[${TIMESTAMP}] ${machine} | ${tool} | Python Analysis
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

mapfile -t DRIVE_ROOTS < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -name '$MFT' -print \
    | sort | xargs -I{} dirname {}
)

echo "════════════════════════════════════════════════════"
echo " Anti-Forensics Detection — jackofallhacks"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ─── embedded Python analyzer ────────────────────────────────────────────────

PY_SCRIPT=$(mktemp /tmp/antiforensics_XXXXXX.py)
trap 'rm -f "${PY_SCRIPT}"' EXIT

cat > "${PY_SCRIPT}" << 'PYEOF'
#!/usr/bin/env python3
"""
antiforensics_analyzer.py
  --mode evtx : Sections A–C over EvtxECmd CSVs
  --mode exec : Section D over Prefetch + Registry/Amcache/ShimCache CSVs
"""

import csv, sys, os, re, argparse
from pathlib import Path

# ── Section A: Log clearing event IDs ────────────────────────────────────────
LOG_CLEAR_IDS = {1102, 104, 1100, 1108}

# ── Section B: VSS / Shadow Copy ─────────────────────────────────────────────
VSS_PROC_IDS = {4688}          # process creation — filter by cmdline
VSS_ERR_IDS  = {8194, 8198}    # VSS errors from System log (keep all)
VSS_CMDLINE  = re.compile(
    r'vssadmin.*delete|wmic.*shadowcopy.*delete|vssadmin.*resize.*shadowstorage',
    re.IGNORECASE
)

# ── Section C: Defender tampering ─────────────────────────────────────────────
DEFENDER_IDS = {5001, 5004, 5007, 5010, 5012, 1116, 1117, 3002}

# All EVTX event IDs of interest (union of A, B, C)
ALL_EVTX_IDS = LOG_CLEAR_IDS | VSS_PROC_IDS | VSS_ERR_IDS | DEFENDER_IDS

# ── Section D: Anti-forensic tool names ──────────────────────────────────────
ANTIFORENSIC_TOOLS = re.compile(
    r'sdelete|eraser|bleachbit|ccleaner|mru.?blaster|evidence.?eliminator'
    r'|wipe\.exe|freeraser|dban|nwipe|cipher|vssadmin',
    re.IGNORECASE
)

# ── Timeline output columns ───────────────────────────────────────────────────
TL_FIELDS = [
    "TimeCreated", "Machine", "Computer", "EventId",
    "Channel", "Section", "MapDescription", "UserName", "RemoteHost",
]

# ── Section labels ────────────────────────────────────────────────────────────
SECTION_LABELS = {
    "A": "Log Clearing",
    "B": "VSS Shadow Deletion",
    "C": "Defender Tampering",
}

# ─── helpers ──────────────────────────────────────────────────────────────────

def find_col(headers, *candidates):
    """Return the first header that matches any candidate (case-insensitive)."""
    hl = {h.strip().lower(): h for h in headers}
    for c in candidates:
        if c.lower() in hl:
            return hl[c.lower()]
    return None

def row_text(row):
    return " ".join(str(v) for v in row.values())

def open_writer(path, fieldnames):
    """Open a CSV file for writing, write header, return (file, DictWriter)."""
    fout = open(path, "w", newline="", encoding="utf-8")
    w = csv.DictWriter(fout, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    return fout, w

def append_timeline(timeline_file, rows):
    """Append rows to the global timeline CSV, writing header if new."""
    if not rows or not timeline_file:
        return
    tl_path   = Path(timeline_file)
    tl_exists = tl_path.exists() and tl_path.stat().st_size > 10
    with open(tl_path, "a", newline="", encoding="utf-8") as tf:
        w = csv.DictWriter(tf, fieldnames=TL_FIELDS)
        if not tl_exists:
            w.writeheader()
        w.writerows(rows)

# ─── evtx mode: Sections A–C ─────────────────────────────────────────────────

def analyze_evtx(evtlog_dir, out_dir, machine, timeline_file):
    in_path  = Path(evtlog_dir)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(in_path.glob("*_evtx*.csv"))
    if not csv_files:
        print(f"  [MISSING   ] No *_evtx*.csv in {evtlog_dir}")
        return {}

    # Lazy-open writers per section key
    writers  = {}   # sec_key -> DictWriter
    handles  = {}   # sec_key -> file handle
    counts   = {"A": 0, "B": 0, "C": 0}
    total    = 0
    timeline = []

    for csv_path in csv_files:
        try:
            with open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    continue
                headers = reader.fieldnames

                eid_col  = find_col(headers, "EventId",       "EventID",   "Event Id",  "Event ID")
                time_col = find_col(headers, "TimeCreated",   "Time Created", "Timestamp")
                comp_col = find_col(headers, "Computer",      "ComputerName")
                desc_col = find_col(headers, "MapDescription","Description", "MapDesc")
                user_col = find_col(headers, "UserName",      "User Name",  "Username")
                host_col = find_col(headers, "RemoteHost",    "Remote Host","IpAddress","WorkstationName")
                chan_col = find_col(headers, "Channel",       "LogName")

                if not eid_col:
                    continue

                for row in reader:
                    total += 1
                    try:
                        eid = int(row[eid_col].strip())
                    except (ValueError, KeyError):
                        continue

                    if eid not in ALL_EVTX_IDS:
                        continue

                    rt = row_text(row)

                    # ── Determine which section(s) this event belongs to ───────
                    matched_sections = []

                    # Section A — log clearing (keep all)
                    if eid in LOG_CLEAR_IDS:
                        matched_sections.append("A")

                    # Section B — VSS deletion
                    if eid in VSS_ERR_IDS:
                        matched_sections.append("B")
                    elif eid in VSS_PROC_IDS:  # 4688
                        if VSS_CMDLINE.search(rt):
                            matched_sections.append("B")

                    # Section C — Defender tampering (keep all)
                    if eid in DEFENDER_IDS:
                        matched_sections.append("C")

                    for sec in matched_sections:
                        # Lazy-open the CSV for this section
                        if sec not in writers:
                            out_file = out_path / f"{machine}_{sec}_AntiForensics_{SECTION_LABELS[sec].replace(' ','')}.csv"
                            fh2, w2 = open_writer(out_file, headers)
                            writers[sec] = w2
                            handles[sec] = fh2

                        writers[sec].writerow(row)
                        counts[sec] += 1

                        timeline.append({
                            "TimeCreated":    row.get(time_col, "") if time_col else "",
                            "Machine":        machine,
                            "Computer":       row.get(comp_col, "") if comp_col else "",
                            "EventId":        str(eid),
                            "Channel":        row.get(chan_col, "") if chan_col else "",
                            "Section":        SECTION_LABELS[sec],
                            "MapDescription": row.get(desc_col, "") if desc_col else "",
                            "UserName":       row.get(user_col, "") if user_col else "",
                            "RemoteHost":     row.get(host_col, "") if host_col else "",
                        })

        except Exception as e:
            print(f"  [WARN      ] {csv_path.name}: {e}", file=sys.stderr)

    for fh2 in handles.values():
        fh2.close()

    append_timeline(timeline_file, timeline)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"  Events scanned : {total}")
    for sec, label in SECTION_LABELS.items():
        n = counts[sec]
        star = " *" if n > 0 else ""
        print(f"    {sec} — {label:<30s}: {n}{star}")

    if not any(counts.values()):
        print("  [NOTE] Zero matches — event log audit policy may not capture these events,")
        print("         or Phase 3 evtx parse needs to complete first.")

    return counts

# ─── exec mode: Section D ─────────────────────────────────────────────────────

# Output columns for Section D
D_FIELDS = [
    "ToolName", "FullPath", "SourceFile",
    "FileNameTimestamp", "LastWriteTimestamp", "ProgramName",
    "SHA1", "AdditionalContext",
]

def scan_csv_for_tools(csv_path, hits):
    """
    Scan a single CSV file for anti-forensic tool references.
    Appends dicts (D_FIELDS) to hits list.
    """
    try:
        with open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                return
            headers = reader.fieldnames

            # Identify useful columns — names vary by tool (PECmd vs AmcacheParser)
            name_col   = find_col(headers,
                "ExecutableName", "FileName", "Name", "ApplicationName",
                "ProgramName", "ImageFileName",
            )
            path_col   = find_col(headers,
                "FullPath", "SourceFilePath", "Path", "FilePath",
                "ApplicationPath", "ExePath",
            )
            ts_col     = find_col(headers,
                "LastRun", "RunTime", "LastWriteTimestamp",
                "FileKeyLastWriteTimestamp", "Created0x10", "LastModified0x10",
                "Timestamp", "TimeCreated",
            )
            ts2_col    = find_col(headers,
                "LastWriteTimestamp", "FileKeyLastWriteTimestamp",
                "LastModified0x10", "Created0x10",
            )
            sha1_col   = find_col(headers, "SHA1", "Sha1", "Hash")
            prog_col   = find_col(headers, "ProgramName", "ProductName", "ApplicationName")

            src_name = Path(csv_path).name

            for row in reader:
                # Build a searchable text from name + path columns
                candidate_name = row.get(name_col, "") if name_col else ""
                candidate_path = row.get(path_col, "") if path_col else ""
                search_text    = " ".join([candidate_name, candidate_path])

                if not ANTIFORENSIC_TOOLS.search(search_text):
                    continue

                # Extract the matched tool name token
                m = ANTIFORENSIC_TOOLS.search(search_text)
                tool_name = m.group(0) if m else search_text[:40]

                full_path = candidate_path or candidate_name or "(unknown)"

                ts_val  = row.get(ts_col,  "") if ts_col  else ""
                ts2_val = row.get(ts2_col, "") if ts2_col else ""
                sha1    = row.get(sha1_col,"") if sha1_col else ""
                prog    = row.get(prog_col,"") if prog_col else ""

                # Build extra context from any remaining populated columns
                extra_parts = []
                for col in headers:
                    if col in (name_col, path_col, ts_col, ts2_col, sha1_col, prog_col):
                        continue
                    val = row.get(col, "").strip()
                    if val and val not in ("-", "0", "False", "false", ""):
                        extra_parts.append(f"{col}={val}")
                extra = "; ".join(extra_parts[:6])  # cap at 6 fields to keep readable

                hits.append({
                    "ToolName":            tool_name,
                    "FullPath":            full_path,
                    "SourceFile":          src_name,
                    "FileNameTimestamp":   ts_val,
                    "LastWriteTimestamp":  ts2_val,
                    "ProgramName":         prog,
                    "SHA1":                sha1,
                    "AdditionalContext":   extra,
                })

    except Exception as e:
        print(f"  [WARN      ] {Path(csv_path).name}: {e}", file=sys.stderr)


def analyze_exec(prefetch_dir, registry_dir, out_dir, machine):
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    hits = []

    # ── Scan Prefetch CSVs ─────────────────────────────────────────────────────
    if prefetch_dir and Path(prefetch_dir).is_dir():
        pf_csvs = list(Path(prefetch_dir).glob("*.csv"))
        for csv_path in sorted(pf_csvs):
            scan_csv_for_tools(csv_path, hits)

    # ── Scan Registry / Amcache / ShimCache CSVs ──────────────────────────────
    if registry_dir and Path(registry_dir).is_dir():
        # Walk up to 3 levels deep (Registry/<subdir>/<csv>)
        reg_csvs = sorted(Path(registry_dir).rglob("*.csv"))
        # Also match extensionless Amcache output files
        reg_other = sorted(
            f for f in Path(registry_dir).rglob("*")
            if f.is_file() and f.suffix == ""
        )
        for csv_path in reg_csvs + reg_other:
            scan_csv_for_tools(csv_path, hits)

    out_file = out_path / f"{machine}_D_AntiForensicTools.csv"

    if hits:
        with open(out_file, "w", newline="", encoding="utf-8") as fo:
            w = csv.DictWriter(fo, fieldnames=D_FIELDS)
            w.writeheader()
            w.writerows(hits)

    print(f"  Anti-forensic tool hits : {len(hits)}")
    if hits:
        seen = set()
        for h in hits:
            key = h["ToolName"].lower()
            if key not in seen:
                seen.add(key)
                print(f"    * {h['ToolName']:<25s}  {h['FullPath']}")
    else:
        print("  [NOTE] No known anti-forensic tools found in execution artifacts.")

    return len(hits)

# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode",          required=True, choices=["evtx", "exec"])
    ap.add_argument("--evtlog-dir",    default="")
    ap.add_argument("--prefetch-dir",  default="")
    ap.add_argument("--registry-dir",  default="")
    ap.add_argument("--output-dir",    required=True)
    ap.add_argument("--machine",       required=True)
    ap.add_argument("--timeline-out",  default="")
    args = ap.parse_args()

    if args.mode == "evtx":
        if not args.evtlog_dir:
            print("--evtlog-dir required for evtx mode"); sys.exit(1)
        analyze_evtx(args.evtlog_dir, args.output_dir, args.machine, args.timeline_out)
    else:
        if not args.prefetch_dir and not args.registry_dir:
            print("--prefetch-dir or --registry-dir required for exec mode"); sys.exit(1)
        analyze_exec(args.prefetch_dir, args.registry_dir, args.output_dir, args.machine)

if __name__ == "__main__":
    main()
PYEOF

# ─── per-machine analysis loop — evtx mode (Sections A–C) ───────────────────

section "A–C. Anti-Forensics (EvtxECmd CSVs per machine)"

declare -A EVTX_COUNTS_A=()
declare -A EVTX_COUNTS_B=()
declare -A EVTX_COUNTS_C=()

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    evtlog_dir="${ANALYSIS_DIR}/${machine}/EventLogs"
    out_dir="${ANALYSIS_DIR}/${machine}/AntiForensics"

    machine_header "${machine}"

    if ! csv_has_data "${evtlog_dir}" "*_evtx*.csv"; then
        status "SKIP" "No EventLog CSVs — run Phase 3 (run_eventlogs.sh) first"
        EVTX_COUNTS_A["${machine}"]=0
        EVTX_COUNTS_B["${machine}"]=0
        EVTX_COUNTS_C["${machine}"]=0
        continue
    fi

    # Skip if all three section CSVs already exist
    a_csv="${out_dir}/${machine}_A_AntiForensics_LogClearing.csv"
    b_csv="${out_dir}/${machine}_B_AntiForensics_VSSShadowDeletion.csv"
    c_csv="${out_dir}/${machine}_C_AntiForensics_DefenderTampering.csv"

    if [[ -f "${a_csv}" ]] || [[ -f "${b_csv}" ]] || [[ -f "${c_csv}" ]]; then
        status "SKIP" "Anti-forensics evtx CSVs already exist"
        EVTX_COUNTS_A["${machine}"]=$(( $(wc -l < "${a_csv}" 2>/dev/null || echo 1) - 1 ))
        EVTX_COUNTS_B["${machine}"]=$(( $(wc -l < "${b_csv}" 2>/dev/null || echo 1) - 1 ))
        EVTX_COUNTS_C["${machine}"]=$(( $(wc -l < "${c_csv}" 2>/dev/null || echo 1) - 1 ))
        continue
    fi

    mkdir -p "${out_dir}"
    cmd="python3 ${PY_SCRIPT} --mode evtx --evtlog-dir '${evtlog_dir}' --output-dir '${out_dir}' --machine '${machine}' --timeline-out '${TIMELINE_OUT}'"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    echo "${tool_out}" | sed 's/^/  /'

    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "Analyzer exited ${rc}"
        EVTX_COUNTS_A["${machine}"]=0
        EVTX_COUNTS_B["${machine}"]=0
        EVTX_COUNTS_C["${machine}"]=0
        continue
    fi

    evtx_csvs=$(find "${out_dir}" -maxdepth 1 -name "*.csv" 2>/dev/null | wc -l)
    status "OK" "${evtx_csvs} section CSV(s) → ${out_dir}"

    EVTX_COUNTS_A["${machine}"]=$(( $(wc -l < "${a_csv}" 2>/dev/null || echo 1) - 1 ))
    EVTX_COUNTS_B["${machine}"]=$(( $(wc -l < "${b_csv}" 2>/dev/null || echo 1) - 1 ))
    EVTX_COUNTS_C["${machine}"]=$(( $(wc -l < "${c_csv}" 2>/dev/null || echo 1) - 1 ))

    log_cmd "${machine}" "antiforensics_analyzer.py evtx (Phase 8 A–C)" \
        "${cmd}" \
        "Detect anti-forensics via event logs: A=log clearing (1102/104/1100/1108), B=VSS/shadow deletion (4688 cmdline + 8194/8198), C=Defender tampering (5001/5004/5007/5010/5012/1116/1117/3002)" \
        "${out_dir}/${machine}_[ABC]_AntiForensics_*.csv" \
        "${evtx_csvs} section CSVs written"
done

# ─── per-machine analysis loop — exec mode (Section D) ──────────────────────

section "D. Anti-Forensic Tool Execution (Prefetch + Registry CSVs)"

declare -A EXEC_COUNTS_D=()

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    prefetch_dir="${ANALYSIS_DIR}/${machine}/Artifacts/Prefetch"
    registry_dir="${ANALYSIS_DIR}/${machine}/Registry"
    out_dir="${ANALYSIS_DIR}/${machine}/AntiForensics"
    d_csv="${out_dir}/${machine}_D_AntiForensicTools.csv"

    machine_header "${machine}"

    has_prefetch=false
    has_registry=false
    csv_has_data "${prefetch_dir}" "*.csv" && has_prefetch=true
    csv_has_data "${registry_dir}" "*.csv" && has_registry=true

    if ! ${has_prefetch} && ! ${has_registry}; then
        status "SKIP" "No Prefetch or Registry CSVs — run Phase 2/4 first"
        EXEC_COUNTS_D["${machine}"]=0
        continue
    fi

    if [[ -f "${d_csv}" ]]; then
        status "SKIP" "Tool execution CSV already exists"
        EXEC_COUNTS_D["${machine}"]=$(( $(wc -l < "${d_csv}" 2>/dev/null || echo 1) - 1 ))
        continue
    fi

    mkdir -p "${out_dir}"

    pf_arg=""
    reg_arg=""
    ${has_prefetch} && pf_arg="--prefetch-dir '${prefetch_dir}'"
    ${has_registry} && reg_arg="--registry-dir '${registry_dir}'"

    cmd="python3 ${PY_SCRIPT} --mode exec ${pf_arg} ${reg_arg} --output-dir '${out_dir}' --machine '${machine}'"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    echo "${tool_out}" | sed 's/^/  /'

    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "Analyzer exited ${rc}"
        EXEC_COUNTS_D["${machine}"]=0
        continue
    fi

    d_count=0
    [[ -f "${d_csv}" ]] && d_count=$(( $(wc -l < "${d_csv}") - 1 ))
    EXEC_COUNTS_D["${machine}"]=${d_count}

    if [[ ${d_count} -gt 0 ]]; then
        status "FOUND" "${d_count} anti-forensic tool hit(s) → ${d_csv}"
    else
        status "OK" "No tool hits found"
    fi

    log_cmd "${machine}" "antiforensics_analyzer.py exec (Phase 8 D)" \
        "${cmd}" \
        "Scan Prefetch + Amcache/ShimCache CSVs for known wipe/evidence-elimination tools: sdelete, eraser, bleachbit, ccleaner, mru-blaster, evidence-eliminator, wipe.exe, freeraser, dban, nwipe, cipher, vssadmin" \
        "${d_csv}" \
        "${d_count} tool hits"
done

# ─── Section F: sort cross-machine timeline ──────────────────────────────────

section "F. Cross-machine Anti-Forensics Timeline"

if [[ -f "${TIMELINE_OUT}" ]] && [[ $(wc -l < "${TIMELINE_OUT}") -gt 1 ]]; then
    TMP_TL=$(mktemp /tmp/antiforensics_tl_XXXXXX.csv)
    head -1    "${TIMELINE_OUT}" >  "${TMP_TL}"
    tail -n +2 "${TIMELINE_OUT}" | sort -t',' -k1,1 >> "${TMP_TL}"
    mv "${TMP_TL}" "${TIMELINE_OUT}"

    total_rows=$(( $(wc -l < "${TIMELINE_OUT}") - 1 ))
    echo "  File : ${TIMELINE_OUT}"
    echo "  Rows : ${total_rows} events across all machines (sorted UTC)"
    echo ""
    printf "  %-30s  %s\n" "Section" "Events"
    echo "  ──────────────────────────────────────────────"
    for label in "Log Clearing" "VSS Shadow Deletion" "Defender Tampering"; do
        count=$(grep -c "${label}" "${TIMELINE_OUT}" 2>/dev/null || echo 0)
        printf "  %-30s  %s\n" "${label}" "${count}"
    done
else
    echo "  No timeline events — Phase 3 must complete before Sections A–C can run."
fi

# ─── Summary with HIGH warnings ──────────────────────────────────────────────

section "Summary"

echo ""
printf "  %-10s  %-12s  %-12s  %-12s  %-12s\n" \
    "Machine" "A LogClear" "B VSSDelete" "C Defender" "D Tools"
echo "  ──────────────────────────────────────────────────────────────────"

total_a=0; total_b=0; total_c=0; total_d=0

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    a=${EVTX_COUNTS_A["${machine}"]:-0}
    b=${EVTX_COUNTS_B["${machine}"]:-0}
    c=${EVTX_COUNTS_C["${machine}"]:-0}
    d=${EXEC_COUNTS_D["${machine}"]:-0}

    total_a=$(( total_a + a ))
    total_b=$(( total_b + b ))
    total_c=$(( total_c + c ))
    total_d=$(( total_d + d ))

    printf "  %-10s  %-12s  %-12s  %-12s  %-12s\n" \
        "${machine}" "${a}" "${b}" "${c}" "${d}"
done

echo "  ──────────────────────────────────────────────────────────────────"
printf "  %-10s  %-12s  %-12s  %-12s  %-12s\n" \
    "TOTAL" "${total_a}" "${total_b}" "${total_c}" "${total_d}"

echo ""

# ── HIGH severity warnings ────────────────────────────────────────────────────
warned=false

if [[ ${total_a} -gt 0 ]]; then
    echo "  [HIGH] Log clearing detected (EventIds 1102/104) — ${total_a} event(s)."
    echo "         Attacker likely cleared Security and/or System logs to destroy evidence."
    warned=true
fi

if [[ ${total_b} -gt 0 ]]; then
    echo "  [HIGH] VSS/Shadow Copy deletion detected — ${total_b} event(s)."
    echo "         Ransomware or targeted attacker destroying backup/restore points."
    warned=true
fi

if [[ ${total_c} -gt 0 ]]; then
    echo "  [HIGH] Defender tampering detected (5001/5010 protection disabled) — ${total_c} event(s)."
    echo "         Real-time protection was disabled or Defender config was modified."
    warned=true
fi

if [[ ${total_d} -gt 0 ]]; then
    echo "  [MEDIUM] Anti-forensic tools found in execution artifacts — ${total_d} hit(s)."
    echo "           Review Section D CSVs for timestamps and full paths."
fi

if ! ${warned} && [[ ${total_d} -eq 0 ]]; then
    echo "  No anti-forensic indicators detected across all machines."
fi

echo ""
echo "════════════════════════════════════════════════════"
echo " Done. Anti-Forensics output:"
find "${ANALYSIS_DIR}" -path "*/AntiForensics/*.csv" 2>/dev/null | sort | awk '{print "  "$0}'
[[ -f "${TIMELINE_OUT}" ]] && echo "  ${TIMELINE_OUT}  (cross-machine timeline)"
echo "════════════════════════════════════════════════════"
