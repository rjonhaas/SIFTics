#!/usr/bin/env bash
# run_hunting.sh — Phase 6: Privilege escalation & lateral movement hunting
# over pre-parsed EvtxECmd CSVs (requires Phase 3 output).
#
# Sections:
#   A. Privilege Escalation — 4672/4673 sensitive privs, 4697 new service,
#                             4698/4702 task create/modify,
#                             4720/4722/4724/4728/4732/4756/4738/4741 account mgmt
#   B. Lateral Movement     — 4624 LogonType 3 (network) & 10 (RemoteInteractive),
#                             4648 explicit credentials, 4776 NTLM auth
#   C. Kerberos Anomalies   — 4768/4769 (all TGT/TGS — analyst filters by etype),
#                             4771 pre-auth failures
#   D. Remote Execution     — 7045 new service install, 4688 process creation
#                             (4688 filtered to suspicious executables only)
#   E. RDP Sessions         — 1149 auth, 21/22/24/25 connect/disconnect
#   F. Cross-machine Timeline — all flagged events merged and sorted by UTC time
#
# Input  : analysis/<MACHINE>/EventLogs/*_evtx*.csv  (Phase 3 output)
# Output : analysis/<MACHINE>/Hunting/<MACHINE>_<Section>.csv
#          analysis/hunting_timeline.csv  (cross-machine, sorted)
# Logging: appends to analysis/commands.txt

set -uo pipefail

CASE_ROOT="/cases/jackofallhacks"
ANALYSIS_DIR="${CASE_ROOT}/analysis"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")
TIMELINE_OUT="${ANALYSIS_DIR}/hunting_timeline.csv"

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
echo " Hunting — Priv Esc & Lateral Movement"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ─── embedded Python analyzer ────────────────────────────────────────────────

PY_SCRIPT=$(mktemp /tmp/hunt_analyzer_XXXXXX.py)
trap 'rm -f "${PY_SCRIPT}"' EXIT

cat > "${PY_SCRIPT}" << 'PYEOF'
#!/usr/bin/env python3
"""
hunt_analyzer.py — Filter EvtxECmd CSVs into hunting sections per machine.
Called once per machine by run_hunting.sh.
"""

import csv, sys, os, re, argparse
from pathlib import Path

# ── Section definitions ──────────────────────────────────────────────────────
SECTIONS = {
    "A_PrivEsc": {
        "ids": {4672, 4673, 4674, 4697, 4698, 4702,
                4720, 4722, 4724, 4728, 4732, 4756, 4738, 4741},
        "label": "Privilege Escalation",
    },
    "B_LateralMovement": {
        "ids": {4624, 4648, 4776},
        "label": "Lateral Movement",
    },
    "C_Kerberos": {
        "ids": {4768, 4769, 4771},
        "label": "Kerberos Anomalies",
    },
    "D_RemoteExec": {
        "ids": {7045, 4688},
        "label": "Remote Execution",
    },
    "E_RDP": {
        "ids": {1149, 21, 22, 24, 25},
        "label": "RDP Sessions",
    },
}

ALL_IDS = set().union(*[s["ids"] for s in SECTIONS.values()])

# LogonTypes worth keeping for lateral movement noise reduction
INTERESTING_LOGON_TYPES = {"3", "10"}

# Suspicious executables for 4688 process creation filtering
SUSPICIOUS_EXES = re.compile(
    r'\b(powershell|pwsh|cmd\.exe|certutil|wscript|mshta|rundll32|'
    r'regsvr32|cscript|msiexec|wmic|psexec|psexesvc|mimikatz|'
    r'net\.exe|net1\.exe|nltest|whoami|procdump|lsass|'
    r'bitsadmin|odbcconf|regasm|regsvcs|installutil|'
    r'msbuild|cmstp|xwizard)\b',
    re.IGNORECASE
)

def find_col(headers, *candidates):
    """Return the first column name that matches any candidate (case-insensitive)."""
    hl = {h.strip().lower(): h for h in headers}
    for c in candidates:
        if c.lower() in hl:
            return hl[c.lower()]
    return None

def row_text(row):
    return " ".join(str(v) for v in row.values())

def get_logon_type(row, rtext):
    """Extract LogonType value from ExtraDataList or full row text."""
    for col, val in row.items():
        if "extradatalist" in col.lower() or "extra" in col.lower():
            m = re.search(r'LogonType[:\s]+(\d+)', val, re.IGNORECASE)
            if m:
                return m.group(1)
    m = re.search(r'LogonType["\s:=]+(\d+)', rtext, re.IGNORECASE)
    return m.group(1) if m else None

def keep_row(section_key, eid, row, rtext):
    """Additional per-section filters beyond EventId match."""
    if section_key == "B_LateralMovement" and eid == 4624:
        lt = get_logon_type(row, rtext)
        # Keep if type is interesting OR if we can't extract the type
        return lt is None or lt in INTERESTING_LOGON_TYPES
    if section_key == "D_RemoteExec" and eid == 4688:
        # 4688 is very noisy — only keep suspicious process launches
        return bool(SUSPICIOUS_EXES.search(rtext))
    return True

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir",    required=True)
    ap.add_argument("--output-dir",   required=True)
    ap.add_argument("--machine",      required=True)
    ap.add_argument("--timeline-out", default="")
    args = ap.parse_args()

    in_path  = Path(args.input_dir)
    out_path = Path(args.output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(in_path.glob("*_evtx*.csv"))
    if not csv_files:
        print(f"  [MISSING   ] No *_evtx*.csv in {args.input_dir}")
        sys.exit(1)

    # Per-section state
    writers  = {}   # section_key -> csv.DictWriter
    handles  = {}   # section_key -> file handle
    counts   = {k: 0 for k in SECTIONS}
    total    = 0
    timeline = []

    for csv_path in csv_files:
        try:
            with open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    continue
                headers = reader.fieldnames

                eid_col  = find_col(headers, "EventId",      "EventID",   "Event Id",  "Event ID")
                time_col = find_col(headers, "TimeCreated",  "Time Created", "Timestamp")
                comp_col = find_col(headers, "Computer",     "ComputerName")
                desc_col = find_col(headers, "MapDescription","Description","MapDesc")
                user_col = find_col(headers, "UserName",     "User Name",  "Username")
                host_col = find_col(headers, "RemoteHost",   "Remote Host","IpAddress","WorkstationName")
                chan_col = find_col(headers, "Channel",      "LogName")

                if not eid_col:
                    continue

                for row in reader:
                    total += 1
                    try:
                        eid = int(row[eid_col].strip())
                    except (ValueError, KeyError):
                        continue

                    if eid not in ALL_IDS:
                        continue

                    rt = row_text(row)

                    for sec_key, sec_def in SECTIONS.items():
                        if eid not in sec_def["ids"]:
                            continue
                        if not keep_row(sec_key, eid, row, rt):
                            continue

                        # Lazy-open output CSV for this section
                        if sec_key not in writers:
                            out_file = out_path / f"{args.machine}_{sec_key}.csv"
                            fout = open(out_file, "w", newline="", encoding="utf-8")
                            w = csv.DictWriter(fout, fieldnames=headers, extrasaction="ignore")
                            w.writeheader()
                            writers[sec_key] = w
                            handles[sec_key] = fout

                        writers[sec_key].writerow(row)
                        counts[sec_key] += 1

                        timeline.append({
                            "TimeCreated":    row.get(time_col, "")   if time_col else "",
                            "Machine":        args.machine,
                            "Computer":       row.get(comp_col, "")   if comp_col else "",
                            "EventId":        str(eid),
                            "Channel":        row.get(chan_col, "")   if chan_col else "",
                            "Section":        sec_def["label"],
                            "MapDescription": row.get(desc_col, "")   if desc_col else "",
                            "UserName":       row.get(user_col, "")   if user_col else "",
                            "RemoteHost":     row.get(host_col, "")   if host_col else "",
                        })

        except Exception as e:
            print(f"  [WARN      ] {csv_path.name}: {e}", file=sys.stderr)

    for fh in handles.values():
        fh.close()

    # Append to global timeline
    if timeline and args.timeline_out:
        tl_path   = Path(args.timeline_out)
        tl_exists = tl_path.exists() and tl_path.stat().st_size > 10
        with open(tl_path, "a", newline="", encoding="utf-8") as tf:
            TL_FIELDS = ["TimeCreated","Machine","Computer","EventId","Channel",
                         "Section","MapDescription","UserName","RemoteHost"]
            w = csv.DictWriter(tf, fieldnames=TL_FIELDS)
            if not tl_exists:
                w.writeheader()
            w.writerows(timeline)

    # Summary output
    print(f"  Events scanned : {total}")
    for sec_key, sec_def in SECTIONS.items():
        n = counts[sec_key]
        star = " *" if n > 0 else ""
        print(f"    {sec_key} — {sec_def['label']:<30s}: {n}{star}")

    if not any(counts.values()):
        print("  [NOTE] Zero matches — event log audit policy may not capture these events,")
        print("         or Phase 3 evtx parse needs to complete first.")

if __name__ == "__main__":
    main()
PYEOF

# ─── per-machine analysis loop ───────────────────────────────────────────────

section "A–E. Hunting per machine (PrivEsc / Lateral / Kerberos / RemoteExec / RDP)"

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    evtlog_dir="${ANALYSIS_DIR}/${machine}/EventLogs"
    out_dir="${ANALYSIS_DIR}/${machine}/Hunting"

    machine_header "${machine}"

    if ! csv_has_data "${evtlog_dir}" "*_evtx*.csv"; then
        status "SKIP" "No EventLog CSVs — run Phase 3 (run_eventlogs.sh) first"
        continue
    fi

    if csv_has_data "${out_dir}" "*.csv"; then
        status "SKIP" "Hunting CSVs already exist"
        continue
    fi

    mkdir -p "${out_dir}"
    cmd="python3 ${PY_SCRIPT} --input-dir '${evtlog_dir}' --output-dir '${out_dir}' --machine '${machine}' --timeline-out '${TIMELINE_OUT}'"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    echo "${tool_out}" | sed 's/^/  /'

    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "Analyzer exited ${rc}"
        continue
    fi

    csv_count=$(find "${out_dir}" -maxdepth 1 -name "*.csv" 2>/dev/null | wc -l)
    status "OK" "${csv_count} section CSV(s) → ${out_dir}"

    log_cmd "${machine}" "hunt_analyzer.py (Phase 6 — Priv Esc / Lateral Movement)" \
        "${cmd}" \
        "Filter EvtxECmd CSVs for: priv esc (4672/4673/4697/4698/4720+), lateral movement (4624 T3/T10, 4648, 4776), Kerberos anomalies (4768/4769/4771), remote execution (7045/4688), RDP (1149/21-25)" \
        "${out_dir}/*.csv" \
        "${csv_count} section CSVs written"
done

# ─── Section F: sort cross-machine timeline ──────────────────────────────────

section "F. Cross-machine Timeline"

if [[ -f "${TIMELINE_OUT}" ]] && [[ $(wc -l < "${TIMELINE_OUT}") -gt 1 ]]; then
    TMP_TL=$(mktemp /tmp/hunt_timeline_XXXXXX.csv)
    head -1  "${TIMELINE_OUT}" >  "${TMP_TL}"
    tail -n +2 "${TIMELINE_OUT}" | sort -t',' -k1,1 >> "${TMP_TL}"
    mv "${TMP_TL}" "${TIMELINE_OUT}"

    total_rows=$(( $(wc -l < "${TIMELINE_OUT}") - 1 ))
    echo "  File : ${TIMELINE_OUT}"
    echo "  Rows : ${total_rows} events across all machines (sorted UTC)"
    echo ""
    printf "  %-32s  %s\n" "Section" "Events"
    echo "  ────────────────────────────────────────────────────"
    for label in "Privilege Escalation" "Lateral Movement" "Kerberos Anomalies" \
                 "Remote Execution" "RDP Sessions"; do
        count=$(grep -c "${label}" "${TIMELINE_OUT}" 2>/dev/null || echo 0)
        printf "  %-32s  %s\n" "${label}" "${count}"
    done
else
    echo "  No timeline events — Phase 3 must complete before Phase 6 can run."
fi

echo ""
echo "════════════════════════════════════════════════════"
echo " Done. Hunting output:"
find "${ANALYSIS_DIR}" -path "*/Hunting/*.csv" 2>/dev/null | sort | awk '{print "  "$0}'
[[ -f "${TIMELINE_OUT}" ]] && echo "  ${TIMELINE_OUT}  (cross-machine timeline)"
echo "════════════════════════════════════════════════════"
