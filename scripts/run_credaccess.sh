#!/usr/bin/env bash
# run_credaccess.sh — Phase 7: Credential Access & Persistence Detection
#
# Sections (A–E work on Phase 3 EvtxECmd CSVs; F works on Phase 1 MFT CSVs):
#   A. DCSync Detection     — 4662 with AD replication GUIDs (DCs only meaningful)
#   B. LSASS/SAM/NTDS Access— 4656/4663 object access + 4688 dump-tool process creation
#   C. Kerberoasting        — 4769 RC4 (0x17/0x18) tickets for non-machine accounts
#   D. AS-REP Roasting      — 4768 pre-auth disabled or 0x17 etype
#   E. WMI Persistence      — 5860/5861 permanent WMI event subscriptions
#   F. Timestomping         — MFT SI<FN flag and uSecZeros (zeroed nanoseconds)
#
# Input  : analysis/<MACHINE>/EventLogs/*_evtx*.csv  (Phase 3)
#          analysis/<MACHINE>/*_MFT.csv              (Phase 1)
# Output : analysis/<MACHINE>/CredAccess/*.csv
#          analysis/credaccess_timeline.csv  (cross-machine, sorted UTC)
# Logging: appends to analysis/commands.txt

set -uo pipefail

CASE_ROOT="/cases/jackofallhacks"
ANALYSIS_DIR="${CASE_ROOT}/analysis"
COMMAND_LOG="${ANALYSIS_DIR}/commands.txt"
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M UTC")
TIMELINE_OUT="${ANALYSIS_DIR}/credaccess_timeline.csv"

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
echo " Credential Access & Persistence — jackofallhacks"
echo " $(date -u)"
echo " Machines: ${#DRIVE_ROOTS[@]}"
echo "════════════════════════════════════════════════════"

# ─── embedded Python analyzer ────────────────────────────────────────────────

PY_SCRIPT=$(mktemp /tmp/credaccess_XXXXXX.py)
trap 'rm -f "${PY_SCRIPT}"' EXIT

cat > "${PY_SCRIPT}" << 'PYEOF'
#!/usr/bin/env python3
"""
credaccess_analyzer.py
  --mode evtx  : Sections A-E over EvtxECmd CSVs
  --mode mft   : Section F timestomping over MFT CSV
"""

import csv, sys, os, re, argparse
from pathlib import Path
from datetime import datetime, timezone

# ── EVTX Section definitions ─────────────────────────────────────────────────

# DCSync: AD replication right GUIDs (any of these in a 4662 = replication abuse)
DCSYNC_GUIDS = {
    "1131f6aa",  # DS-Replication-Get-Changes
    "1131f6ab",  # DS-Replication-Get-Changes-All
    "89e95b76",  # DS-Replication-Get-Changes-In-Filtered-Set
}

# LSASS/credential store object names
CRED_TARGETS = re.compile(
    r'(lsass\.exe|\\SAM\b|ntds\.dit|\\SECURITY\b|\\SYSTEM\b)',
    re.IGNORECASE
)

# Process names used for LSASS/credential dumping (4688 filter)
DUMP_TOOLS = re.compile(
    r'\b(procdump|procdump64|comsvcs|sqldumper|'
    r'nanodump|pypykatz|safetykatz|crackmapexec|secretsdump|'
    r'lsassy|mimikatz|mimilib|kiwi)\b',
    re.IGNORECASE
)
# rundll32 comsvcs.dll MiniDump pattern
COMSVCS_MINIDUMP = re.compile(r'comsvcs.*minidump|minidump.*comsvcs', re.IGNORECASE)
# WerFault invoked by an attacker: WerFault.exe -u -p <pid>
# Legitimate WER is spawned by the OS crash handler — user-initiated = suspicious.
# Technique: WerFault.exe -u -p <lsass_pid> -ip <lsass_pid> -s 65536
# Dump lands at: C:\Users\<user>\AppData\Local\CrashDumps\lsass.exe.<pid>.dmp
WERFAULT_DUMP = re.compile(r'werfault.*-[uU]\b|-[uU].*werfault', re.IGNORECASE)

# RC4/DES Kerberos encryption types (hex and decimal)
RC4_ETYPES = {"0x17", "0x18", "17", "18", "23", "24"}

# Well-known service principal names to exclude from Kerberoasting
BENIGN_SPNS = {"krbtgt", "kadmin/changepw", "kadmin"}

# Executable / script extensions for timestomping focus
EXEC_EXTS = {
    ".exe", ".dll", ".sys", ".com", ".scr", ".cpl",
    ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".hta", ".msi", ".msp", ".msc",
}

# Paths that are noisy with legitimate SI<FN from Windows Update — suppress
# these unless uSecZeros is also set
NOISY_PATHS = re.compile(
    r'\\WinSxS\\|\\Windows\\Installer\\|\\Windows\\servicing\\',
    re.IGNORECASE
)

# ── helpers ───────────────────────────────────────────────────────────────────

def find_col(headers, *candidates):
    hl = {h.strip().lower(): h for h in headers}
    for c in candidates:
        if c.lower() in hl:
            return hl[c.lower()]
    return None

def row_text(row):
    return " ".join(str(v) for v in row.values())

def re_field(pattern, text, default=""):
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1).strip() if m else default

# ── per-event filters ─────────────────────────────────────────────────────────

def keep_dcsync(row, rt):
    # Flag only non-machine accounts performing replication
    uname = re_field(r'SubjectUserName[:\s"=]+([^\s|,\"]+)', rt)
    if uname.endswith("$"):
        return False  # DC computer account — expected
    return any(g in rt.lower() for g in DCSYNC_GUIDS)

def keep_cred_access(eid, row, rt):
    if eid in {4656, 4663}:
        return bool(CRED_TARGETS.search(rt))
    if eid == 4688:
        return (bool(DUMP_TOOLS.search(rt))
                or bool(COMSVCS_MINIDUMP.search(rt))
                or bool(WERFAULT_DUMP.search(rt)))
    return False

def keep_kerberoasting(row, rt):
    # Must have RC4/DES etype
    etype = re_field(
        r'TicketEncryptionType[:\s"=]+(0x[\da-fA-F]+|\d+)', rt
    ).lower()
    if not etype or etype not in RC4_ETYPES:
        return False
    # Exclude machine accounts and well-known benign SPNs
    svc = re_field(r'ServiceName[:\s"=]+([^\s|,\"]+)', rt).lower().rstrip("$")
    if svc in BENIGN_SPNS or svc.endswith("$"):
        return False
    return True

def keep_asrep(row, rt):
    # Pre-auth disabled: PreAuthType = 0
    pa = re_field(r'PreAuthType[:\s"=]+(\d+)', rt)
    if pa == "0":
        return True
    # Also flag RC4 TGT requests from user accounts (possible roasting)
    etype = re_field(
        r'TicketEncryptionType[:\s"=]+(0x[\da-fA-F]+|\d+)', rt
    ).lower()
    return etype in RC4_ETYPES

def keep_wmi(eid, row, rt):
    return eid in {5860, 5861}

# ── section dispatch ─────────────────────────────────────────────────────────

SECTIONS_EVTX = {
    "A_DCSync":       {"ids": {4662},            "label": "DCSync Detection",         "filter": keep_dcsync},
    "B_CredAccess":   {"ids": {4656, 4663, 4688}, "label": "LSASS / SAM / NTDS Access","filter": keep_cred_access},
    "C_Kerberoasting":{"ids": {4769},             "label": "Kerberoasting",            "filter": lambda r,t: keep_kerberoasting(r,t)},
    "D_ASREP":        {"ids": {4768},             "label": "AS-REP Roasting",          "filter": lambda r,t: keep_asrep(r,t)},
    "E_WMI":          {"ids": {5860, 5861},       "label": "WMI Persistence",          "filter": keep_wmi},
}

ALL_EVTX_IDS = set().union(*[s["ids"] for s in SECTIONS_EVTX.values()])

# ── EVTX analysis (Sections A–E) ─────────────────────────────────────────────

def analyze_evtx(evtlog_dir, out_dir, machine, timeline_file):
    in_path  = Path(evtlog_dir)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(in_path.glob("*_evtx*.csv"))
    if not csv_files:
        print(f"  [MISSING   ] No *_evtx*.csv in {evtlog_dir}")
        return {}

    writers  = {}
    handles  = {}
    counts   = {k: 0 for k in SECTIONS_EVTX}
    total    = 0
    timeline = []

    for csv_path in csv_files:
        try:
            with open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    continue
                headers = reader.fieldnames

                eid_col  = find_col(headers, "EventId", "EventID", "Event Id")
                time_col = find_col(headers, "TimeCreated", "Time Created", "Timestamp")
                comp_col = find_col(headers, "Computer", "ComputerName")
                desc_col = find_col(headers, "MapDescription", "Description")
                user_col = find_col(headers, "UserName", "Username")
                host_col = find_col(headers, "RemoteHost", "WorkstationName", "IpAddress")
                chan_col = find_col(headers, "Channel", "LogName")

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

                    for sec_key, sec in SECTIONS_EVTX.items():
                        if eid not in sec["ids"]:
                            continue
                        # filter function takes (eid, row, rt) or (row, rt)
                        try:
                            keep = sec["filter"](eid, row, rt)
                        except TypeError:
                            keep = sec["filter"](row, rt)
                        if not keep:
                            continue

                        if sec_key not in writers:
                            out_file = out_path / f"{machine}_{sec_key}.csv"
                            fout = open(out_file, "w", newline="", encoding="utf-8")
                            w = csv.DictWriter(fout, fieldnames=headers, extrasaction="ignore")
                            w.writeheader()
                            writers[sec_key] = w
                            handles[sec_key] = fout

                        writers[sec_key].writerow(row)
                        counts[sec_key] += 1

                        timeline.append({
                            "TimeCreated":    row.get(time_col, "")  if time_col else "",
                            "Machine":        machine,
                            "Computer":       row.get(comp_col, "")  if comp_col else "",
                            "EventId":        str(eid),
                            "Channel":        row.get(chan_col, "")  if chan_col else "",
                            "Section":        sec["label"],
                            "MapDescription": row.get(desc_col, "")  if desc_col else "",
                            "UserName":       row.get(user_col, "")  if user_col else "",
                            "RemoteHost":     row.get(host_col, "")  if host_col else "",
                        })

        except Exception as e:
            print(f"  [WARN      ] {csv_path.name}: {e}", file=sys.stderr)

    for fh in handles.values():
        fh.close()

    if timeline and timeline_file:
        tl_path   = Path(timeline_file)
        tl_exists = tl_path.exists() and tl_path.stat().st_size > 10
        TL_FIELDS = ["TimeCreated","Machine","Computer","EventId","Channel",
                     "Section","MapDescription","UserName","RemoteHost"]
        with open(tl_path, "a", newline="", encoding="utf-8") as tf:
            w = csv.DictWriter(tf, fieldnames=TL_FIELDS)
            if not tl_exists:
                w.writeheader()
            w.writerows(timeline)

    print(f"  Events scanned : {total}")
    for sec_key, sec in SECTIONS_EVTX.items():
        n = counts[sec_key]
        star = " *" if n > 0 else ""
        print(f"    {sec_key} — {sec['label']:<35s}: {n}{star}")

    audit_notes = {
        "A_DCSync":        "requires 'Audit Directory Service Access' on DCs",
        "B_CredAccess":    "4656/4663 require 'Audit Object Access'; 4688 requires process creation auditing",
        "C_Kerberoasting": "requires 'Audit Kerberos Service Ticket Operations'",
        "D_ASREP":         "requires 'Audit Kerberos Authentication Service'",
        "E_WMI":           "requires WMI-Activity/Operational log enabled",
    }
    zero_secs = [k for k, v in counts.items() if v == 0]
    if zero_secs:
        print("  [NOTE] Zero matches in some sections — audit policy may not capture these.")
        for k in zero_secs:
            if k in audit_notes:
                print(f"         {k}: {audit_notes[k]}")

    return counts

# ── MFT analysis — Section F (Timestomping) + Section G (Crash Dumps) ────────
# Single-pass over the MFT CSV to avoid re-reading multi-million-row files.

TIMESTOMP_COLS = [
    "EntryNumber", "ParentPath", "FileName", "Extension", "FileSize",
    "SI<FN", "uSecZeros", "Copied",
    "Created0x10", "Created0x30",
    "LastModified0x10", "LastModified0x30",
    "LastRecordChange0x10", "LastRecordChange0x30",
]

DUMP_FILE_EXTS = {".dmp", ".mdmp"}

# Attacker-controlled writable paths where a dump would be placed.
# Use (?:\\|$) for Temp/tmp so paths without a trailing backslash still match
# (MFTECmd omits the trailing separator on leaf directories).
WRITABLE_PATHS = re.compile(
    r'\\AppData\\|\\Temp(?:\\|$)|\\tmp(?:\\|$)|\\Users\\Public\\'
    r'|\\ProgramData\\(?!Microsoft\\Windows\\WER\\Report)',
    re.IGNORECASE
)
# Paths that generate legitimate .dmp files — only flag if lsass named
SYSTEM_DUMP_PATHS = re.compile(
    r'\\Windows\\(?:System32|SysWOW64|Minidump|LiveKernelReports)(?:\\|$)',
    re.IGNORECASE
)
# WER report sidecar files alongside a crash dump
WER_REPORT_PATH = re.compile(r'\\WER\\Report(?:Queue|Archive)', re.IGNORECASE)
LSASS_RE        = re.compile(r'lsass', re.IGNORECASE)

DUMP_OUT_COLS = [
    "EntryNumber", "ParentPath", "FileName", "Extension", "FileSize",
    "Created0x10", "LastModified0x10", "LastAccess0x10",
    "uSecZeros", "SI<FN", "Severity", "Reason",
]

def analyze_mft(mft_csv, out_dir, machine):
    """Single MFT pass: Section F (Timestomping) + Section G (Crash Dump artifacts)."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    ts_file   = out_path / f"{machine}_F_Timestomping.csv"
    dump_file = out_path / f"{machine}_G_CrashDumps.csv"

    ts_hits   = []
    dump_hits = []
    total = sifn = uzero = 0

    try:
        with open(mft_csv, encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                print("  [ERROR     ] MFT CSV has no headers")
                return

            headers = reader.fieldnames
            sifn_col    = find_col(headers, "SI<FN")
            uzero_col   = find_col(headers, "uSecZeros", "uSecZero")
            ext_col     = find_col(headers, "Extension")
            path_col    = find_col(headers, "ParentPath")
            name_col    = find_col(headers, "FileName")
            resident_col= find_col(headers, "ResidentDataASCII")

            if not sifn_col or not uzero_col:
                print("  [WARN      ] SI<FN or uSecZeros column not found in MFT CSV")
                return

            ts_cols   = [c for c in TIMESTOMP_COLS if find_col(headers, c)]
            dump_cols = [c for c in DUMP_OUT_COLS
                         if c not in ("Severity","Reason") and find_col(headers, c)]
            dump_cols += ["Severity", "Reason"]

            for row in reader:
                total += 1
                ext  = row.get(ext_col,  "").strip().lower() if ext_col  else ""
                path = row.get(path_col, "").strip()          if path_col else ""
                name = row.get(name_col, "").strip()          if name_col else ""

                # ── Section F: Timestomping ───────────────────────────────────
                si_flag = row.get(sifn_col,  "").strip().lower()
                uz_flag = row.get(uzero_col, "").strip().lower()
                is_sifn  = si_flag in {"true", "1", "yes"}
                is_uzero = uz_flag in {"true", "1", "yes"}

                if is_sifn or is_uzero:
                    keep = True
                    if is_sifn and not is_uzero:
                        if NOISY_PATHS.search(path):
                            keep = False
                        elif ext not in EXEC_EXTS:
                            keep = False
                    if keep:
                        ts_row = {c: row.get(find_col(headers, c), "") for c in ts_cols}
                        ts_hits.append(ts_row)
                        if is_sifn:  sifn  += 1
                        if is_uzero: uzero += 1

                # ── Section G: Crash Dump Artifacts ──────────────────────────
                if ext in DUMP_FILE_EXTS or ext == ".wer":
                    severity = None
                    reasons  = []
                    resident = row.get(resident_col, "") if resident_col else ""

                    if LSASS_RE.search(name) or LSASS_RE.search(path):
                        severity = "HIGH"
                        reasons.append("lsass in filename/path")
                    elif ext == ".wer":
                        if LSASS_RE.search(resident):
                            severity = "HIGH"
                            reasons.append("lsass referenced in WER report content")
                        elif WER_REPORT_PATH.search(path):
                            severity = "LOW"
                            reasons.append("WER report sidecar")
                        # .wer outside WER paths — ignore (unlikely)
                    elif ext in DUMP_FILE_EXTS:
                        if WRITABLE_PATHS.search(path) and not SYSTEM_DUMP_PATHS.search(path):
                            severity = "MEDIUM"
                            reasons.append("dump in user-writable path (WerFault/comsvcs/procdump output)")
                        elif not SYSTEM_DUMP_PATHS.search(path):
                            severity = "LOW"
                            reasons.append("dump outside standard Windows crash dump directories")
                        # .dmp inside System32/Minidump = normal kernel crash dumps — skip

                    if severity:
                        d_row = {c: row.get(find_col(headers, c), "")
                                 for c in dump_cols if c not in ("Severity","Reason")}
                        d_row["Severity"] = severity
                        d_row["Reason"]   = "; ".join(reasons)
                        dump_hits.append(d_row)

    except Exception as e:
        print(f"  [ERROR     ] MFT analysis failed: {e}", file=sys.stderr)
        return

    # ── Write Section F output ────────────────────────────────────────────────
    if ts_hits:
        with open(ts_file, "w", newline="", encoding="utf-8") as fo:
            w = csv.DictWriter(fo, fieldnames=ts_cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(ts_hits)

    # ── Write Section G output ────────────────────────────────────────────────
    if dump_hits:
        with open(dump_file, "w", newline="", encoding="utf-8") as fo:
            w = csv.DictWriter(fo, fieldnames=dump_cols)
            w.writeheader()
            w.writerows(dump_hits)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"  MFT entries scanned : {total}")
    print(f"    F_Timestomping — SI<FN (exec/script)      : {sifn}"  + (" *" if sifn  else ""))
    print(f"    F_Timestomping — uSecZeros (zeroed ns)    : {uzero}" + (" *" if uzero else ""))
    if uzero:
        print("    [HIGH] uSecZeros = timestomping tool (Metasploit/Cobalt Strike/timestomp.exe)")

    high = sum(1 for d in dump_hits if d["Severity"] == "HIGH")
    med  = sum(1 for d in dump_hits if d["Severity"] == "MEDIUM")
    low  = sum(1 for d in dump_hits if d["Severity"] == "LOW")
    print(f"    G_CrashDumps  — HIGH   (lsass dump)       : {high}" + (" *" if high else ""))
    print(f"    G_CrashDumps  — MEDIUM (user-path dump)   : {med}"  + (" *" if med  else ""))
    print(f"    G_CrashDumps  — LOW    (other .dmp/.wer)  : {low}")
    if high:
        print("    [HIGH] lsass dump file on disk — WerFault/comsvcs/procdump technique confirmed")

# ── main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode",         required=True, choices=["evtx", "mft"])
    ap.add_argument("--evtlog-dir",   default="")
    ap.add_argument("--mft-csv",      default="")
    ap.add_argument("--output-dir",   required=True)
    ap.add_argument("--machine",      required=True)
    ap.add_argument("--timeline-out", default="")
    args = ap.parse_args()

    if args.mode == "evtx":
        if not args.evtlog_dir:
            print("--evtlog-dir required for evtx mode"); sys.exit(1)
        analyze_evtx(args.evtlog_dir, args.output_dir, args.machine, args.timeline_out)
    else:
        if not args.mft_csv:
            print("--mft-csv required for mft mode"); sys.exit(1)
        analyze_mft(args.mft_csv, args.output_dir, args.machine)

if __name__ == "__main__":
    main()
PYEOF

# ─── main machine loop ───────────────────────────────────────────────────────

section "A–E. Credential Access (EvtxECmd CSVs per machine)"

for drive_root in "${DRIVE_ROOTS[@]}"; do
    machine=$(echo "${drive_root}" | grep -oP '[^/]+(?=_Kape)')
    evtlog_dir="${ANALYSIS_DIR}/${machine}/EventLogs"
    out_dir="${ANALYSIS_DIR}/${machine}/CredAccess"

    machine_header "${machine}"

    if ! csv_has_data "${evtlog_dir}" "*_evtx*.csv"; then
        status "SKIP" "No EventLog CSVs — run Phase 3 first"
        continue
    fi

    if csv_has_data "${out_dir}" "*_[ABCDE]_*.csv"; then
        status "SKIP" "EvtxECmd hunting CSVs already exist"
    else
        mkdir -p "${out_dir}"
        cmd="python3 ${PY_SCRIPT} --mode evtx --evtlog-dir '${evtlog_dir}' --output-dir '${out_dir}' --machine '${machine}' --timeline-out '${TIMELINE_OUT}'"
        tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
        echo "${tool_out}" | sed 's/^/  /'
        if [[ ${rc} -ne 0 ]]; then
            status "ERROR" "Analyzer exited ${rc}"; continue
        fi
        evtx_csvs=$(find "${out_dir}" -maxdepth 1 -name "*_[ABCDE]_*.csv" 2>/dev/null | wc -l)
        status "OK" "${evtx_csvs} section CSV(s) written"
        log_cmd "${machine}" "credaccess_analyzer.py evtx (Phase 7 A–E)" \
            "${cmd}" \
            "Credential access hunting: DCSync (4662 replication GUIDs), LSASS/SAM/NTDS access (4656/4663/4688), Kerberoasting (4769 RC4), AS-REP (4768 pre-auth=0), WMI persistence (5861)" \
            "${out_dir}/*_[ABCDE]_*.csv" \
            "${evtx_csvs} section CSVs"
    fi

    # Sections F+G — MFT analysis (timestomping + crash dump artifacts, single pass)
    mft_csv=$(find "${ANALYSIS_DIR}/${machine}" -maxdepth 1 -name "*_MFT.csv" 2>/dev/null | head -1)

    if [[ -z "${mft_csv}" ]]; then
        status "SKIP" "No MFT CSV for F/G — run Phase 1 first"
    elif [[ -f "${out_dir}/${machine}_F_Timestomping.csv" ]] || \
         [[ -f "${out_dir}/${machine}_G_CrashDumps.csv" ]]; then
        status "SKIP" "MFT section CSVs already exist (F/G)"
    else
        mkdir -p "${out_dir}"
        cmd="python3 ${PY_SCRIPT} --mode mft --mft-csv '${mft_csv}' --output-dir '${out_dir}' --machine '${machine}'"
        tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
        echo "${tool_out}" | sed 's/^/  /'
        if [[ ${rc} -ne 0 ]]; then
            status "ERROR" "MFT analyzer exited ${rc}"; continue
        fi
        ts_rows=0; dump_rows=0
        [[ -f "${out_dir}/${machine}_F_Timestomping.csv" ]] && \
            ts_rows=$(( $(wc -l < "${out_dir}/${machine}_F_Timestomping.csv") - 1 ))
        [[ -f "${out_dir}/${machine}_G_CrashDumps.csv" ]] && \
            dump_rows=$(( $(wc -l < "${out_dir}/${machine}_G_CrashDumps.csv") - 1 ))
        status "OK" "F: ${ts_rows} timestomped | G: ${dump_rows} crash dump artifacts"
        log_cmd "${machine}" "credaccess_analyzer.py mft (Phase 7 F+G)" \
            "${cmd}" \
            "F: Timestomping — MFT SI<FN (backdated SI timestamp) and uSecZeros (zeroed nanoseconds). G: Crash dump artifacts — .dmp/.mdmp/.wer files; HIGH=lsass dump (WerFault -u -p / comsvcs MiniDump), MEDIUM=dump in user-writable path" \
            "${out_dir}/${machine}_F_Timestomping.csv + ${machine}_G_CrashDumps.csv" \
            "F: ${ts_rows} entries | G: ${dump_rows} entries"
    fi
done

# ─── sort cross-machine timeline ─────────────────────────────────────────────

section "Timeline — Cross-machine Credential Access Events"

if [[ -f "${TIMELINE_OUT}" ]] && [[ $(wc -l < "${TIMELINE_OUT}") -gt 1 ]]; then
    TMP_TL=$(mktemp /tmp/credaccess_tl_XXXXXX.csv)
    head -1    "${TIMELINE_OUT}" >  "${TMP_TL}"
    tail -n +2 "${TIMELINE_OUT}" | sort -t',' -k1,1 >> "${TMP_TL}"
    mv "${TMP_TL}" "${TIMELINE_OUT}"

    total_rows=$(( $(wc -l < "${TIMELINE_OUT}") - 1 ))
    echo "  File : ${TIMELINE_OUT}"
    echo "  Rows : ${total_rows} events across all machines (sorted UTC)"
    echo ""
    printf "  %-38s  %s\n" "Section" "Events"
    echo "  ────────────────────────────────────────────────────────"
    for label in "DCSync Detection" "LSASS / SAM / NTDS Access" \
                 "Kerberoasting" "AS-REP Roasting" "WMI Persistence"; do
        count=$(grep -c "${label}" "${TIMELINE_OUT}" 2>/dev/null || echo 0)
        printf "  %-38s  %s\n" "${label}" "${count}"
    done
else
    echo "  No timeline events — Phase 3 must complete before Sections A–E can run."
fi

echo ""
echo "════════════════════════════════════════════════════"
echo " Done. CredAccess output:"
find "${ANALYSIS_DIR}" -path "*/CredAccess/*.csv" 2>/dev/null | sort | awk '{print "  "$0}'
[[ -f "${TIMELINE_OUT}" ]] && echo "  ${TIMELINE_OUT}  (cross-machine timeline)"
echo "════════════════════════════════════════════════════"
