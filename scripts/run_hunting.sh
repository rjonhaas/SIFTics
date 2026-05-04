#!/usr/bin/env bash
# DAEDALUS:HANDLES win_evtx win_registry
# DAEDALUS:DOMAIN windows_hunting
# run_hunting.sh — Phase 6: Privilege escalation & lateral movement hunting
# over pre-parsed EvtxECmd CSVs (requires Phase 3 output).
#
# Sections:
#   A. Privilege Escalation    — 4672/4673 sensitive privs, 4697 new service,
#                                4698/4702 task create/modify,
#                                4720/4722/4724/4728/4732/4756/4738/4741 account mgmt
#   B. Lateral Movement        — 4624 LogonType 3 (network) & 10 (RemoteInteractive),
#                                4648 explicit credentials, 4776 NTLM auth
#   C. Kerberos Anomalies      — 4768/4769 (all TGT/TGS — analyst filters by etype),
#                                4771 pre-auth failures
#   D. Remote Execution        — 7045 new service install, 4688 process creation
#                                (4688 filtered to suspicious executables only)
#   E. RDP Sessions            — 1149 auth, 21/22/24/25 connect/disconnect
#   F. Cross-machine Timeline  — all flagged events merged and sorted by UTC time
#   G. Renamed Executables     — Sysmon EID 1: OriginalFileName ≠ Image basename
#                                (searches all EventLog CSVs incl. *_Sysmon.csv)
#   H. Unquoted Service Path   — Services with unquoted paths + MFT cross-ref for
#                                executables placed at Windows path-resolution candidates
#   I. Service Binary Hijack   — Sysmon EID 1 where services.exe spawns a binary
#                                outside standard Windows paths (unquoted svc exploit)
#
# Input  : analysis/<MACHINE>/EventLogs/*_evtx*.csv + *_Sysmon.csv  (Phase 3 output)
#          analysis/<MACHINE>/Registry/System/*/<MACHINE>_*_Services  (EZ Tools)
#          analysis/<MACHINE>/<MACHINE>_*_MFT.csv                     (Phase 3 MFT)
# Output : analysis/<MACHINE>/Hunting/<MACHINE>_<Section>.csv
#          analysis/hunting_timeline.csv  (cross-machine, sorted)
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

# ── Section G constants ───────────────────────────────────────────────────────

# PE OriginalFileName values for known LOLBins — high priority when renamed
LOLBIN_ORIGINALS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe", "makecab.exe",
    "expand.exe", "extrac32.exe", "msiexec.exe", "regsvr32.exe", "rundll32.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msbuild.exe", "cmstp.exe", "schtasks.exe",
    "wmic.exe", "ntdsutil.exe", "vssadmin.exe", "net.exe", "nltest.exe",
    "procdump.exe", "dumpit.exe", "winpmem.exe",
}

# (original_lower, image_basename_lower) pairs known to mismatch benignly
RENAMED_NOISE_PAIRS = {
    ("tsthemes.exe",        "tstheme.exe"),
    ("cleanmgr.dll",        "cleanmgr.exe"),
    ("wlrmndr.exe",         "wlrmdr.exe"),
    ("usoclient",           "usoclient.exe"),
    ("fzsftp",              "fzsftp.exe"),
    ("googleupdate.exe",    "googlecrashhandler.exe"),
    ("googleupdate.exe",    "googlecrashhandler64.exe"),
    ("apphostnameregistrationverifier.exe", "apphostregistrationverifier.exe"),
    ("desktop-launcher.exe","firefox.exe"),
}

SUSPICIOUS_PATH_RE = re.compile(
    r'(\\Users\\|\\ProgramData\\|\\Windows\\Temp\\|\\Temp\\|\\AppData\\|'
    r'ADMIN\$|\\public\\|\\downloads\\|\\desktop\\)',
    re.IGNORECASE
)

INSTALLER_PATH_RE = re.compile(
    r'(\\Update\\Install\\|mini_installer|_setup\b|_installer\b|chrome_installer)',
    re.IGNORECASE
)

# ── Section I constants ───────────────────────────────────────────────────────

# Paths that are normal for services.exe to launch from — filter these out in I
STANDARD_SVC_PATHS_RE = re.compile(
    r'(?i)\\(Windows\\System32|Windows\\SysWOW64|Windows\\servicing|'
    r'Program\ Files|Program\ Files\ \(x86\)|Windows\\WinSxS|'
    r'Windows\\Microsoft\.NET)',
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

def get_logon_type(row, rtext):
    for col, val in row.items():
        if "extradatalist" in col.lower() or "extra" in col.lower():
            m = re.search(r'LogonType[:\s]+(\d+)', val, re.IGNORECASE)
            if m:
                return m.group(1)
    m = re.search(r'LogonType["\s:=]+(\d+)', rtext, re.IGNORECASE)
    return m.group(1) if m else None

def keep_row(section_key, eid, row, rtext):
    if section_key == "B_LateralMovement" and eid == 4624:
        lt = get_logon_type(row, rtext)
        return lt is None or lt in INTERESTING_LOGON_TYPES
    if section_key == "D_RemoteExec" and eid == 4688:
        return bool(SUSPICIOUS_EXES.search(rtext))
    return True

# ── Section G — renamed executable detection ──────────────────────────────────

def check_renamed_exes(in_path, out_path, machine):
    """
    Scan ALL CSVs in in_path (incl. *_Sysmon.csv) for Sysmon EID 1 events
    where PE-header OriginalFileName differs from the on-disk Image basename.
    """
    G_FIELDS = [
        "TimeCreated", "Machine", "UserName",
        "Image", "OriginalFileName", "CommandLine",
        "ParentImage", "ParentCommandLine",
        "SuspiciousPath", "LOLBin", "MD5", "SHA256",
    ]
    hits = []

    for csv_path in sorted(in_path.glob("*.csv")):
        try:
            with open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    continue
                headers  = reader.fieldnames
                eid_col  = find_col(headers, "EventId",     "EventID",   "Event Id")
                time_col = find_col(headers, "TimeCreated", "Time Created")
                user_col = find_col(headers, "UserName",    "User Name")
                pay_col  = find_col(headers, "Payload")
                if not (eid_col and pay_col):
                    continue

                for row in reader:
                    try:
                        eid = int(row[eid_col].strip())
                    except (ValueError, KeyError):
                        continue
                    if eid != 1:
                        continue

                    payload = row.get(pay_col, "")

                    img_m    = re.search(r'"@Name"\s*:\s*"Image"\s*,\s*"#text"\s*:\s*"([^"]+)"', payload)
                    orig_m   = re.search(r'"@Name"\s*:\s*"OriginalFileName"\s*,\s*"#text"\s*:\s*"([^"]+)"', payload)
                    cmd_m    = re.search(r'"@Name"\s*:\s*"CommandLine"\s*,\s*"#text"\s*:\s*"([^"]+)"', payload)
                    par_m    = re.search(r'"@Name"\s*:\s*"ParentImage"\s*,\s*"#text"\s*:\s*"([^"]+)"', payload)
                    pcmd_m   = re.search(r'"@Name"\s*:\s*"ParentCommandLine"\s*,\s*"#text"\s*:\s*"([^"]+)"', payload)
                    md5_m    = re.search(r'MD5=([A-Fa-f0-9]{32})', payload)
                    sha256_m = re.search(r'SHA256=([A-Fa-f0-9]{64})', payload)

                    if not (img_m and orig_m):
                        continue

                    image    = img_m.group(1)
                    original = orig_m.group(1).strip()

                    if original in ("-", ""):
                        continue

                    img_base  = re.split(r'\\\\|[/\\]', image)[-1].lower()
                    orig_base = original.lower()

                    if img_base == orig_base:
                        continue
                    if (orig_base, img_base) in RENAMED_NOISE_PAIRS:
                        continue
                    if INSTALLER_PATH_RE.search(image):
                        continue

                    hits.append({
                        "TimeCreated":       row.get(time_col, "") if time_col else "",
                        "Machine":           machine,
                        "UserName":          row.get(user_col, "") if user_col else "",
                        "Image":             image,
                        "OriginalFileName":  original,
                        "CommandLine":       cmd_m.group(1)[:300]  if cmd_m  else "",
                        "ParentImage":       par_m.group(1)        if par_m  else "",
                        "ParentCommandLine": pcmd_m.group(1)[:200] if pcmd_m else "",
                        "SuspiciousPath":    str(bool(SUSPICIOUS_PATH_RE.search(image))),
                        "LOLBin":            str(orig_base in LOLBIN_ORIGINALS),
                        "MD5":               md5_m.group(1)    if md5_m    else "",
                        "SHA256":            sha256_m.group(1) if sha256_m else "",
                    })

        except Exception as e:
            print(f"  [WARN      ] {csv_path.name} (G): {e}", file=sys.stderr)

    if hits:
        out_file = out_path / f"{machine}_G_RenamedExe.csv"
        with open(out_file, "w", newline="", encoding="utf-8") as fout:
            w = csv.DictWriter(fout, fieldnames=G_FIELDS)
            w.writeheader()
            w.writerows(hits)

    return len(hits)


# ── Section H — unquoted service path + binary placement ─────────────────────

def check_unquoted_svc_paths(registry_dir, mft_dir, out_path, machine):
    """
    Find services with unquoted binary paths containing spaces, then cross-reference
    MFT for executables placed at Windows path-resolution candidate locations.
    Attacker pattern: place malicious.exe at C:\\Some Dir\\malicious.exe to hijack
    C:\\Some Dir\\legitimate service.exe when the service restarts.
    """
    H_FIELDS = [
        "Machine", "ServiceName", "DisplayName", "StartType", "Account",
        "RegisteredPath", "CandidatePath", "MFTCreated", "MFTModified", "FileSizeBytes",
    ]

    if not registry_dir or not mft_dir:
        return 0

    # ── Step 1: find services with unquoted paths containing spaces ──
    unquoted = []
    reg_path = Path(registry_dir)
    for svc_csv in reg_path.glob("**/*Services*"):
        if not svc_csv.is_file():
            continue
        try:
            with open(svc_csv, encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    continue
                h = reader.fieldnames
                name_col  = find_col(h, "ServiceName", "KeyName")
                disp_col  = find_col(h, "DisplayName")
                path_col  = find_col(h, "ImagePath", "BinaryPath")
                start_col = find_col(h, "StartType", "Start")
                acct_col  = find_col(h, "ObjectName", "AccountName")
                if not (name_col and path_col):
                    continue
                for row in reader:
                    raw = row.get(path_col, "").strip()
                    if not raw or raw.startswith('"'):
                        continue
                    img = raw.lstrip()
                    if ' ' not in img:
                        continue
                    # Skip built-in Windows service paths
                    if re.search(r'(?i)\\(system32|syswow64)\\', img):
                        continue
                    if not re.match(r'(?i)[A-Za-z]:\\', img):
                        continue
                    # Generate the candidate paths Windows tries before reaching real binary
                    parts = img.split(' ')
                    candidates = []
                    for i in range(1, len(parts)):
                        c = ' '.join(parts[:i])
                        if not c.lower().endswith('.exe'):
                            c += '.exe'
                        candidates.append(c)
                    unquoted.append({
                        "ServiceName":    row.get(name_col, ""),
                        "DisplayName":    row.get(disp_col, "") if disp_col else "",
                        "StartType":      row.get(start_col, "") if start_col else "",
                        "Account":        row.get(acct_col, "") if acct_col else "",
                        "RegisteredPath": img,
                        "Candidates":     candidates,
                    })
        except Exception as e:
            print(f"  [WARN      ] {svc_csv.name} (H-reg): {e}", file=sys.stderr)

    if not unquoted:
        return 0

    # Normalise a path: lowercase, strip drive letter, backslash → forward slash
    def norm(p):
        p = p.replace('\\', '/')
        if len(p) > 2 and p[1] == ':':
            p = p[2:]
        return p.lower().strip('/')

    # Build lookup: normalised candidate → service info
    cand_map = {}
    for svc in unquoted:
        for c in svc["Candidates"]:
            cand_map[norm(c)] = svc

    # ── Step 2: scan MFT for executables placed at candidate paths ──
    hits = []
    mft_path = Path(mft_dir)
    for mft_csv in mft_path.glob("*_MFT.csv"):
        try:
            with open(mft_csv, encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    continue
                h = reader.fieldnames
                fn_col  = find_col(h, "FileName", "Name")
                par_col = find_col(h, "ParentPath", "ParentDirectory")
                ext_col = find_col(h, "Extension")
                c10_col = find_col(h, "Created0x10", "Created", "CreationTime")
                m10_col = find_col(h, "LastModified0x10", "Modified", "LastWriteTime")
                sz_col  = find_col(h, "FileSize", "Size")
                if not (fn_col and par_col):
                    continue
                for row in reader:
                    ext = (row.get(ext_col, "") if ext_col else "").lower()
                    if ext not in (".exe", ".dll"):
                        continue
                    # MFT ParentPath format: .\Folder\Sub  → strip leading .\
                    parent = row.get(par_col, "").lstrip('.').replace('\\', '/').strip('/')
                    fname  = row.get(fn_col, "")
                    full   = norm(parent + '/' + fname)
                    if full in cand_map:
                        svc = cand_map[full]
                        hits.append({
                            "Machine":        machine,
                            "ServiceName":    svc["ServiceName"],
                            "DisplayName":    svc["DisplayName"],
                            "StartType":      svc["StartType"],
                            "Account":        svc["Account"],
                            "RegisteredPath": svc["RegisteredPath"],
                            "CandidatePath":  parent + '/' + fname,
                            "MFTCreated":     row.get(c10_col, "") if c10_col else "",
                            "MFTModified":    row.get(m10_col, "") if m10_col else "",
                            "FileSizeBytes":  row.get(sz_col,  "") if sz_col  else "",
                        })
        except Exception as e:
            print(f"  [WARN      ] {mft_csv.name} (H-mft): {e}", file=sys.stderr)

    if hits:
        out_file = out_path / f"{machine}_H_UnquotedSvcPath.csv"
        with open(out_file, "w", newline="", encoding="utf-8") as fout:
            w = csv.DictWriter(fout, fieldnames=H_FIELDS)
            w.writeheader()
            w.writerows(hits)

    return len(hits)


# ── Section I — service binary hijack detection ───────────────────────────────

def check_service_hijack(in_path, out_path, machine):
    """
    Find Sysmon EID 1 events where services.exe is the parent but the spawned
    binary lives outside standard Windows system paths — the fingerprint of an
    unquoted service path exploit or service binary replacement.
    Cross-references System EID 7036 (service start) within the same minute
    to name the hijacked service.
    """
    I_FIELDS = [
        "TimeCreated", "Machine", "UserName", "Image", "CommandLine",
        "MD5", "SHA256", "CorrelatedServiceName", "CorrelatedSvcStartTime",
    ]

    # ── Pass 1: collect System 7036 "running" events for time correlation ──
    svc_starts = []   # list of (ts_prefix_16, service_name)
    for csv_path in sorted(in_path.glob("*_evtx*.csv")):
        try:
            with open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    continue
                h = reader.fieldnames
                eid_col  = find_col(h, "EventId", "EventID")
                time_col = find_col(h, "TimeCreated")
                p1_col   = find_col(h, "PayloadData1")
                pay_col  = find_col(h, "Payload")
                if not eid_col:
                    continue
                for row in reader:
                    try:
                        eid = int(row[eid_col].strip())
                    except (ValueError, KeyError):
                        continue
                    if eid != 7036:
                        continue
                    p1  = row.get(p1_col,  "") if p1_col  else ""
                    pay = row.get(pay_col, "") if pay_col else ""
                    if "running" not in (p1 + pay).lower():
                        continue
                    ts = row.get(time_col, "") if time_col else ""
                    # Extract service name from PayloadData1 ("Name: Foo | Foo")
                    svc_m = re.search(r'Name:\s*([^|,\n]+)', p1)
                    if not svc_m:
                        svc_m = re.search(r'"param1"[^"]*"#text"\s*:\s*"([^"]+)"', pay)
                    svc_name = svc_m.group(1).strip() if svc_m else ""
                    svc_starts.append((ts[:16], svc_name))
        except Exception as e:
            print(f"  [WARN      ] {csv_path.name} (I-7036): {e}", file=sys.stderr)

    # ── Pass 2: scan Sysmon EID 1 for services.exe → suspicious binary ──
    hits = []
    for csv_path in sorted(in_path.glob("*.csv")):
        try:
            with open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    continue
                h = reader.fieldnames
                eid_col  = find_col(h, "EventId", "EventID")
                time_col = find_col(h, "TimeCreated")
                user_col = find_col(h, "UserName")
                pay_col  = find_col(h, "Payload")
                if not eid_col:
                    continue
                for row in reader:
                    try:
                        eid = int(row[eid_col].strip())
                    except (ValueError, KeyError):
                        continue
                    if eid != 1:
                        continue
                    pay = row.get(pay_col, "") if pay_col else ""
                    # ParentImage must be services.exe
                    par_m = re.search(
                        r'"@Name"\s*:\s*"ParentImage"\s*,\s*"#text"\s*:\s*"([^"]+)"', pay)
                    if not par_m or not re.search(r'(?i)\\services\.exe$', par_m.group(1)):
                        continue
                    # Image path
                    img_m = re.search(
                        r'"@Name"\s*:\s*"Image"\s*,\s*"#text"\s*:\s*"([^"]+)"', pay)
                    if not img_m:
                        continue
                    image = img_m.group(1)
                    # Skip standard system paths — only flag third-party / suspicious
                    if STANDARD_SVC_PATHS_RE.search(image):
                        continue
                    ts   = row.get(time_col, "") if time_col else ""
                    user = row.get(user_col, "") if user_col else ""
                    cmd_m = re.search(
                        r'"@Name"\s*:\s*"CommandLine"\s*,\s*"#text"\s*:\s*"([^"]+)"', pay)
                    md5_m = re.search(r'MD5=([A-Fa-f0-9]{32})', pay)
                    sha_m = re.search(r'SHA256=([A-Fa-f0-9]{64})', pay)
                    # Correlate with 7036 within the same minute
                    corr_ts   = ""
                    corr_name = ""
                    for svc_ts16, svc_nm in svc_starts:
                        if ts[:16] == svc_ts16:
                            corr_ts   = svc_ts16
                            corr_name = svc_nm
                            break
                    hits.append({
                        "TimeCreated":            ts,
                        "Machine":                machine,
                        "UserName":               user,
                        "Image":                  image,
                        "CommandLine":            cmd_m.group(1)[:300] if cmd_m else "",
                        "MD5":                    md5_m.group(1) if md5_m else "",
                        "SHA256":                 sha_m.group(1) if sha_m else "",
                        "CorrelatedServiceName":  corr_name,
                        "CorrelatedSvcStartTime": corr_ts,
                    })
        except Exception as e:
            print(f"  [WARN      ] {csv_path.name} (I-sysmon): {e}", file=sys.stderr)

    if hits:
        out_file = out_path / f"{machine}_I_ServiceHijack.csv"
        with open(out_file, "w", newline="", encoding="utf-8") as fout:
            w = csv.DictWriter(fout, fieldnames=I_FIELDS)
            w.writeheader()
            w.writerows(hits)

    return len(hits)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir",    required=True)
    ap.add_argument("--output-dir",   required=True)
    ap.add_argument("--machine",      required=True)
    ap.add_argument("--timeline-out", default="")
    ap.add_argument("--registry-dir", default="")   # for H: services registry CSV dir
    ap.add_argument("--mft-dir",      default="")   # for H: machine analysis dir w/ MFT CSV
    args = ap.parse_args()

    in_path  = Path(args.input_dir)
    out_path = Path(args.output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(in_path.glob("*_evtx*.csv"))
    if not csv_files:
        print(f"  [MISSING   ] No *_evtx*.csv in {args.input_dir}")
        sys.exit(1)

    # Per-section state
    writers  = {}
    handles  = {}
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

    # Section G — renamed executables
    g_count = check_renamed_exes(in_path, out_path, args.machine)

    # Section H — unquoted service path + MFT binary placement
    h_count = check_unquoted_svc_paths(args.registry_dir, args.mft_dir, out_path, args.machine)

    # Section I — service binary hijack (services.exe spawns non-system binary)
    i_count = check_service_hijack(in_path, out_path, args.machine)

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

    # Summary
    print(f"  Events scanned : {total}")
    for sec_key, sec_def in SECTIONS.items():
        n = counts[sec_key]
        star = " *" if n > 0 else ""
        print(f"    {sec_key:<20s} — {sec_def['label']:<30s}: {n}{star}")
    for label, n in [("G_RenamedExe", g_count), ("H_UnquotedSvcPath", h_count), ("I_ServiceHijack", i_count)]:
        star = " *" if n > 0 else ""
        print(f"    {label:<20s} — {'(see label)':<30s}: {n}{star}")

    if not any(counts.values()) and g_count == 0 and h_count == 0 and i_count == 0:
        print("  [NOTE] Zero matches — event log audit policy may not capture these events,")
        print("         or Phase 3 evtx parse needs to complete first.")

if __name__ == "__main__":
    main()
PYEOF

# ─── per-machine analysis loop ───────────────────────────────────────────────

section "A–I. Hunting per machine (PrivEsc / Lateral / Kerberos / RemoteExec / RDP / Renamed / UnquotedSvc / SvcHijack)"

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

    # Locate registry Services dir (newest timestamped subdir under Registry/System)
    reg_dir=$(find "${ANALYSIS_DIR}/${machine}/Registry/System" \
        -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -r | head -1)
    reg_dir="${reg_dir:-}"

    # MFT CSVs live in the machine analysis dir itself
    mft_dir="${ANALYSIS_DIR}/${machine}"

    cmd="python3 ${PY_SCRIPT} \
        --input-dir '${evtlog_dir}' \
        --output-dir '${out_dir}' \
        --machine '${machine}' \
        --timeline-out '${TIMELINE_OUT}' \
        --registry-dir '${reg_dir}' \
        --mft-dir '${mft_dir}'"

    tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
    echo "${tool_out}" | sed 's/^/  /'

    if [[ ${rc} -ne 0 ]]; then
        status "ERROR" "Analyzer exited ${rc}"
        continue
    fi

    csv_count=$(find "${out_dir}" -maxdepth 1 -name "*.csv" 2>/dev/null | wc -l)
    status "OK" "${csv_count} section CSV(s) → ${out_dir}"

    log_cmd "${machine}" "hunt_analyzer.py (Phase 6 — A–I)" \
        "${cmd}" \
        "Priv esc / lateral movement / Kerberos / remote exec / RDP / renamed EXEs / unquoted svc path + MFT drop / service binary hijack" \
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
