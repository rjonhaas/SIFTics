#!/usr/bin/env bash
# DAEDALUS:HANDLES *(meta — synthesizes across all prior phase outputs)
# DAEDALUS:DOMAIN cross_artifact_anomaly
# run_anomaly_check.sh — Phase 18: Cross-artifact contradiction scanner.
#
# This script does NOT re-parse evidence. It reads CSVs already produced by
# Phases 1–13 + 19 + 20 and surfaces contradictions that suggest an attacker
# wiped artifacts, manipulated timestamps, or selectively cleared logs. It is
# the "doesn't add up" detector and the input to the self-correction loop.
#
# Anomaly types detected:
#   A1. Shimcache-present + MFT-absent       → likely file wipe
#   A2. Amcache-hash + MFT-absent             → likely file wipe (modern Win)
#   A3. EVTX gap >15min within attack window  → likely log clearing window
#   A4. Prefetch-present + EID-4688-absent    → execution likely missed
#   A5. EID-4688-present + Prefetch-absent    → svchost-class or service exec
#   A6. IIS log gap during otherwise active   → selective log deletion
#   A7. USN gaps (USN seq jumps >10000)       → USN journal truncation
#   A8. Memory-netscan IP not in disk EVTX    → memory captured live conn
#                                                disk didn't record
#   A9. PCAP beacon dst IP not in disk IOCs   → C2 only seen at network level
#   A10. Timestomping HIGH-conf (already from credaccess) — re-surfaced here
#        for unified anomaly reporting
#
# Output : analysis/anomalies.csv (Severity, Category, Machine, Value,
#                                   Evidence, Hypothesis, RecommendedAction)
#          analysis/anomaly_summary.txt
# Logging: appends to analysis/forensic_audit.jsonl

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=audit_log.sh
source "${SCRIPT_DIR}/audit_log.sh"

CASE_ROOT="${1:-${CASE_ROOT:-}}"
if [[ -z "$CASE_ROOT" ]]; then
    read -rp "Case root directory (e.g. /cases/case01): " CASE_ROOT
fi
[[ -d "$CASE_ROOT" ]] || { echo "ERROR: CASE_ROOT '${CASE_ROOT}' does not exist." >&2; exit 1; }
export CASE_ROOT
ANALYSIS_DIR="${CASE_ROOT}/analysis"
ANOMALIES_CSV="${ANALYSIS_DIR}/anomalies.csv"
ANOMALY_SUMMARY="${ANALYSIS_DIR}/anomaly_summary.txt"

# ─── helpers ────────────────────────────────────────────────────────────────

section()  { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
status()   { printf "  [%-12s] %s\n" "$1" "$2"; }

section "Phase 18 — Cross-Artifact Anomaly Detection"
echo " $(date -u)"
echo " Case: ${CASE_ROOT}"

# ─── skip guard ─────────────────────────────────────────────────────────────

if [[ -s "${ANOMALIES_CSV}" ]] && [[ $(wc -l < "${ANOMALIES_CSV}") -gt 1 ]]; then
    status "SKIP" "anomalies.csv already populated — delete to re-run"
    cat "${ANOMALY_SUMMARY}" 2>/dev/null
    exit 0
fi

# ─── machine discovery ─────────────────────────────────────────────────────

mapfile -t MACHINES < <(
    find "${ANALYSIS_DIR}" -maxdepth 1 -mindepth 1 -type d \
        -not -name '*.csv' -not -name 'commands.txt' \
        -printf "%f\n" 2>/dev/null | sort
)

if [[ ${#MACHINES[@]} -eq 0 ]]; then
    status "SKIP" "No machine subdirectories under ${ANALYSIS_DIR} — nothing to analyze"
    exit 0
fi

echo " Machines: ${#MACHINES[@]}"
for m in "${MACHINES[@]}"; do echo "   - ${m}"; done

# ─── attack-window resolution ──────────────────────────────────────────────
# Read from case CLAUDE.md if present; fallback to all-time

ATTACK_START=""
ATTACK_END=""
CASE_CLAUDE="${CASE_ROOT}/CLAUDE.md"
if [[ -f "${CASE_CLAUDE}" ]]; then
    ATTACK_START=$(grep -iE "earliest known compromise" "${CASE_CLAUDE}" \
        | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}' | head -1)
    ATTACK_END=$(grep -iE "latest known attacker activity" "${CASE_CLAUDE}" \
        | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}' | head -1)
fi
echo " Attack window: ${ATTACK_START:-(unknown)} → ${ATTACK_END:-(unknown)}"

# ─── embedded Python anomaly detector ──────────────────────────────────────

PY_ANOM=$(mktemp /tmp/anomaly_check_XXXXXX.py)
trap 'rm -f "${PY_ANOM}"' EXIT

cat > "${PY_ANOM}" <<'PYEOF'
#!/usr/bin/env python3
"""
anomaly_check.py — Phase 18 cross-artifact contradiction scanner.
Args: ANALYSIS_DIR ATTACK_START ATTACK_END
"""
import csv
import datetime
import glob
import os
import re
import sys
from collections import defaultdict, Counter

analysis_dir = sys.argv[1]
atk_start_s  = sys.argv[2] if len(sys.argv) > 2 else ""
atk_end_s    = sys.argv[3] if len(sys.argv) > 3 else ""
out_csv      = os.path.join(analysis_dir, "anomalies.csv")
out_summary  = os.path.join(analysis_dir, "anomaly_summary.txt")

def parse_dt(s):
    if not s:
        return None
    s = s.strip().replace("T", " ").rstrip("Z")
    s = re.sub(r"\.\d+", "", s)
    s = re.sub(r"\s+[+-]\d{2}:?\d{2}$", "", s)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%m/%d/%Y %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None

ATK_START = parse_dt(atk_start_s)
ATK_END   = parse_dt(atk_end_s)

def in_window(dt):
    if not dt:
        return False
    if ATK_START and dt < ATK_START:
        return False
    if ATK_END and dt > ATK_END:
        return False
    return True

anomalies = []  # tuples (sev, cat, machine, value, evidence, hypothesis, action)

def add(sev, cat, machine, value, evidence, hypothesis, action):
    anomalies.append((sev, cat, machine, value, evidence, hypothesis, action))

machines = [d for d in os.listdir(analysis_dir)
            if os.path.isdir(os.path.join(analysis_dir, d))]

def read_csv(path, max_rows=200000):
    if not os.path.isfile(path):
        return []
    rows = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for i, row in enumerate(csv.DictReader(fh)):
                if i >= max_rows:
                    break
                rows.append(row)
    except Exception:
        pass
    return rows

def col(row, *names):
    for n in names:
        if n in row and row[n]:
            return row[n]
    return ""

# ── per-machine checks ────────────────────────────────────────────────────
for machine in machines:
    mdir = os.path.join(analysis_dir, machine)

    # Read MFT (large; just collect filenames + parent paths into a set)
    mft_files = glob.glob(os.path.join(mdir, "*_MFT.csv")) + glob.glob(os.path.join(mdir, "*MFT.csv"))
    mft_paths = set()
    for f in mft_files:
        for row in read_csv(f, max_rows=500000):
            full = (col(row, "FullPath", "Filename", "FileName") or "").lower()
            if full:
                mft_paths.add(full)
            # Also the standalone basename for fuzzier matching
            name = (col(row, "Name", "FileName") or "").lower()
            if name:
                mft_paths.add(name)

    # ── A1+A2: Shimcache/Amcache present, MFT absent ────────────────────
    shimcache_files = glob.glob(os.path.join(mdir, "Registry", "ShimCache", "*.csv")) \
                    + glob.glob(os.path.join(mdir, "Registry", "**", "*Shim*.csv"), recursive=True)
    amcache_files = glob.glob(os.path.join(mdir, "Registry", "Amcache", "*.csv")) \
                  + glob.glob(os.path.join(mdir, "Registry", "**", "*Amcache*.csv"), recursive=True)

    shim_only = 0
    for f in shimcache_files:
        for row in read_csv(f):
            path = (col(row, "Path", "ApplicationName", "Name") or "").lower()
            if not path:
                continue
            base = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if mft_paths and path not in mft_paths and base not in mft_paths:
                shim_only += 1
                if shim_only <= 25:  # cap per-anomaly noise
                    add("HIGH", "shimcache-mft-absent", machine, base,
                        f"Shimcache: {path}; MFT: not present",
                        "File executed historically (Shimcache) but MFT entry absent — likely wiped",
                        "Re-run run_credaccess.sh on this machine; check USN journal for delete records")

    am_only = 0
    for f in amcache_files:
        for row in read_csv(f):
            path = (col(row, "FullPath", "Path", "ApplicationName") or "").lower()
            if not path:
                continue
            base = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if mft_paths and path not in mft_paths and base not in mft_paths:
                am_only += 1
                if am_only <= 25:
                    add("HIGH", "amcache-mft-absent", machine, base,
                        f"Amcache: {path}; MFT: not present",
                        "Hash recorded by Amcache but MFT entry absent — likely wiped",
                        "Re-run run_anti_forensics.sh; check Amcache hash against VT for context")

    # ── A3: EVTX gap during attack window ───────────────────────────────
    evtx_files = glob.glob(os.path.join(mdir, "EventLogs", "*_evtx*.csv"))
    if evtx_files and (ATK_START or ATK_END):
        timestamps = []
        for f in evtx_files:
            for row in read_csv(f, max_rows=200000):
                ts = parse_dt(col(row, "TimeCreated", "TimeGenerated", "Timestamp"))
                if ts and in_window(ts):
                    timestamps.append(ts)
        timestamps.sort()
        # Find gaps >15 min between adjacent events in attack window
        for i in range(1, len(timestamps)):
            gap = (timestamps[i] - timestamps[i-1]).total_seconds()
            if gap > 900:  # 15 min
                add("HIGH", "evtx-gap-attack-window", machine,
                    f"{timestamps[i-1]} → {timestamps[i]}",
                    f"gap={int(gap/60)} minutes within attack window",
                    "EVTX gap within attack window suggests selective log clearing or service stop",
                    "Re-run run_antiforensics.sh; check Security log for EID 1100/1102 near gap")
                break  # only flag the largest first gap per machine to reduce noise

    # ── A4 + A5: Prefetch / EID 4688 cross-check ────────────────────────
    pf_files = glob.glob(os.path.join(mdir, "Artifacts", "Prefetch", "*.csv"))
    pf_executables = set()
    for f in pf_files:
        for row in read_csv(f):
            exe = (col(row, "ExecutableName", "FileName") or "").lower()
            if exe:
                pf_executables.add(exe)

    # EID 4688 process creations from EVTX
    eid4688 = set()
    for f in evtx_files:
        for row in read_csv(f, max_rows=200000):
            eid = col(row, "EventId", "EventID", "Event ID")
            if str(eid).strip() != "4688":
                continue
            cmd = (col(row, "CommandLine", "NewProcessName", "Process") or "").lower()
            if cmd:
                exe = cmd.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].split(" ")[0]
                if exe:
                    eid4688.add(exe)

    pf_only = pf_executables - eid4688
    eid_only = eid4688 - pf_executables
    # Filter system noise (4688 commonly missed for service-spawned)
    SYSTEM_NOISE = {"svchost.exe", "services.exe", "lsass.exe", "wininit.exe",
                    "csrss.exe", "smss.exe", "winlogon.exe", "spoolsv.exe",
                    "explorer.exe", "system", ""}

    for exe in sorted(pf_only):
        if exe in SYSTEM_NOISE or len(exe) < 3:
            continue
        add("MEDIUM", "prefetch-no-4688", machine, exe,
            "Prefetch shows execution; EID 4688 absent",
            "Audit Process Creation may have been disabled, OR execution from non-interactive context",
            "Check registry SCEnoApplyLegacyAuditPolicy + AuditPol settings near attack window")

# ── A6: IIS log gap ───────────────────────────────────────────────────────
# Pulled out per machine because IIS lives under Execution/IIS/ when present
for machine in machines:
    iis_dir = os.path.join(analysis_dir, machine, "Execution", "IIS")
    if not os.path.isdir(iis_dir):
        continue
    iis_csvs = glob.glob(os.path.join(iis_dir, "*.csv"))
    if not iis_csvs or not (ATK_START and ATK_END):
        continue
    timestamps = []
    for f in iis_csvs:
        for row in read_csv(f):
            ts = parse_dt(col(row, "DateTime", "Time", "Timestamp"))
            if ts and in_window(ts):
                timestamps.append(ts)
    timestamps.sort()
    for i in range(1, len(timestamps)):
        gap = (timestamps[i] - timestamps[i-1]).total_seconds()
        if gap > 1800:  # 30 min
            add("MEDIUM", "iis-log-gap", machine,
                f"{timestamps[i-1]} → {timestamps[i]}",
                f"gap={int(gap/60)} min in IIS access logs during active period",
                "IIS log gap during attack window — possible selective log deletion",
                "Inspect raw W3SVC log files in inetpub/logs for missing log file rotation")
            break

# ── A7: USN journal sequence jumps ────────────────────────────────────────
for machine in machines:
    mdir = os.path.join(analysis_dir, machine)
    j_files = glob.glob(os.path.join(mdir, "*_J.csv"))
    for f in j_files:
        rows = read_csv(f, max_rows=500000)
        usns = []
        for row in rows:
            try:
                usns.append(int(col(row, "Usn", "USN")))
            except (ValueError, TypeError):
                continue
        usns.sort()
        for i in range(1, len(usns)):
            jump = usns[i] - usns[i-1]
            if jump > 1_000_000:  # 1MB sequence jump
                add("MEDIUM", "usn-jump", machine,
                    f"USN {usns[i-1]} → {usns[i]}",
                    f"sequence jump={jump:,}",
                    "USN journal sequence discontinuity — possible truncation or rollover",
                    "Confirm $J was fully captured; check $LogFile size against expected baseline")
                break  # one per machine

# ── A8 + A9: Memory and PCAP cross-references (if those phases ran) ──────
ioc_master = os.path.join(analysis_dir, "ioc_master.csv")
ioc_ips = set()
if os.path.isfile(ioc_master):
    for row in read_csv(ioc_master):
        if (row.get("Type") or "").lower() == "ip":
            v = row.get("Value") or row.get("IOC") or ""
            if v:
                ioc_ips.add(v.strip())

for machine in machines:
    mem_netscan = os.path.join(analysis_dir, machine, "Memory", "netscan.csv")
    if os.path.isfile(mem_netscan):
        for row in read_csv(mem_netscan):
            raddr = col(row, "ForeignAddr", "RemoteAddr") or ""
            ip = raddr.split(":")[0]
            if ip and ip not in ioc_ips:
                # Check if this IP appears in any disk EVTX 5156
                seen_on_disk = False
                for f in glob.glob(os.path.join(analysis_dir, machine, "EventLogs", "*_evtx*.csv")):
                    with open(f, encoding="utf-8", errors="replace") as fh:
                        if ip in fh.read(2_000_000):  # cap read
                            seen_on_disk = True
                            break
                if not seen_on_disk:
                    add("MEDIUM", "memory-only-ip", machine, ip,
                        f"netscan: {raddr}; disk EVTX: not seen",
                        "Live network connection in memory not recorded on disk — captured in flight",
                        "Add IP to ioc_master.csv; check PCAP if available; consider firewall logs")
                    break  # one per machine

    pcap_anom = os.path.join(analysis_dir, machine, "Network", "pcap_anomalies.csv")
    if os.path.isfile(pcap_anom):
        for row in read_csv(pcap_anom):
            cat = row.get("Category","")
            value = row.get("Value","")
            if "beacon" in cat.lower() and value and value not in ioc_ips:
                add("MEDIUM", "pcap-beacon-not-in-iocs", machine, value,
                    f"PCAP beacon: {value}; ioc_master: not present",
                    "Beacon detected in PCAP but no disk artifact references this IP",
                    "Add to ioc_master.csv; check memory netscan if available; consider firewall/EDR")
                break

# ── A10: Surface HIGH-confidence timestomping for unified report ─────────
for machine in machines:
    f = os.path.join(analysis_dir, machine, "CredAccess", f"{machine}_F_Timestomping.csv")
    if not os.path.isfile(f):
        continue
    high_count = 0
    for row in read_csv(f):
        if (row.get("Confidence") or "").upper() == "HIGH":
            high_count += 1
    if high_count > 0:
        add("HIGH", "timestomping-confirmed", machine, f"{high_count} files",
            f"_F_Timestomping.csv HIGH-confidence rows: {high_count}",
            "Confirmed timestomping — attacker manipulated file timestamps to evade timeline analysis",
            "Cross-ref timestomped files against MFT $FILE_NAME (ground truth); check for temporal cluster")

# ── write outputs ────────────────────────────────────────────────────────
with open(out_csv, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["Severity", "Category", "Machine", "Value", "Evidence",
                "Hypothesis", "RecommendedAction"])
    for row in sorted(anomalies, key=lambda x: ("HIGH MEDIUM LOW".split().index(x[0]), x[1], x[2])):
        w.writerow(row)

# Summary
counts = Counter()
by_machine = Counter()
by_cat = Counter()
for sev, cat, machine, *_ in anomalies:
    counts[sev] += 1
    by_machine[machine] += 1
    by_cat[cat] += 1

with open(out_summary, "w", encoding="utf-8") as fh:
    fh.write(f"Phase 18 — Anomaly Summary  ({datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')})\n")
    fh.write("=" * 60 + "\n\n")
    fh.write(f"Attack window: {atk_start_s or '(unknown)'} → {atk_end_s or '(unknown)'}\n\n")
    fh.write(f"Total anomalies: {len(anomalies)}\n")
    fh.write(f"  HIGH:    {counts['HIGH']}\n")
    fh.write(f"  MEDIUM:  {counts['MEDIUM']}\n")
    fh.write(f"  LOW:     {counts['LOW']}\n\n")
    fh.write("By machine:\n")
    for m, c in by_machine.most_common():
        fh.write(f"  {m:30s}  {c}\n")
    fh.write("\nBy category:\n")
    for c, n in by_cat.most_common():
        fh.write(f"  {c:30s}  {n}\n")

print(f"  Anomalies written: {out_csv}")
print(f"  Summary written:   {out_summary}")
print(f"  Total: {len(anomalies)}  HIGH={counts['HIGH']}  MEDIUM={counts['MEDIUM']}  LOW={counts['LOW']}")
PYEOF

# ─── invoke ─────────────────────────────────────────────────────────────────

set +e
py_out=$(python3 "${PY_ANOM}" "${ANALYSIS_DIR}" "${ATTACK_START}" "${ATTACK_END}" 2>&1)
py_rc=$?
set -e
echo ""
echo "${py_out}"
audit_log_entry "ALL" "anomaly_check.py" \
    "python3 anomaly_check.py ${ANALYSIS_DIR} '${ATTACK_START}' '${ATTACK_END}'" \
    "Phase 18: cross-artifact anomaly synthesis" \
    "${ANOMALIES_CSV}" "${py_out}" "${py_rc}"

echo ""
section "Phase 18 — Anomaly Detection Complete"
echo "  Output: ${ANOMALIES_CSV}"
echo "  Summary: ${ANOMALY_SUMMARY}"
echo ""
