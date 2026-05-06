#!/usr/bin/env bash
# DAEDALUS:HANDLES mem_image
# DAEDALUS:DOMAIN windows_memory
# run_memory.sh — Phase 19: Autonomous memory triage via Volatility 3.
#
# Sections:
#   M1. Image discovery                — *.mem / *.raw / *.dmp / *.vmem under CASE_ROOT
#   M2. Process scan                    — windows.psscan
#   M3. Process tree                    — windows.pstree
#   M4. Command lines                   — windows.cmdline
#   M5. Network connections             — windows.netscan
#   M6. Service inventory               — windows.svcscan
#   M7. Code injection (with dump)      — windows.malfind --dump
#   M8. Timeline                        — timeliner
#   M9. YARA sweep on malfind dumps     — if /opt/yara_rules/ exists
#   M10. Memory anomaly synthesis       — orphan PPIDs, wrong-parent svchost/lsass,
#                                          RWX VADs without file backing,
#                                          netscan IPs cross-ref against ioc_master.csv
#
# Output : analysis/<MACHINE>/Memory/{psscan,pstree,cmdline,netscan,svcscan,malfind,timeliner}.csv
#          analysis/<MACHINE>/Memory/dumps/<pid>_*.dmp           (malfind dumps)
#          analysis/<MACHINE>/Memory/yara_hits.csv               (if YARA rules present)
#          analysis/<MACHINE>/Memory/memory_anomalies.csv        (synthesis)
# Logging: appends to analysis/forensic_audit.jsonl + analysis/commands.txt

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=audit_log.sh
source "${SCRIPT_DIR}/audit_log.sh"

# Resolve CASE_ROOT: $1 argument → inherited env var → interactive prompt
CASE_ROOT="${1:-${CASE_ROOT:-}}"
if [[ -z "$CASE_ROOT" ]]; then
    read -rp "Case root directory (e.g. /cases/case01): " CASE_ROOT
fi
[[ -d "$CASE_ROOT" ]] || { echo "ERROR: CASE_ROOT '${CASE_ROOT}' does not exist." >&2; exit 1; }
export CASE_ROOT
ANALYSIS_DIR="${CASE_ROOT}/analysis"

VOL3="${VOL3:-python3 /opt/volatility3-2.20.0/vol.py}"
YARA_BIN="${YARA_BIN:-/usr/local/bin/yara}"
YARA_RULES_DIR="${YARA_RULES_DIR:-/opt/yara_rules}"
IOC_MASTER="${ANALYSIS_DIR}/ioc_master.csv"

# ─── helpers ────────────────────────────────────────────────────────────────

run_tool() {
    set +e; out=$(eval "$1" 2>&1); rc=$?; set -e
    echo "${out}"; return ${rc}
}

section()        { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
machine_header() { echo ""; echo "  ── $* ──"; }
status()         { printf "  [%-12s] %s\n" "$1" "$2"; }

# ─── discovery ──────────────────────────────────────────────────────────────

mapfile -t MEMORY_IMAGES < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -type f \
        \( -iname "*.mem" -o -iname "*.raw" -o -iname "*.dmp" -o -iname "*.vmem" -o -iname "*.lime" \) \
        -size +10M -print 2>/dev/null | sort
)

echo "════════════════════════════════════════════════════"
echo " Memory Triage — Phase 19 (Volatility 3)"
echo " $(date -u)"
echo " Case   : ${CASE_ROOT}"
echo " Images : ${#MEMORY_IMAGES[@]}"
echo "════════════════════════════════════════════════════"

if [[ ${#MEMORY_IMAGES[@]} -eq 0 ]]; then
    status "SKIP" "No memory images found under ${CASE_ROOT} (looked for *.mem, *.raw, *.dmp, *.vmem, *.lime ≥10M)"
    exit 0
fi

# ─── verify Volatility 3 is callable ────────────────────────────────────────

if ! eval "${VOL3} --help" >/dev/null 2>&1; then
    status "ERROR" "Volatility 3 not callable as: ${VOL3}"
    echo "  Override with: VOL3='python3 /path/to/vol.py' bash $0 ${CASE_ROOT}"
    exit 1
fi

# ─── per-image processing ───────────────────────────────────────────────────

# vol3_run PLUGIN OUTPUT_CSV [EXTRA_ARGS...]
# Runs Volatility 3 plugin with CSV renderer; logs via audit_log.
vol3_run() {
    local plugin="$1" out_csv="$2"; shift 2
    local image="$IMG" machine="$MACHINE"
    local cmd="${VOL3} -f '${image}' -r csv ${plugin} $*"

    if [[ -s "${out_csv}" ]] && [[ $(wc -l < "${out_csv}") -gt 1 ]]; then
        status "SKIP" "${plugin} — already populated"
        return 0
    fi

    set +e
    eval "${cmd}" > "${out_csv}" 2> "${out_csv}.stderr"
    local rc=$?
    set -e

    local lines=$(wc -l < "${out_csv}" 2>/dev/null || echo 0)
    audit_log_entry "${machine}" "Volatility3 (${plugin})" "${cmd}" \
        "Memory triage Phase 19: ${plugin}" "${out_csv}" \
        "${lines} lines" "${rc}"

    if [[ ${rc} -ne 0 ]] || [[ ${lines} -le 1 ]]; then
        status "WARN" "${plugin} → ${lines} lines, rc=${rc} (see ${out_csv}.stderr)"
        return 1
    fi
    status "OK" "${plugin} → ${lines} lines"
}

for IMG in "${MEMORY_IMAGES[@]}"; do
    # Machine name: basename minus extension, sanitized
    BASE=$(basename "${IMG}")
    MACHINE="${LINUX_MACHINE:-${BASE%.*}}"
    # Replace non-alphanumerics with _
    MACHINE=$(echo "${MACHINE}" | tr -c '[:alnum:]_-' '_' | sed 's/_*$//')

    OUT_DIR="${ANALYSIS_DIR}/${MACHINE}/Memory"
    DUMP_DIR="${OUT_DIR}/dumps"
    mkdir -p "${OUT_DIR}" "${DUMP_DIR}"

    section "Memory image: ${IMG} → MACHINE=${MACHINE}"

    # Per-machine completion signal: psscan.csv has data
    PSSCAN_CSV="${OUT_DIR}/psscan.csv"
    if [[ -s "${PSSCAN_CSV}" ]] && [[ $(wc -l < "${PSSCAN_CSV}") -gt 1 ]] \
       && [[ -s "${OUT_DIR}/memory_anomalies.csv" ]]; then
        status "SKIP" "Memory triage already complete for ${MACHINE}"
        continue
    fi

    machine_header "Sections M2–M8: Volatility 3 plugins"

    vol3_run "windows.psscan.PsScan"     "${OUT_DIR}/psscan.csv"     || true
    vol3_run "windows.pstree.PsTree"     "${OUT_DIR}/pstree.csv"     || true
    vol3_run "windows.cmdline.CmdLine"   "${OUT_DIR}/cmdline.csv"    || true
    vol3_run "windows.netscan.NetScan"   "${OUT_DIR}/netscan.csv"    || true
    vol3_run "windows.svcscan.SvcScan"   "${OUT_DIR}/svcscan.csv"    || true
    vol3_run "windows.malfind.Malfind"   "${OUT_DIR}/malfind.csv"   --dump "--dump-dir=${DUMP_DIR}" || true
    vol3_run "timeliner.Timeliner"       "${OUT_DIR}/timeliner.csv"  || true

    # ── M9. YARA sweep on malfind dumps ─────────────────────────────────────
    machine_header "Section M9: YARA sweep on malfind dumps"
    YARA_HITS="${OUT_DIR}/yara_hits.csv"
    DUMP_COUNT=$(find "${DUMP_DIR}" -type f 2>/dev/null | wc -l)

    if [[ ${DUMP_COUNT} -eq 0 ]]; then
        status "SKIP" "No malfind dumps to scan"
    elif [[ ! -x "${YARA_BIN}" ]]; then
        status "SKIP" "YARA not at ${YARA_BIN}; set YARA_BIN to override"
    elif [[ ! -d "${YARA_RULES_DIR}" ]]; then
        status "SKIP" "No YARA rules at ${YARA_RULES_DIR}; set YARA_RULES_DIR to override"
    else
        echo "Rule,DumpFile,DumpSize,Strings" > "${YARA_HITS}"
        find "${YARA_RULES_DIR}" -name "*.yar" -o -name "*.yara" 2>/dev/null \
        | while read -r rule_file; do
            find "${DUMP_DIR}" -type f 2>/dev/null \
            | while read -r dump; do
                hits=$("${YARA_BIN}" -s "${rule_file}" "${dump}" 2>/dev/null)
                if [[ -n "${hits}" ]]; then
                    rule_name=$(echo "${hits}" | head -1 | awk '{print $1}')
                    dsize=$(stat -c %s "${dump}" 2>/dev/null || echo 0)
                    matches=$(echo "${hits}" | grep -E '^0x' | head -3 | tr '\n' '|')
                    echo "${rule_name},${dump},${dsize},\"${matches}\"" >> "${YARA_HITS}"
                fi
            done
        done
        hit_count=$(($(wc -l < "${YARA_HITS}") - 1))
        status "OK" "YARA → ${hit_count} hits across ${DUMP_COUNT} dumps"
        audit_log_entry "${MACHINE}" "YARA (malfind dumps)" \
            "${YARA_BIN} -s <rules> <dumps>" \
            "Phase 19 M9: YARA sweep on memory dumps" \
            "${YARA_HITS}" "${hit_count} hits / ${DUMP_COUNT} dumps" "0"
    fi

    # ── M10. Memory anomaly synthesis ────────────────────────────────────────
    machine_header "Section M10: Memory anomaly synthesis"
    ANOMALIES="${OUT_DIR}/memory_anomalies.csv"

    PY_OUT=$(mktemp /tmp/mem_anom_XXXXXX.py)
    trap 'rm -f "${PY_OUT}"' EXIT
    cat > "${PY_OUT}" <<'PYEOF'
#!/usr/bin/env python3
"""
memory_anomaly_synth.py — Phase 19 M10
Reads psscan/pstree/cmdline/netscan + ioc_master.csv (if present); flags:
  - Orphan PPID (parent process not in psscan)
  - Wrong-parent classics: svchost.exe parent != services.exe;
    lsass.exe parent != wininit.exe; conhost.exe parent != cmd-likes
  - Suspicious paths: process image in Temp/AppData/ProgramData/Public
  - netscan external IPs that match ioc_master.csv
  - malfind hits (RWX VAD without file backing) — already produced by Vol3
"""
import csv
import ipaddress
import os
import sys
from collections import defaultdict

mem_dir = sys.argv[1]
ioc_master = sys.argv[2] if len(sys.argv) > 2 else ""
out_csv = os.path.join(mem_dir, "memory_anomalies.csv")

def read_csv(path):
    if not os.path.isfile(path):
        return []
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        return list(csv.DictReader(fh))

psscan = read_csv(os.path.join(mem_dir, "psscan.csv"))
cmdline_rows = read_csv(os.path.join(mem_dir, "cmdline.csv"))
netscan = read_csv(os.path.join(mem_dir, "netscan.csv"))
malfind = read_csv(os.path.join(mem_dir, "malfind.csv"))

def col(row, *names):
    for n in names:
        if n in row and row[n]:
            return row[n]
    return ""

def is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
    except ValueError:
        return True

# Build PID → process map
pid_to_proc = {}
for row in psscan:
    pid = col(row, "PID")
    name = (col(row, "ImageFileName", "Name", "ProcessName") or "").lower()
    ppid = col(row, "PPID")
    if pid:
        pid_to_proc[pid] = {"name": name, "ppid": ppid, "row": row}

# Build PID → cmdline map
pid_to_cmd = {}
for row in cmdline_rows:
    pid_to_cmd[col(row, "PID")] = col(row, "Args", "CommandLine", "Cmdline")

EXPECTED_PARENTS = {
    "svchost.exe": {"services.exe"},
    "lsass.exe": {"wininit.exe"},
    "winlogon.exe": {"smss.exe"},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "lsm.exe": {"wininit.exe"},
    "spoolsv.exe": {"services.exe"},
}
SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\", "\\programdata\\", "\\users\\public\\",
                    "\\$recycle.bin\\", "\\windows\\debug\\", "\\windows\\tasks\\"]

anomalies = []  # (severity, category, pid, process, evidence, hypothesis)

# Wrong-parent + orphan-PPID detection
for pid, p in pid_to_proc.items():
    name = p["name"]
    ppid = p["ppid"]
    parent = pid_to_proc.get(ppid)

    if name in EXPECTED_PARENTS:
        if not parent:
            anomalies.append(("HIGH", "wrong-parent", pid, name,
                              f"parent PID {ppid} not in psscan",
                              f"{name} expects parent in {sorted(EXPECTED_PARENTS[name])} — orphan"))
        elif parent["name"] not in EXPECTED_PARENTS[name]:
            anomalies.append(("HIGH", "wrong-parent", pid, name,
                              f"parent={parent['name']} (PID {ppid})",
                              f"{name} should be spawned by {sorted(EXPECTED_PARENTS[name])}"))

    # Suspicious image paths from cmdline
    cmd = (pid_to_cmd.get(pid) or "").lower()
    for sp in SUSPICIOUS_PATHS:
        if sp in cmd:
            anomalies.append(("MEDIUM", "suspicious-path", pid, name,
                              f"cmdline path={sp}",
                              "process image in attacker-friendly directory"))
            break

# malfind hits
for row in malfind:
    pid = col(row, "PID")
    name = (col(row, "Process", "ProcessName") or "").lower()
    proto = col(row, "Protection", "VadTag")
    file_backed = col(row, "FileOutput", "File")
    if "PAGE_EXECUTE_READWRITE" in proto.upper() or "RWX" in proto.upper():
        anomalies.append(("HIGH", "malfind-rwx", pid, name,
                          f"protection={proto} file_backed={file_backed or 'NONE'}",
                          "RWX memory region without file backing — code injection candidate"))

# netscan vs ioc_master
ioc_ips = set()
if ioc_master and os.path.isfile(ioc_master):
    with open(ioc_master, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            t = (row.get("Type") or "").lower()
            v = row.get("Value") or row.get("IOC") or ""
            if t == "ip" and v:
                ioc_ips.add(v.strip())

for row in netscan:
    raddr = col(row, "ForeignAddr", "RemoteAddr", "Foreign Address")
    raddr_ip = raddr.split(":")[0] if raddr else ""
    if not raddr_ip or is_internal(raddr_ip):
        continue
    pid = col(row, "PID", "Owner")
    proto = col(row, "Proto", "Protocol")
    state = col(row, "State")
    process = (col(row, "Owner", "ProcessName") or pid_to_proc.get(pid, {}).get("name", "?"))

    if raddr_ip in ioc_ips:
        anomalies.append(("HIGH", "netscan-ioc-match", pid, process,
                          f"{proto} {raddr} ({state})",
                          f"connection to IOC IP {raddr_ip} — confirms host compromise"))
    else:
        anomalies.append(("LOW", "external-conn", pid, process,
                          f"{proto} {raddr} ({state})",
                          "external connection — review"))

# Write
with open(out_csv, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["Severity", "Category", "PID", "Process", "Evidence", "Hypothesis"])
    for row in sorted(anomalies, key=lambda x: ("HIGH MEDIUM LOW".split().index(x[0]), x[1])):
        w.writerow(row)

high = sum(1 for a in anomalies if a[0] == "HIGH")
med = sum(1 for a in anomalies if a[0] == "MEDIUM")
low = sum(1 for a in anomalies if a[0] == "LOW")
print(f"  Anomalies → HIGH={high}  MEDIUM={med}  LOW={low}  total={len(anomalies)}")
PYEOF

    set +e
    py_out=$(python3 "${PY_OUT}" "${OUT_DIR}" "${IOC_MASTER}" 2>&1)
    py_rc=$?
    set -e
    echo "${py_out}"
    audit_log_entry "${MACHINE}" "memory_anomaly_synth.py" \
        "python3 memory_anomaly_synth.py ${OUT_DIR} ${IOC_MASTER}" \
        "Phase 19 M10: synthesize memory anomalies (wrong-parent, malfind, netscan IOC)" \
        "${ANOMALIES}" "${py_out}" "${py_rc}"

    rm -f "${PY_OUT}"
    trap - EXIT
done

# ─── completion ─────────────────────────────────────────────────────────────

section "Phase 19 — Memory Triage Complete"
echo "  Output base: ${ANALYSIS_DIR}/<MACHINE>/Memory/"
echo "  Completion signal: psscan.csv + memory_anomalies.csv per machine"
echo ""
