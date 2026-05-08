#!/usr/bin/env bash
# DAEDALUS:HANDLES pcap zeek_logs
# DAEDALUS:DOMAIN network_captures
# run_pcap.sh — Phase 20: Autonomous PCAP triage via tshark + (optional) Zeek.
#
# Sections:
#   N1. Capture orientation             — capinfos per file
#   N2. Top talkers + external IPs     — tshark conv,ip + RFC1918 filter
#   N3. DNS                              — queries, NXDOMAIN, suspicious-name (DGA-ish)
#   N4. HTTP                             — requests, large responses, TLS SNI
#   N5. Beacon scoring                  — per-dst-IP interval CV (reuse C2 beacon algo)
#   N6. Zeek (optional)                 — conn/dns/http/ssl/files if zeek present
#   N7. PCAP anomaly synthesis          — beacon candidates, NXDOMAIN bursts,
#                                          large outbound, IOC IP matches
#
# Output : analysis/<MACHINE>/Network/{capinfos,top_talkers,external_ips,dns_queries,
#          dns_nxdomain,dns_suspicious,http_requests,http_large_responses,tls_sni,
#          beacon_scores,large_transfers,pcap_anomalies}.csv
#          analysis/<MACHINE>/Network/zeek/{conn,dns,http,ssl,files}.log  (if Zeek)
# Logging: appends to analysis/forensic_audit.jsonl + analysis/commands.txt

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

TSHARK="${TSHARK:-/usr/bin/tshark}"
CAPINFOS="${CAPINFOS:-/usr/bin/capinfos}"
ZEEK="${ZEEK:-/opt/zeek/bin/zeek}"
IOC_MASTER="${ANALYSIS_DIR}/ioc_master.csv"
DENYLIST_JSON="${SCRIPT_DIR}/../config/ioc_denylist.json"

# ─── helpers ────────────────────────────────────────────────────────────────

run_tool() {
    set +e; out=$(eval "$1" 2>&1); rc=$?; set -e
    echo "${out}"; return ${rc}
}

section()        { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
machine_header() { echo ""; echo "  ── $* ──"; }
status()         { printf "  [%-12s] %s\n" "$1" "$2"; }

# ─── discovery ──────────────────────────────────────────────────────────────

mapfile -t PCAPS < <(
    find "${CASE_ROOT}" -path "${ANALYSIS_DIR}" -prune -o -type f \
        \( -iname "*.pcap" -o -iname "*.pcapng" -o -iname "*.cap" \) \
        -size +10k -print 2>/dev/null | sort
)

echo "════════════════════════════════════════════════════"
echo " Network Capture Triage — Phase 20 (tshark/Zeek)"
echo " $(date -u)"
echo " Case  : ${CASE_ROOT}"
echo " PCAPs : ${#PCAPS[@]}"
echo "════════════════════════════════════════════════════"

if [[ ${#PCAPS[@]} -eq 0 ]]; then
    status "SKIP" "No PCAPs found under ${CASE_ROOT}"
    exit 0
fi

if [[ ! -x "${TSHARK}" ]]; then
    status "ERROR" "tshark not at ${TSHARK}"
    echo "  Install: sudo apt install tshark"
    exit 1
fi

# ─── per-PCAP processing ────────────────────────────────────────────────────

for PCAP in "${PCAPS[@]}"; do
    BASE=$(basename "${PCAP}")
    MACHINE="${PCAP_MACHINE:-${BASE%.*}}"
    MACHINE=$(echo "${MACHINE}" | tr -c '[:alnum:]_-' '_' | sed 's/_*$//')

    OUT_DIR="${ANALYSIS_DIR}/${MACHINE}/Network"
    ZEEK_DIR="${OUT_DIR}/zeek"
    mkdir -p "${OUT_DIR}"

    section "PCAP: ${PCAP} → MACHINE=${MACHINE}"

    # Per-file completion: anomaly CSV exists with data
    if [[ -s "${OUT_DIR}/pcap_anomalies.csv" ]] && [[ $(wc -l < "${OUT_DIR}/pcap_anomalies.csv") -gt 1 ]]; then
        status "SKIP" "PCAP triage already complete for ${MACHINE}"
        continue
    fi

    # ── N1. Orientation ──────────────────────────────────────────────────────
    machine_header "N1: Orientation (capinfos)"
    INFO_TXT="${OUT_DIR}/capinfos.txt"
    if [[ -x "${CAPINFOS}" ]]; then
        set +e
        "${CAPINFOS}" "${PCAP}" > "${INFO_TXT}" 2>&1
        rc=$?
        set -e
        status "OK" "capinfos → ${INFO_TXT}"
        audit_log_entry "${MACHINE}" "capinfos" "${CAPINFOS} ${PCAP}" \
            "Phase 20 N1: PCAP orientation" "${INFO_TXT}" "$(wc -l < "${INFO_TXT}") lines" "${rc}"
    else
        status "SKIP" "capinfos not present"
    fi

    # ── N2. Top talkers + external IPs ───────────────────────────────────────
    machine_header "N2: Top talkers + external IPs"

    TOP_TALKERS="${OUT_DIR}/top_talkers.txt"
    set +e
    "${TSHARK}" -r "${PCAP}" -z conv,ip -q 2>/dev/null > "${TOP_TALKERS}"
    rc=$?
    set -e
    status "OK" "top_talkers → ${TOP_TALKERS}"
    audit_log_entry "${MACHINE}" "tshark (conv,ip)" \
        "tshark -r ${PCAP} -z conv,ip -q" \
        "Phase 20 N2: top talker conversations" "${TOP_TALKERS}" "$(wc -l < "${TOP_TALKERS}") lines" "${rc}"

    EXT_IPS="${OUT_DIR}/external_ips.txt"
    set +e
    "${TSHARK}" -r "${PCAP}" -T fields -e ip.src -e ip.dst 2>/dev/null \
      | tr '\t' '\n' | sort -u \
      | grep -Ev '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|224\.|::|fe80:|$)' \
      > "${EXT_IPS}"
    set -e
    ext_count=$(wc -l < "${EXT_IPS}")
    status "OK" "external IPs → ${ext_count}"
    audit_log_entry "${MACHINE}" "tshark (external IPs)" \
        "tshark -r ${PCAP} -T fields -e ip.src -e ip.dst | RFC1918-filter" \
        "Phase 20 N2: unique external IPs" "${EXT_IPS}" "${ext_count} unique IPs" "0"

    # ── N3. DNS ──────────────────────────────────────────────────────────────
    machine_header "N3: DNS"

    DNS_Q="${OUT_DIR}/dns_queries.csv"
    DNS_NX="${OUT_DIR}/dns_nxdomain.csv"
    DNS_SUS="${OUT_DIR}/dns_suspicious.csv"

    set +e
    echo "Time,SrcIP,QueryName" > "${DNS_Q}"
    "${TSHARK}" -r "${PCAP}" -Y "dns.flags.response==0" \
        -T fields -e frame.time_epoch -e ip.src -e dns.qry.name \
        -E separator=, 2>/dev/null >> "${DNS_Q}"

    echo "Time,SrcIP,QueryName" > "${DNS_NX}"
    "${TSHARK}" -r "${PCAP}" -Y "dns.flags.rcode==3" \
        -T fields -e frame.time_epoch -e ip.src -e dns.qry.name \
        -E separator=, 2>/dev/null >> "${DNS_NX}"
    set -e

    # DGA-ish: long names or high digit ratio
    python3 - "${DNS_Q}" "${DNS_SUS}" <<'PYEOF'
import csv, sys, re
src, dst = sys.argv[1], sys.argv[2]
seen = set()
with open(dst, "w", newline="", encoding="utf-8") as out:
    w = csv.writer(out)
    w.writerow(["QueryName", "Length", "DigitRatio", "Reason"])
    try:
        with open(src, newline="", encoding="utf-8", errors="replace") as fh:
            r = csv.DictReader(fh)
            for row in r:
                q = row.get("QueryName","").strip().lower()
                if not q or q in seen:
                    continue
                seen.add(q)
                # Strip TLD for length analysis (use leftmost label)
                first_label = q.split(".")[0] if "." in q else q
                if len(first_label) < 8:
                    continue
                digits = sum(c.isdigit() for c in first_label)
                ratio = digits / max(len(first_label), 1)
                if len(first_label) >= 25 or ratio >= 0.4:
                    reason = []
                    if len(first_label) >= 25: reason.append("long-label")
                    if ratio >= 0.4: reason.append("digit-heavy")
                    w.writerow([q, len(first_label), f"{ratio:.2f}", "+".join(reason)])
    except FileNotFoundError:
        pass
PYEOF

    nx_count=$(($(wc -l < "${DNS_NX}") - 1))
    sus_count=$(($(wc -l < "${DNS_SUS}") - 1))
    status "OK" "DNS queries=$(($(wc -l < "${DNS_Q}") - 1)) NXDOMAIN=${nx_count} suspicious=${sus_count}"
    audit_log_entry "${MACHINE}" "tshark (DNS)" \
        "tshark -r ${PCAP} DNS triple (queries, NXDOMAIN, DGA-suspicious)" \
        "Phase 20 N3: DNS triage" "${DNS_Q},${DNS_NX},${DNS_SUS}" \
        "queries=$(($(wc -l < "${DNS_Q}") - 1)) NX=${nx_count} sus=${sus_count}" "0"

    # ── N4. HTTP + TLS SNI ───────────────────────────────────────────────────
    machine_header "N4: HTTP + TLS SNI"

    HTTP_REQ="${OUT_DIR}/http_requests.csv"
    HTTP_LARGE="${OUT_DIR}/http_large_responses.csv"
    TLS_SNI="${OUT_DIR}/tls_sni.csv"

    set +e
    echo "Time,SrcIP,DstIP,Host,URI,UserAgent,Status" > "${HTTP_REQ}"
    "${TSHARK}" -r "${PCAP}" -Y "http.request" \
        -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host \
        -e http.request.uri -e http.user_agent -e http.response.code \
        -E separator=, -E quote=d 2>/dev/null >> "${HTTP_REQ}"

    echo "Time,SrcIP,DstIP,ContentLength" > "${HTTP_LARGE}"
    "${TSHARK}" -r "${PCAP}" -Y "http.response and http.content_length > 100000" \
        -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.content_length \
        -E separator=, 2>/dev/null >> "${HTTP_LARGE}"

    echo "Time,SrcIP,DstIP,SNI" > "${TLS_SNI}"
    "${TSHARK}" -r "${PCAP}" -Y "tls.handshake.type==1" \
        -T fields -e frame.time_epoch -e ip.src -e ip.dst \
        -e tls.handshake.extensions_server_name \
        -E separator=, 2>/dev/null >> "${TLS_SNI}"
    set -e

    status "OK" "HTTP req=$(($(wc -l < "${HTTP_REQ}") - 1)) large=$(($(wc -l < "${HTTP_LARGE}") - 1)) SNI=$(($(wc -l < "${TLS_SNI}") - 1))"
    audit_log_entry "${MACHINE}" "tshark (HTTP/TLS)" \
        "tshark -r ${PCAP} HTTP/TLS extraction" \
        "Phase 20 N4: HTTP requests, large responses, TLS SNI" \
        "${HTTP_REQ},${HTTP_LARGE},${TLS_SNI}" "extracted" "0"

    # ── N5. Beacon scoring (TCP SYN intervals per dst IP) ────────────────────
    machine_header "N5: Beacon scoring (interval CV per destination IP)"

    BEACON_CSV="${OUT_DIR}/beacon_scores.csv"
    PY_BEACON=$(mktemp /tmp/beacon_XXXXXX.py)
    cat > "${PY_BEACON}" <<'PYEOF'
#!/usr/bin/env python3
"""Per-dst-IP beacon scoring: low CV of inter-request intervals = beacon."""
import sys, statistics, csv, json, os, ipaddress
from collections import defaultdict

src = sys.argv[1]   # tshark output: dst_ip\ttime
dst = sys.argv[2]
denylist_path = sys.argv[3] if len(sys.argv) > 3 else ""
ioc_master_path = sys.argv[4] if len(sys.argv) > 4 else ""

denylist_ips = set()
denylist_prefixes = []
if denylist_path and os.path.isfile(denylist_path):
    try:
        with open(denylist_path) as fh:
            d = json.load(fh)
        for ip in d.get("ips", []) + d.get("ip_exact", []):
            denylist_ips.add(ip)
        for px in d.get("ip_prefix", []):
            denylist_prefixes.append(px)
    except Exception:
        pass

def is_denylisted(ip):
    if ip in denylist_ips:
        return True
    return any(ip.startswith(px) for px in denylist_prefixes)

def is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
    except ValueError:
        return True

ioc_ips = set()
if ioc_master_path and os.path.isfile(ioc_master_path):
    with open(ioc_master_path, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            t = (row.get("Type") or "").lower()
            v = row.get("Value") or row.get("IOC") or ""
            if t == "ip" and v:
                ioc_ips.add(v.strip())

flows = defaultdict(list)
with open(src, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 2 or not parts[0]:
            continue
        try:
            flows[parts[0]].append(float(parts[1]))
        except ValueError:
            continue

with open(dst, "w", newline="", encoding="utf-8") as out:
    w = csv.writer(out)
    w.writerow(["DstIP", "Connections", "MeanInterval_s", "StdDev_s", "CV", "BeaconScore",
                "Classification", "DenylistFlag", "IOCMatch"])
    for ip, times in sorted(flows.items()):
        if is_internal(ip):
            continue
        if len(times) < 5:
            continue
        times.sort()
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            continue
        mean = statistics.mean(intervals)
        if mean < 1:
            continue
        sd = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv = sd / mean if mean > 0 else 0.0

        # BeaconScore 0-100
        score = 0
        if len(times) >= 10: score += 30
        elif len(times) >= 5: score += 15
        if cv < 0.3: score += 50
        elif cv < 0.5: score += 30
        elif cv < 0.7: score += 15
        if 30 <= mean <= 600: score += 20

        denyflag = "Y" if is_denylisted(ip) else ""
        ioc_match = "Y" if ip in ioc_ips else ""
        if denyflag:
            score = max(0, score - 40)

        if ioc_match:
            cls = "BEACON_IOC_CONFIRMED"
        elif score >= 70:
            cls = "BEACON_LIKELY"
        elif score >= 40:
            cls = "BEACON_POSSIBLE"
        elif denyflag:
            cls = "FILTERED"
        else:
            cls = "NOISE"

        w.writerow([ip, len(times), f"{mean:.1f}", f"{sd:.1f}", f"{cv:.2f}",
                    score, cls, denyflag, ioc_match])
PYEOF

    BEACON_RAW=$(mktemp /tmp/beacon_raw_XXXXXX.tsv)
    set +e
    "${TSHARK}" -r "${PCAP}" \
        -Y "tcp.flags.syn==1 and tcp.flags.ack==0" \
        -T fields -e ip.dst -e frame.time_epoch \
        -E separator=/t 2>/dev/null > "${BEACON_RAW}"

    python3 "${PY_BEACON}" "${BEACON_RAW}" "${BEACON_CSV}" "${DENYLIST_JSON}" "${IOC_MASTER}"
    set -e
    rm -f "${PY_BEACON}" "${BEACON_RAW}"
    beacon_count=$(($(wc -l < "${BEACON_CSV}") - 1))
    likely=$(awk -F, '$7=="BEACON_LIKELY" || $7=="BEACON_IOC_CONFIRMED"' "${BEACON_CSV}" | wc -l)
    status "OK" "Beacon scoring → ${beacon_count} dst IPs scored, ${likely} BEACON_LIKELY/IOC"
    audit_log_entry "${MACHINE}" "beacon_score (PCAP)" \
        "tshark SYN intervals → CV scoring" \
        "Phase 20 N5: per-destination beacon scoring" \
        "${BEACON_CSV}" "${beacon_count} scored, ${likely} likely" "0"

    # ── N6. Zeek (optional) ──────────────────────────────────────────────────
    machine_header "N6: Zeek (optional)"
    if [[ -x "${ZEEK}" ]] || command -v zeek >/dev/null 2>&1; then
        ZK="${ZEEK}"
        [[ -x "${ZK}" ]] || ZK="$(command -v zeek)"
        mkdir -p "${ZEEK_DIR}"
        set +e
        ( cd "${ZEEK_DIR}" && "${ZK}" -r "${PCAP}" LogAscii::use_json=T 2>&1 >/dev/null )
        rc=$?
        set -e
        log_count=$(find "${ZEEK_DIR}" -name "*.log" 2>/dev/null | wc -l)
        status "OK" "Zeek → ${log_count} log files in ${ZEEK_DIR}"
        audit_log_entry "${MACHINE}" "zeek" "${ZK} -r ${PCAP}" \
            "Phase 20 N6: Zeek protocol decode" "${ZEEK_DIR}" "${log_count} logs" "${rc}"
    else
        status "SKIP" "Zeek not installed; set ZEEK= or apt install zeek"
    fi

    # ── N7. PCAP anomaly synthesis ───────────────────────────────────────────
    machine_header "N7: PCAP anomaly synthesis"

    ANOMALIES="${OUT_DIR}/pcap_anomalies.csv"
    PY_ANOM=$(mktemp /tmp/pcap_anom_XXXXXX.py)
    cat > "${PY_ANOM}" <<'PYEOF'
#!/usr/bin/env python3
"""Synthesize PCAP anomalies: beacons + DGA + large outbound + IOC IP matches."""
import csv, os, sys
from collections import Counter

net_dir = sys.argv[1]
out_csv = os.path.join(net_dir, "pcap_anomalies.csv")

def read(name):
    p = os.path.join(net_dir, name)
    if not os.path.isfile(p):
        return []
    with open(p, newline="", encoding="utf-8", errors="replace") as fh:
        return list(csv.DictReader(fh))

beacons = read("beacon_scores.csv")
dns_sus = read("dns_suspicious.csv")
dns_nx = read("dns_nxdomain.csv")
http_large = read("http_large_responses.csv")

anomalies = []  # (severity, category, value, evidence, hypothesis)

for b in beacons:
    cls = b.get("Classification","")
    ip = b.get("DstIP","")
    cv = b.get("CV","?")
    n = b.get("Connections","?")
    score = b.get("BeaconScore","?")
    if cls == "BEACON_IOC_CONFIRMED":
        anomalies.append(("HIGH", "beacon-ioc", ip,
                          f"score={score} cv={cv} connections={n} ioc_match=Y",
                          "C2 beacon to known-IOC IP — confirmed"))
    elif cls == "BEACON_LIKELY":
        anomalies.append(("HIGH", "beacon-likely", ip,
                          f"score={score} cv={cv} connections={n}",
                          "low-variance interval pattern — likely C2 beacon"))
    elif cls == "BEACON_POSSIBLE":
        anomalies.append(("MEDIUM", "beacon-possible", ip,
                          f"score={score} cv={cv} connections={n}",
                          "interval pattern possibly beaconing — review"))

for d in dns_sus:
    anomalies.append(("MEDIUM", "dns-suspicious", d.get("QueryName",""),
                      f"length={d.get('Length','?')} digits={d.get('DigitRatio','?')} reason={d.get('Reason','?')}",
                      "DGA-like DNS query — possible algorithm-generated C2"))

# NXDOMAIN burst per source IP
nx_per_src = Counter(d.get("SrcIP","") for d in dns_nx if d.get("SrcIP"))
for src, count in nx_per_src.items():
    if count >= 50:
        anomalies.append(("MEDIUM", "nxdomain-burst", src,
                          f"{count} NXDOMAIN responses",
                          "high NXDOMAIN volume — possible DGA enumeration or stale C2"))

for h in http_large:
    cl = h.get("ContentLength","?")
    src = h.get("SrcIP","?")
    dst = h.get("DstIP","?")
    anomalies.append(("MEDIUM", "http-large-response", f"{src}→{dst}",
                      f"content_length={cl}",
                      "HTTP response >100KB — possible exfiltration or download"))

with open(out_csv, "w", newline="", encoding="utf-8") as out:
    w = csv.writer(out)
    w.writerow(["Severity", "Category", "Value", "Evidence", "Hypothesis"])
    for row in sorted(anomalies, key=lambda x: ("HIGH MEDIUM LOW".split().index(x[0]), x[1])):
        w.writerow(row)

high = sum(1 for a in anomalies if a[0] == "HIGH")
med  = sum(1 for a in anomalies if a[0] == "MEDIUM")
low  = sum(1 for a in anomalies if a[0] == "LOW")
print(f"  Anomalies → HIGH={high}  MEDIUM={med}  LOW={low}  total={len(anomalies)}")
PYEOF

    set +e
    py_out=$(python3 "${PY_ANOM}" "${OUT_DIR}" 2>&1)
    py_rc=$?
    set -e
    echo "${py_out}"
    audit_log_entry "${MACHINE}" "pcap_anomaly_synth.py" \
        "python3 pcap_anomaly_synth.py ${OUT_DIR}" \
        "Phase 20 N7: synthesize PCAP anomalies (beacons, DGA, large outbound)" \
        "${ANOMALIES}" "${py_out}" "${py_rc}"
    rm -f "${PY_ANOM}"
done

# ─── completion ─────────────────────────────────────────────────────────────

section "Phase 20 — PCAP Triage Complete"
echo "  Output base: ${ANALYSIS_DIR}/<MACHINE>/Network/"
echo "  Completion signal: pcap_anomalies.csv per PCAP"
echo ""
