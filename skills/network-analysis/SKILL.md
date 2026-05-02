# Skill: Network Analysis (PCAP / Zeek / Netflow)

## Overview
Use this skill when PCAP, pcapng, Zeek logs, or netflow records are available. The tools
run first — they produce ground truth. The LLM reads the output, identifies suspicious
patterns, and follows threads (suspicious IP → memory netscan cross-ref, extracted file →
malware-analysis, C2 URI → yara-hunting) until each finding is resolved or escalated.

**Invoke this skill when the IC identifies a network evidence source, or when any other
skill produces an IP, domain, or URI that needs network-level validation.**

---

## Tool Inventory

| Tool | Binary | Purpose |
|------|--------|---------|
| capinfos | `capinfos` | PCAP metadata: time range, packet count, data volume |
| tshark | `tshark` | Wireshark CLI — filtering, field extraction, statistics |
| Zeek | `zeek` | Full protocol dissection → structured logs (conn, dns, http, ssl, files) |
| tcpflow | `tcpflow` | Reconstruct TCP streams to disk for content inspection |
| NetworkMiner | `mono /opt/NetworkMiner*/NetworkMiner.exe` | Passive file extraction, host profiling |
| ngrep | `ngrep` | Grep-style search over packet payloads |
| strings | `strings` | Extract printable strings from raw PCAP or extracted files |

---

## Execution Workflow

### Step 1 — PCAP orientation

```bash
mkdir -p ./analysis/network ./exports/network

# What is in this capture?
capinfos <capture.pcap> | tee ./analysis/network/pcap_info.txt

# Protocol hierarchy
tshark -r <capture.pcap> -z io,phs -q | tee ./analysis/network/protocol_hierarchy.txt

# Time range of capture
tshark -r <capture.pcap> -T fields -e frame.time_epoch | \
  sort -n | awk 'NR==1{print "First:", $0} END{print "Last:", $0}'
```

### Step 2 — Top talkers and conversation map

```bash
# IP conversations (volume-ranked)
tshark -r <capture.pcap> -z conv,ip -q | sort -k5 -rn | head -30 \
  | tee ./analysis/network/top_talkers.txt

# Unique external IPs (exclude RFC1918 + loopback)
tshark -r <capture.pcap> -T fields -e ip.src -e ip.dst \
  | tr '\t' '\n' | sort -u \
  | grep -Ev '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|$)' \
  > ./analysis/network/external_ips.txt

echo "Unique external IPs: $(wc -l < ./analysis/network/external_ips.txt)"
```

### Step 3 — DNS analysis

```bash
# All DNS queries (unique, sorted by query name)
tshark -r <capture.pcap> -Y "dns.flags.response==0" \
  -T fields -e frame.time -e ip.src -e dns.qry.name \
  | sort -k3 -u | tee ./analysis/network/dns_queries.txt

# Failed DNS (NXDOMAIN) — DGA or deleted C2 infrastructure
tshark -r <capture.pcap> -Y "dns.flags.rcode==3" \
  -T fields -e frame.time -e ip.src -e dns.qry.name \
  | tee ./analysis/network/dns_nxdomain.txt

# Long or high-entropy domain names (DGA indicator)
awk '{print $3}' ./analysis/network/dns_queries.txt \
  | awk 'length($0) > 30 || gsub(/[0-9]/,"",$0)/length($0) > 0.4' \
  | sort -u | tee ./analysis/network/dns_suspicious.txt
```

### Step 4 — HTTP / HTTPS traffic

```bash
# HTTP requests — URI, user-agent, response code, bytes
tshark -r <capture.pcap> -Y http.request \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.host \
  -e http.request.uri -e http.user_agent -e http.response.code \
  | tee ./analysis/network/http_requests.txt

# HTTP responses with large bodies (exfiltration)
tshark -r <capture.pcap> -Y "http.response and http.content_length > 100000" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.content_length \
  | tee ./analysis/network/http_large_responses.txt

# Extract files transferred over HTTP
tshark -r <capture.pcap> --export-objects http,./exports/network/http_objects/ 2>/dev/null
echo "HTTP objects extracted: $(ls ./exports/network/http_objects/ 2>/dev/null | wc -l)"

# TLS SNI (server names even in encrypted traffic)
tshark -r <capture.pcap> -Y tls.handshake.type==1 \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  | tee ./analysis/network/tls_sni.txt
```

### Step 5 — Beaconing detection

```bash
# Connection intervals per destination IP (look for regular intervals = beaconing)
tshark -r <capture.pcap> -T fields -e frame.time_epoch -e ip.dst \
  | awk '{print $2, $1}' | sort | \
python3 - <<'EOF'
import sys, statistics
from collections import defaultdict

flows = defaultdict(list)
for line in sys.stdin:
    parts = line.strip().split()
    if len(parts) == 2:
        flows[parts[0]].append(float(parts[1]))

print(f"{'DestIP':<18} {'Connections':>11} {'Mean interval':>14} {'StdDev':>8} {'CV':>6}")
for ip, times in sorted(flows.items()):
    if len(times) < 5:
        continue
    times.sort()
    intervals = [times[i+1]-times[i] for i in range(len(times)-1)]
    if not intervals:
        continue
    mean = statistics.mean(intervals)
    if mean < 1:
        continue
    sd = statistics.stdev(intervals) if len(intervals) > 1 else 0
    cv = sd / mean if mean > 0 else 0
    if cv < 0.5 and len(times) >= 10:  # low variance = regular = beaconing
        print(f"{ip:<18} {len(times):>11} {mean:>14.1f}s {sd:>8.1f}s {cv:>6.2f}  *** BEACON CANDIDATE")
    else:
        print(f"{ip:<18} {len(times):>11} {mean:>14.1f}s {sd:>8.1f}s {cv:>6.2f}")
EOF
tee ./analysis/network/beacon_candidates.txt
```

### Step 6 — Zeek full protocol analysis (if Zeek available)

```bash
mkdir -p ./exports/network/zeek
cd ./exports/network/zeek

# Run Zeek against the PCAP
zeek -r /full/path/to/<capture.pcap> LogAscii::use_json=T 2>/dev/null

cd -

# Top destination IPs by connection count
jq -r '.["id.resp_h"]' ./exports/network/zeek/conn.log 2>/dev/null | \
  sort | uniq -c | sort -rn | head -20 | tee ./analysis/network/zeek_top_dests.txt

# Long-duration connections (tunnels, C2 keep-alive)
jq -r 'select(.duration > 300) | [.ts, .["id.orig_h"], .["id.resp_h"],
  .["id.resp_p"], .duration, .orig_bytes, .resp_bytes] | @csv' \
  ./exports/network/zeek/conn.log 2>/dev/null \
  | tee ./analysis/network/zeek_long_conns.txt

# DNS answers mapping name → IP
jq -r '[.ts, .["id.orig_h"], .query, (.answers // [] | join(","))] | @csv' \
  ./exports/network/zeek/dns.log 2>/dev/null \
  | tee ./analysis/network/zeek_dns.txt

# HTTP with suspicious user-agents
jq -r 'select(.user_agent | test("curl|python|powershell|wget|go-http|libwww"; "i")) |
  [.ts, .["id.orig_h"], .["id.resp_h"], .host, .uri, .user_agent, .status_code] | @csv' \
  ./exports/network/zeek/http.log 2>/dev/null \
  | tee ./analysis/network/zeek_suspicious_ua.txt

# SSL/TLS — JA3 fingerprints for threat intelligence pivot
jq -r '[.ts, .["id.orig_h"], .["id.resp_h"], .server_name, .ja3, .ja3s] | @csv' \
  ./exports/network/zeek/ssl.log 2>/dev/null \
  | tee ./analysis/network/zeek_tls.txt

# Files transferred (Zeek extracts metadata for all file transfers)
jq -r '[.ts, .["tx_hosts"][0], .["rx_hosts"][0], .mime_type, .filename, .md5, .sha256] | @csv' \
  ./exports/network/zeek/files.log 2>/dev/null \
  | tee ./analysis/network/zeek_files.txt
```

### Step 7 — Credential exposure (cleartext protocols)

```bash
# FTP credentials
tshark -r <capture.pcap> -Y "ftp.request.command == \"USER\" or ftp.request.command == \"PASS\"" \
  -T fields -e frame.time -e ip.src -e ip.dst -e ftp.request.arg \
  | tee ./analysis/network/ftp_creds.txt

# HTTP Basic auth (base64-encoded in Authorization header)
tshark -r <capture.pcap> -Y "http.authorization" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.authorization \
  | while IFS=$'\t' read -r ts src dst auth; do
      decoded=$(echo "$auth" | sed 's/Basic //' | base64 -d 2>/dev/null)
      echo "$ts  $src→$dst  $auth  ($decoded)"
    done | tee ./analysis/network/http_basic_auth.txt

# SMTP credentials
tshark -r <capture.pcap> -Y "smtp.req.parameter" \
  -T fields -e frame.time -e ip.src -e ip.dst -e smtp.req.command -e smtp.req.parameter \
  | tee ./analysis/network/smtp_auth.txt
```

---

## Finding Recognition — What Is Suspicious

| Pattern | Indicator | Severity |
|---------|-----------|----------|
| CV < 0.3 with ≥10 connections to same external IP | Beaconing / C2 | High |
| HTTP GET with `curl`, `python-requests`, `go-http` UA | Automated tool / C2 | High |
| DNS query for domain > 30 chars or >40% digits | DGA (domain generation algorithm) | High |
| Large outbound HTTP POST to external IP | Data exfiltration | High |
| Repeated NXDOMAIN for similar-pattern domains | DGA C2 infrastructure | Medium |
| HTTP file download with PE/ELF MIME type from external | Malware delivery | High |
| Long-duration TCP connection (>5 min) to external port | Tunnel or C2 keep-alive | Medium |
| TLS to non-standard port (not 443/8443) | C2 over non-standard TLS | Medium |
| Base64-encoded credentials in HTTP auth | Cleartext credential exposure | Medium |
| DNS TXT record queries | DNS tunneling or C2 | Medium |
| Outbound SMB/445 to external IP | Lateral movement or data exfil | High |

---

## In-Skill Pivot Protocol

When a finding is detected, follow the thread before escalating to the IC:

| Finding | Follow-up action within this skill |
|---------|------------------------------------|
| Beacon candidate IP | Cross-ref against `./analysis/network/external_ips.txt`; check if same IP in Zeek ssl.log JA3; extract all URIs to that IP |
| HTTP object extracted | Run `file` + `sha256sum` on every extracted object; if PE/ELF → hand to malware-analysis |
| DGA domain candidate | Check DNS answers for resolved IPs; add those IPs to IOC master |
| Long TLS connection | Extract JA3 fingerprint; check Zeek files.log for transferred objects |
| Cleartext credential | Note account name + password; flag for credential access section in COP |
| Large outbound POST | Inspect payload with tcpflow; note destination IP + byte volume for exfil estimate |

---

## Escalation to IC (cross-skill pivots)

These findings leave network-analysis and require another skill:

| Finding | IC pivot |
|---------|---------|
| Confirmed C2 IP or domain | Add to IOC master; IC cross-refs with memory-analysis netscan |
| Extracted executable file | IC tasks malware-analysis with the file path |
| Known-bad JA3 fingerprint | IC adds JA3 hash to IOC master; look up against abuse.ch JA3 feeds for known malware family; if family identified, IC tasks yara-hunting for that family's file signatures on disk |
| Credential in cleartext | IC updates COP under Credential Access findings |
| New external IP not in IOC master | IC cross-refs against cloud-forensics CloudTrail if hybrid environment |

---

## Output Paths

| Output | Path |
|--------|------|
| PCAP metadata | `./analysis/network/pcap_info.txt` |
| Top talkers | `./analysis/network/top_talkers.txt` |
| External IPs | `./analysis/network/external_ips.txt` |
| DNS queries / NXDOMAIN | `./analysis/network/dns_queries.txt`, `dns_nxdomain.txt` |
| HTTP requests / large responses | `./analysis/network/http_requests.txt` |
| HTTP objects (extracted files) | `./exports/network/http_objects/` |
| Beacon candidates | `./analysis/network/beacon_candidates.txt` |
| Zeek logs (raw) | `./exports/network/zeek/` |
| Zeek summaries | `./analysis/network/zeek_*.txt` |
| Credential exposure | `./analysis/network/ftp_creds.txt`, `http_basic_auth.txt`, `smtp_auth.txt` |

---

## Notes

- Zeek produces far richer output than tshark filtering alone — run it whenever a PCAP is available
- Beaconing CV threshold of 0.3 is conservative; some legitimate software beacons. Cross-ref with process name from memory-analysis before declaring C2
- JA3 fingerprints can be looked up against threat intel databases (abuse.ch JA3 feeds)
- `tcpflow` reconstructs streams to files — useful for reading C2 command/response content
- Encrypted traffic (TLS 1.3) limits payload inspection; rely on JA3, SNI, and behavioral patterns
