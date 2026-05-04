#!/usr/bin/env bash
# DAEDALUS:HANDLES win_evtx
# DAEDALUS:DOMAIN lateral_movement
# run_attack_path.sh — Phase 17: Attack Path Graph
#
# Builds a directed attack path graph from lateral movement artifacts
# across all machines in the case.
#
# Inputs (read from analysis/):
#   analysis/hunting_timeline.csv          (Phase 6 — lateral movement events)
#   analysis/credaccess_timeline.csv       (Phase 7 — credential access events)
#   analysis/<MACHINE>/Hunting/*.csv       (per-machine hunting CSVs)
#   analysis/<MACHINE>/EventLogs/*_evtx*.csv
#       — EID 4624 LogonType 3/10 and EID 4648 if present
#
# Outputs:
#   analysis/attack_path.csv              From_Machine, To_Machine, Timestamp_UTC,
#                                          Method, Account, EventID, Source_File
#   analysis/attack_path_summary.md        Human-readable narrative with timestamps
#   analysis/attack_path.mermaid           Mermaid flowchart LR diagram source
#
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

ATTACK_PATH_CSV="${ANALYSIS_DIR}/attack_path.csv"
ATTACK_PATH_MD="${ANALYSIS_DIR}/attack_path_summary.md"
ATTACK_PATH_MERMAID="${ANALYSIS_DIR}/attack_path.mermaid"

# ─── helpers ──────────────────────────────────────────────────────────────────

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

section() { echo ""; echo "════════════════════════════════════════"; echo " $*"; echo "════════════════════════════════════════"; }
status()  { printf "  [%-10s] %s\n" "$1" "$2"; }

# ─── banner ───────────────────────────────────────────────────────────────────

echo "════════════════════════════════════════════════════"
echo " Attack Path Graph — Phase 17"
echo " $(date -u)"
echo " Case : ${CASE_ROOT}"
echo "════════════════════════════════════════════════════"

# ─── skip guard ───────────────────────────────────────────────────────────────

if [[ -f "${ATTACK_PATH_CSV}" ]] && [[ $(wc -l < "${ATTACK_PATH_CSV}" 2>/dev/null) -gt 1 ]]; then
    echo "SKIP — attack_path.csv already exists with data."
    exit 0
fi

mkdir -p "${ANALYSIS_DIR}"

# ─── embedded Python analyzer ─────────────────────────────────────────────────

PY_SCRIPT=$(mktemp /tmp/attack_path_XXXXXX.py)
trap 'rm -f "${PY_SCRIPT}"' EXIT

cat > "${PY_SCRIPT}" << 'PYEOF'
#!/usr/bin/env python3
"""
attack_path_analyzer.py
Build a directed lateral-movement graph from hunting/evtx CSVs.
Usage: python3 <script> <analysis_dir>
"""

import csv
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── constants ─────────────────────────────────────────────────────────────────

LATERAL_KEYWORDS = re.compile(
    r'lateral|psexec|wmi|rdp|remote|pass.the.hash|scheduled.task.remote',
    re.IGNORECASE
)

# Methods inferred by keyword in section/category text
METHOD_MAP = [
    (re.compile(r'psexec',              re.IGNORECASE), "PsExec"),
    (re.compile(r'pass.the.hash|pth',   re.IGNORECASE), "Pass-the-Hash"),
    (re.compile(r'wmi',                 re.IGNORECASE), "WMI"),
    (re.compile(r'rdp|remote.interactive|logontype.*10|type.*10', re.IGNORECASE), "RDP"),
    (re.compile(r'scheduled.task.remote',               re.IGNORECASE), "Scheduled Task Remote"),
    (re.compile(r'network.*logon|logontype.*3|type.*3',  re.IGNORECASE), "Network Logon (Type 3)"),
    (re.compile(r'lateral',             re.IGNORECASE), "Lateral Movement"),
    (re.compile(r'remote',              re.IGNORECASE), "Remote"),
]

# ── helpers ───────────────────────────────────────────────────────────────────

def find_col(headers, *candidates):
    hl = {h.strip().lower(): h for h in headers}
    for c in candidates:
        if c.lower() in hl:
            return hl[c.lower()]
    return None

def norm_machine(name):
    """Strip domain prefix/suffix, upper-case, strip whitespace."""
    if not name:
        return ""
    n = name.strip()
    # strip domain suffix (e.g. MACHINE.domain.local → MACHINE)
    n = n.split(".")[0]
    return n.upper()

def infer_method(text, eid=None, logon_type=None):
    if eid == 4648:
        return "Explicit Credentials (4648)"
    if eid == 4624:
        if logon_type == "10":
            return "RDP (LogonType 10)"
        if logon_type == "3":
            return "Network Logon (LogonType 3)"
    for pattern, label in METHOD_MAP:
        if pattern.search(text):
            return label
    return "Unknown"

def parse_ts(raw):
    """Return a sortable UTC timestamp string; blank on failure."""
    if not raw:
        return ""
    # Try ISO-8601 variants
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",  "%Y-%m-%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S",     "%m/%d/%Y %I:%M:%S %p"):
        try:
            dt = datetime.strptime(raw.strip().rstrip("Z"), fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return raw.strip()

def ts_bucket(ts_str):
    """Return first 19 chars for 60-second dedup window."""
    return ts_str[:16] if ts_str else ""

def get_logon_type(row_text, row):
    """Extract LogonType from row text or extra data fields."""
    for col, val in row.items():
        if "extra" in col.lower() or "payload" in col.lower():
            m = re.search(r'LogonType[:\s"=]+(\d+)', val, re.IGNORECASE)
            if m:
                return m.group(1)
    m = re.search(r'LogonType[:\s"=]+(\d+)', row_text, re.IGNORECASE)
    return m.group(1) if m else None

# ── CSV scanners ──────────────────────────────────────────────────────────────

def extract_from_hunting_csv(csv_path, machine_label):
    """
    Extract lateral movement edges from a hunting timeline CSV or
    per-machine Hunting CSV (Phase 6 output).
    Returns list of edge dicts.
    """
    edges = []
    try:
        with open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                return edges
            h = reader.fieldnames
            time_col    = find_col(h, "TimeCreated", "Time Created", "Timestamp")
            machine_col = find_col(h, "Machine", "ComputerName", "Computer")
            section_col = find_col(h, "Section", "Category", "MapDescription",
                                   "Description", "Channel")
            eid_col     = find_col(h, "EventId", "EventID", "Event Id")
            user_col    = find_col(h, "UserName", "User Name", "Username",
                                   "TargetUserName")
            remote_col  = find_col(h, "RemoteHost", "Remote Host", "IpAddress",
                                   "WorkstationName", "SourceHost", "SourceComputer")

            for row in reader:
                section_val = row.get(section_col, "") if section_col else ""
                eid_raw     = row.get(eid_col, "").strip() if eid_col else ""
                row_text    = " ".join(str(v) for v in row.values())

                try:
                    eid = int(eid_raw) if eid_raw else 0
                except ValueError:
                    eid = 0

                logon_type = get_logon_type(row_text, row) if eid == 4624 else None

                # Decide whether to keep this row
                is_lateral_section = bool(LATERAL_KEYWORDS.search(section_val))
                is_lateral_eid = (
                    (eid == 4624 and logon_type in ("3", "10"))
                    or eid == 4648
                )

                if not (is_lateral_section or is_lateral_eid):
                    continue

                ts_raw   = row.get(time_col, "")   if time_col    else ""
                machine  = row.get(machine_col, "") if machine_col else machine_label
                remote   = row.get(remote_col, "")  if remote_col  else ""
                account  = row.get(user_col, "")    if user_col    else ""

                # 4624/4648 on a machine = someone logged INTO that machine
                # remote_col = source (from_machine); machine = destination (to_machine)
                if eid in (4624, 4648):
                    from_m = norm_machine(remote)   or norm_machine(machine_label)
                    to_m   = norm_machine(machine)  or norm_machine(machine_label)
                else:
                    # hunting category rows: machine is the actor (from)
                    from_m = norm_machine(machine)  or norm_machine(machine_label)
                    to_m   = norm_machine(remote)   or ""

                if not from_m:
                    continue

                method = infer_method(section_val + " " + row_text, eid, logon_type)

                edges.append({
                    "From_Machine":  from_m,
                    "To_Machine":    to_m,
                    "Timestamp_UTC": parse_ts(ts_raw),
                    "Method":        method,
                    "Account":       account,
                    "EventID":       str(eid) if eid else "",
                    "Source_File":   csv_path.name,
                })
    except Exception as e:
        print(f"  [WARN] {csv_path.name}: {e}", file=sys.stderr)
    return edges


def extract_from_evtx_csv(csv_path, machine_label):
    """
    Extract EID 4624 (type 3/10) and EID 4648 rows directly from an
    EvtxECmd output CSV (Phase 3 output).
    Returns list of edge dicts.
    """
    edges = []
    try:
        with open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                return edges
            h = reader.fieldnames
            eid_col    = find_col(h, "EventId", "EventID", "Event Id")
            time_col   = find_col(h, "TimeCreated", "Time Created", "Timestamp")
            comp_col   = find_col(h, "Computer", "ComputerName")
            user_col   = find_col(h, "UserName", "User Name", "Username",
                                  "TargetUserName")
            remote_col = find_col(h, "RemoteHost", "WorkstationName",
                                  "IpAddress", "Remote Host")
            if not eid_col:
                return edges

            for row in reader:
                eid_raw = row.get(eid_col, "").strip()
                try:
                    eid = int(eid_raw)
                except ValueError:
                    continue

                if eid not in (4624, 4648):
                    continue

                row_text   = " ".join(str(v) for v in row.values())
                logon_type = get_logon_type(row_text, row) if eid == 4624 else None

                if eid == 4624 and logon_type not in ("3", "10"):
                    continue

                ts_raw  = row.get(time_col, "")   if time_col   else ""
                machine = row.get(comp_col, "")   if comp_col   else machine_label
                remote  = row.get(remote_col, "") if remote_col else ""
                account = row.get(user_col, "")   if user_col   else ""

                from_m = norm_machine(remote)  or norm_machine(machine_label)
                to_m   = norm_machine(machine) or norm_machine(machine_label)

                if not from_m:
                    continue

                method = infer_method(row_text, eid, logon_type)

                edges.append({
                    "From_Machine":  from_m,
                    "To_Machine":    to_m,
                    "Timestamp_UTC": parse_ts(ts_raw),
                    "Method":        method,
                    "Account":       account,
                    "EventID":       str(eid),
                    "Source_File":   csv_path.name,
                })
    except Exception as e:
        print(f"  [WARN] {csv_path.name}: {e}", file=sys.stderr)
    return edges

# ── deduplication ─────────────────────────────────────────────────────────────

def dedup_edges(edges):
    """
    Deduplicate: same From→To→Method within 60 seconds = same event.
    Keep the earliest timestamp representative.
    """
    seen = {}
    result = []
    for e in sorted(edges, key=lambda x: x["Timestamp_UTC"]):
        key = (
            e["From_Machine"],
            e["To_Machine"],
            e["Method"],
            ts_bucket(e["Timestamp_UTC"]),
        )
        if key not in seen:
            seen[key] = True
            result.append(e)
    return result

# ── output builders ───────────────────────────────────────────────────────────

CSV_FIELDS = ["From_Machine", "To_Machine", "Timestamp_UTC",
              "Method", "Account", "EventID", "Source_File"]

def write_csv(edges, out_path):
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(edges)


def write_summary(edges, out_path):
    lines = [
        "# Attack Path Summary",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]

    if not edges:
        lines += [
            "## Result",
            "",
            "No lateral movement detected in available artifacts",
            "",
        ]
    else:
        lines += [
            f"**Total lateral movement events:** {len(edges)}",
            "",
            "## Lateral Movement Events (chronological)",
            "",
        ]
        for e in sorted(edges, key=lambda x: x["Timestamp_UTC"]):
            ts_disp = e["Timestamp_UTC"]
            # Friendly HH:MM UTC display
            try:
                dt = datetime.strptime(ts_disp, "%Y-%m-%dT%H:%M:%SZ")
                ts_disp = dt.strftime("%H:%M UTC (%Y-%m-%d)")
            except ValueError:
                pass
            from_m   = e["From_Machine"]  or "(unknown)"
            to_m     = e["To_Machine"]    or "(unknown)"
            account  = e["Account"]       or "(unknown account)"
            method   = e["Method"]        or "Unknown"
            eid_disp = f" (EID {e['EventID']})" if e["EventID"] else ""
            lines.append(
                f"- {ts_disp} — **{account}** moved from **{from_m}** "
                f"to **{to_m}** via {method}{eid_disp}"
            )

        # Unique machine nodes
        nodes = sorted({e["From_Machine"] for e in edges} |
                       {e["To_Machine"]   for e in edges if e["To_Machine"]})
        lines += [
            "",
            "## Machines Involved",
            "",
        ]
        for n in nodes:
            lines.append(f"- {n}")

    lines.append("")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def write_mermaid(edges, out_path):
    if not edges:
        content = (
            "flowchart LR\n"
            "    NO_LATERAL_MOVEMENT[\"No lateral movement detected\"]\n"
        )
    else:
        node_ids = {}
        node_lines = []
        edge_lines = []

        # Assign short IDs to machine names
        all_machines = sorted(
            {e["From_Machine"] for e in edges} |
            {e["To_Machine"]   for e in edges if e["To_Machine"]}
        )
        for i, m in enumerate(all_machines):
            nid = f"M{i}"
            node_ids[m] = nid
            # Sanitise label for Mermaid
            label = m.replace('"', "'")
            node_lines.append(f'    {nid}["{label}"]')

        seen_edges = set()
        for e in sorted(edges, key=lambda x: x["Timestamp_UTC"]):
            from_m = e["From_Machine"]
            to_m   = e["To_Machine"]
            if not from_m or not to_m:
                continue
            src = node_ids.get(from_m, from_m)
            dst = node_ids.get(to_m,   to_m)
            method  = e["Method"].replace('"', "'")[:40]
            ts_disp = e["Timestamp_UTC"]
            try:
                dt = datetime.strptime(ts_disp, "%Y-%m-%dT%H:%M:%SZ")
                ts_disp = dt.strftime("%H:%M")
            except ValueError:
                ts_disp = ts_disp[:16]
            label = f"{method}\\n{ts_disp}"
            edge_key = (src, dst, method)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            edge_lines.append(f'    {src} -->|"{label}"| {dst}')

        parts = ["flowchart LR"] + node_lines + edge_lines
        content = "\n".join(parts) + "\n"

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(content)

# ── main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: attack_path_analyzer.py <analysis_dir>", file=sys.stderr)
        sys.exit(1)

    analysis_dir = Path(sys.argv[1])
    if not analysis_dir.is_dir():
        print(f"ERROR: analysis dir not found: {analysis_dir}", file=sys.stderr)
        sys.exit(1)

    all_edges = []

    # ── 1. Cross-machine hunting timeline (Phase 6) ───────────────────────────
    hunting_tl = analysis_dir / "hunting_timeline.csv"
    if hunting_tl.exists():
        print(f"  Scanning {hunting_tl.name} …")
        edges = extract_from_hunting_csv(hunting_tl, "CROSS_MACHINE")
        print(f"    → {len(edges)} lateral movement rows")
        all_edges.extend(edges)

    # ── 2. Credential access timeline (Phase 7) ───────────────────────────────
    cred_tl = analysis_dir / "credaccess_timeline.csv"
    if cred_tl.exists():
        print(f"  Scanning {cred_tl.name} …")
        edges = extract_from_hunting_csv(cred_tl, "CROSS_MACHINE")
        print(f"    → {len(edges)} lateral movement rows")
        all_edges.extend(edges)

    # ── 3. Per-machine Hunting CSVs ───────────────────────────────────────────
    for machine_dir in sorted(analysis_dir.iterdir()):
        if not machine_dir.is_dir():
            continue
        machine = machine_dir.name
        if machine in ("commands.txt",) or "." in machine:
            continue

        hunting_dir = machine_dir / "Hunting"
        if hunting_dir.is_dir():
            for csv_path in sorted(hunting_dir.glob("*.csv")):
                edges = extract_from_hunting_csv(csv_path, machine)
                if edges:
                    print(f"  Scanning {machine}/Hunting/{csv_path.name} → {len(edges)} rows")
                all_edges.extend(edges)

        # ── 4. EventLog CSVs — EID 4624 type 3/10 + 4648 ─────────────────────
        evtlog_dir = machine_dir / "EventLogs"
        if evtlog_dir.is_dir():
            for csv_path in sorted(evtlog_dir.glob("*_evtx*.csv")):
                edges = extract_from_evtx_csv(csv_path, machine)
                if edges:
                    print(f"  Scanning {machine}/EventLogs/{csv_path.name} → {len(edges)} rows")
                all_edges.extend(edges)

    # ── Deduplicate ───────────────────────────────────────────────────────────
    deduped = dedup_edges(all_edges)
    print(f"  Total edges before dedup : {len(all_edges)}")
    print(f"  Total edges after  dedup : {len(deduped)}")

    # ── Write outputs ─────────────────────────────────────────────────────────
    csv_out     = analysis_dir / "attack_path.csv"
    md_out      = analysis_dir / "attack_path_summary.md"
    mermaid_out = analysis_dir / "attack_path.mermaid"

    write_csv(deduped,      csv_out)
    write_summary(deduped,  md_out)
    write_mermaid(deduped,  mermaid_out)

    print(f"  attack_path.csv     → {csv_out}")
    print(f"  attack_path_summary.md → {md_out}")
    print(f"  attack_path.mermaid → {mermaid_out}")

    if deduped:
        # Print machine-level edge summary
        from_counts = {}
        for e in deduped:
            k = (e["From_Machine"], e["To_Machine"])
            from_counts[k] = from_counts.get(k, 0) + 1
        print("")
        print("  Attack path edges:")
        for (f, t), cnt in sorted(from_counts.items(), key=lambda x: -x[1]):
            print(f"    {f:<20s} → {t:<20s}  ({cnt} event(s))")
    else:
        print("  No lateral movement detected in available artifacts")

if __name__ == "__main__":
    main()
PYEOF

# ─── run the analyzer ─────────────────────────────────────────────────────────

section "Building Attack Path Graph"

cmd="python3 '${PY_SCRIPT}' '${ANALYSIS_DIR}'"
tool_out=$(run_tool "${cmd}") && rc=0 || rc=$?
echo "${tool_out}" | sed 's/^/  /'

if [[ ${rc} -ne 0 ]]; then
    status "ERROR" "Attack path analyzer exited ${rc}"
    exit ${rc}
fi

# Count output rows (minus header)
edge_count=0
if [[ -f "${ATTACK_PATH_CSV}" ]]; then
    edge_count=$(( $(wc -l < "${ATTACK_PATH_CSV}") - 1 ))
fi

if [[ ${edge_count} -gt 0 ]]; then
    status "OK" "${edge_count} lateral movement edge(s) written to attack_path.csv"
else
    status "OK" "No lateral movement found — empty graph written"
fi

log_cmd "ALL_MACHINES" "attack_path_analyzer.py (Phase 17)" \
    "${cmd}" \
    "Build directed attack path graph from EID 4624 (type 3/10), 4648, and hunting timeline lateral movement rows across all machines" \
    "${ATTACK_PATH_CSV}  ${ATTACK_PATH_MD}  ${ATTACK_PATH_MERMAID}" \
    "${edge_count} unique lateral movement edges"

# ─── summary ──────────────────────────────────────────────────────────────────

section "Attack Path Outputs"

echo "  attack_path.csv         : ${ATTACK_PATH_CSV}"
echo "  attack_path_summary.md  : ${ATTACK_PATH_MD}"
echo "  attack_path.mermaid     : ${ATTACK_PATH_MERMAID}"
echo ""

if [[ ${edge_count} -gt 0 ]]; then
    echo "  Lateral movement edges  : ${edge_count}"
    echo ""
    echo "  From Machine          → To Machine             Events"
    echo "  ─────────────────────────────────────────────────────"
    # Print From→To counts from the CSV (skip header)
    tail -n +2 "${ATTACK_PATH_CSV}" \
        | awk -F',' 'NF>=2{print $1","$2}' \
        | sort \
        | uniq -c \
        | sort -rn \
        | awk '{
            cnt=$1
            split($2,a,",")
            printf "  %-20s → %-20s  %d\n", a[1], a[2], cnt
          }'
else
    echo "  No lateral movement detected in available artifacts"
fi

echo ""
echo "════════════════════════════════════════════════════"
echo " Done — Phase 17 complete"
echo "════════════════════════════════════════════════════"
