#!/usr/bin/env python3
"""gen_case_config.py — Auto-generate reports/case_executive.json from the
investigation report and COP (Chain of Proceedings / Case Overview Plan).

Usage: python3 gen_case_config.py <case_root>

Reads:
  <case_root>/reports/investigation_report.md
  <case_root>/analysis/cop.md

Outputs:
  <case_root>/reports/case_executive.json

The JSON structure is the CASE_CONFIG shape consumed by gen_html_package.py.
"""

import sys
import re
import json
from pathlib import Path

PLACEHOLDER = "[ANALYST: provide for customer delivery]"

# ── Severity keyword rules (evaluated in order, first match wins) ──────────────

SEVERITY_RULES = [
    ("CRITICAL", [
        r"ransomware",
        r"domain\s+compromise",
        r"domain\s+admin\s+compromise",
        r"full\s+domain\s+compromise",
        r"active\s+intrusion",
    ]),
    ("HIGH", [
        r"credential\s+access\s+confirmed",
        r"credaccess\s+confirmed",
        r"lateral\s+movement\s+confirmed",
        r"privilege\s+escalation\s+confirmed",
        r"data\s+exfiltration\s+confirmed",
        r"exfiltration\s+confirmed",
        r"c2\s+session\s+confirmed",
        r"c2.*established",
    ]),
    ("MEDIUM", []),  # fall-through default
]

# ── Finding severity mapping ───────────────────────────────────────────────────

FINDING_SEVERITY_KEYWORDS = {
    "CRITICAL": [r"ransomware", r"domain\s+compromise", r"active\s+breach", r"c2.*established"],
    "HIGH":     [r"exfiltrat", r"credential", r"lateral\s+movement", r"privilege\s+escalation",
                 r"backdoor", r"webshell", r"persistence"],
    "MEDIUM":   [r"suspicious", r"anomalous", r"indicator", r"artifact"],
    "LOW":      [],
}

MITRE_PATTERN = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
IPV4_PATTERN  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|gov|mil|edu|xyz|ru|cn|info|biz|co)\b'
)
HASH_PATTERN  = re.compile(r'\b[0-9a-fA-F]{32,64}\b')
PATH_WIN_PATTERN = re.compile(r'[A-Za-z]:\\(?:[^\s,;\|"\'<>]+)')
PATH_UNIX_PATTERN = re.compile(r'(?:^|[\s"])(/(?:[^\s,;\|"\'<>]+))')
UTC_TIME_PATTERN  = re.compile(
    r'\b(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}(?::\d{2})?)?(?:\s*UTC)?)\b'
)


# ─── Text helpers ─────────────────────────────────────────────────────────────

def read_file(path: Path) -> str:
    """Return file contents or empty string if missing."""
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def split_sections(text: str) -> dict:
    """Split markdown into a dict of {heading_text: body_text}.

    Keys are lowercased stripped heading text, including the leading '#' sequence
    so callers can match by section number or keyword.
    """
    sections: dict = {}
    current_key = "__preamble__"
    current_lines: list = []
    for line in text.splitlines():
        m = re.match(r'^(#{1,6})\s+(.*)', line)
        if m:
            sections[current_key] = "\n".join(current_lines).strip()
            current_key = m.group(2).strip()
            current_lines = []
        else:
            current_lines.append(line)
    sections[current_key] = "\n".join(current_lines).strip()
    return sections


def find_section(sections: dict, *patterns) -> str:
    """Return body of first section whose heading matches any of the patterns."""
    for key, body in sections.items():
        for pat in patterns:
            if re.search(pat, key, re.IGNORECASE):
                return body
    return ""


def extract_paragraphs(text: str) -> list:
    """Return non-empty paragraphs (blank-line separated)."""
    return [p.strip() for p in re.split(r'\n{2,}', text) if p.strip()]


def strip_md_inline(text: str) -> str:
    """Remove common inline markdown (bold, italic, code, links)."""
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    # Strip any residual leading asterisks or underscores (unmatched bold/italic)
    text = text.lstrip('*_').rstrip('*_')
    return text.strip()


def parse_md_table(text: str) -> list:
    """Parse a GFM table from text, returning list of dicts keyed by header."""
    rows = []
    lines = [l for l in text.splitlines() if l.strip()]
    # Find first line that looks like a table header
    header_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith('|') and '|' in line[1:]:
            header_idx = i
            break
    if header_idx is None:
        return rows
    headers = [c.strip() for c in lines[header_idx].strip('|').split('|')]
    # Skip separator row (--- lines)
    data_start = header_idx + 1
    if data_start < len(lines) and re.match(r'^[\s\|\-:]+$', lines[data_start]):
        data_start += 1
    for line in lines[data_start:]:
        if not line.strip().startswith('|'):
            break
        cells = [c.strip() for c in line.strip('|').split('|')]
        # Pad or trim to header length
        while len(cells) < len(headers):
            cells.append("")
        row = {headers[j]: cells[j] for j in range(len(headers))}
        rows.append(row)
    return rows


# ─── Field extractors ─────────────────────────────────────────────────────────

def extract_case_name(report_text: str) -> tuple:
    """Return (value, extracted_bool)."""
    m = re.search(r'^#\s+(.+)$', report_text, re.MULTILINE)
    if m:
        return strip_md_inline(m.group(1)), True
    return PLACEHOLDER, False


def extract_case_type(report_text: str, cop_text: str) -> tuple:
    combined = report_text + "\n" + cop_text
    m = re.search(r'[Cc]ase\s+[Tt]ype\s*[:\-–]\s*(.+)', combined)
    if m:
        return strip_md_inline(m.group(1)).strip(), True
    # Fallback: keyword sniff
    lc = combined.lower()
    for kw in ("ransomware", "apt", "bec", "insider threat", "data breach",
               "supply chain", "phishing", "lateral movement", "web intrusion"):
        if kw in lc:
            return kw.title(), True
    return PLACEHOLDER, False


def infer_severity(report_text: str, cop_text: str) -> tuple:
    """Return (severity_string, extracted_bool)."""
    # Gather confirmed-findings sections
    sections_r = split_sections(report_text)
    sections_c = split_sections(cop_text)
    confirmed_body = (
        find_section(sections_r, r"confirmed\s+finding", r"confirmed\s+ioc") +
        find_section(sections_c, r"confirmed\s+finding", r"confirmed\s+ioc")
    )
    search_text = (confirmed_body or (report_text + cop_text)).lower()

    for sev, patterns in SEVERITY_RULES:
        if not patterns:
            continue
        for pat in patterns:
            if re.search(pat, search_text, re.IGNORECASE):
                return sev, True
    return "MEDIUM", False


def extract_date_range(report_text: str) -> tuple:
    """Parse Section 3 (Attack Timeline) for earliest and latest UTC timestamps."""
    sections = split_sections(report_text)
    timeline_body = find_section(sections, r'^3[.\s]', r'attack\s+timeline', r'incident\s+timeline')
    if not timeline_body:
        # Broaden search to any section with timeline in name
        timeline_body = find_section(sections, r'timeline')

    text_to_search = timeline_body if timeline_body else report_text

    # Try to find timestamps from table Time column first
    table_rows = parse_md_table(text_to_search)
    timestamps = []
    for row in table_rows:
        for key in row:
            if re.search(r'\btime\b', key, re.IGNORECASE):
                val = row[key].strip()
                if val:
                    timestamps.append(val)

    if not timestamps:
        # Fall back to regex scan
        raw = UTC_TIME_PATTERN.findall(text_to_search)
        timestamps = [t.strip() for t in raw if len(t.strip()) >= 10]

    def _ensure_utc(ts: str) -> str:
        return ts if re.search(r'\bUTC\b', ts, re.IGNORECASE) else ts + " UTC"

    if len(timestamps) >= 2:
        earliest = _ensure_utc(timestamps[0])
        latest   = _ensure_utc(timestamps[-1])
        return f"{earliest} – {latest}", True
    elif len(timestamps) == 1:
        return _ensure_utc(timestamps[0]), True
    return PLACEHOLDER, False


def extract_analyst(cop_text: str) -> tuple:
    m = re.search(r'[Aa]nalyst\s*[:\-–]\s*(.+)', cop_text)
    if m:
        val = strip_md_inline(m.group(1)).strip()
        if val:
            return val, True
    # Check CLAUDE.md global (this script is standalone, so check env fallback only)
    return PLACEHOLDER, False


def extract_summary(report_text: str) -> tuple:
    """Return (summary_short, summary_paragraphs, extracted_bool)."""
    sections = split_sections(report_text)
    exec_body = find_section(
        sections,
        r'executive\s+summary',
        r'^1[.\s].*executive',
        r'^1[.\s]',
    )
    if not exec_body:
        # Try first substantial content after the H1
        # Use preamble or whatever comes before section 2
        for key, body in sections.items():
            if key == "__preamble__":
                continue
            if body and len(body) > 50:
                exec_body = body
                break

    if exec_body:
        paras = extract_paragraphs(exec_body)
        # Strip table rows and heading lines
        paras = [p for p in paras if not p.startswith('|') and not p.startswith('#')]
        paras = [strip_md_inline(p) for p in paras if len(p) > 20]
        if paras:
            short = paras[0]
            # Truncate to ~2 sentences
            sentences = re.split(r'(?<=[.!?])\s+', short)
            summary_short = " ".join(sentences[:2])
            return summary_short, paras, True

    return PLACEHOLDER, [PLACEHOLDER], False


def extract_findings(cop_text: str, report_text: str) -> tuple:
    """Parse Confirmed Findings table from cop.md; fall back to report."""
    sections_c = split_sections(cop_text)
    sections_r = split_sections(report_text)

    findings_body = find_section(sections_c, r'confirmed\s+finding')
    if not findings_body:
        findings_body = find_section(sections_r, r'confirmed\s+finding')

    rows = parse_md_table(findings_body) if findings_body else []

    findings = []
    for i, row in enumerate(rows, 1):
        # Try to find ID column
        fid = None
        for k in row:
            if re.search(r'\bid\b|^#', k, re.IGNORECASE):
                fid = row[k].strip()
                break
        if not fid:
            fid = f"FND-{i}"
        elif not re.match(r'FND-\d+', fid, re.IGNORECASE):
            fid = f"FND-{i}"

        # Title
        title = ""
        for k in row:
            if re.search(r'find|title|name|description', k, re.IGNORECASE):
                title = strip_md_inline(row[k]).strip()
                if title:
                    break
        if not title:
            # Use first non-ID, non-empty cell
            for k, v in row.items():
                if v.strip() and k.strip().upper() not in ("ID", "#"):
                    title = strip_md_inline(v).strip()
                    break
        if not title:
            title = PLACEHOLDER

        # Description — second distinct text field; empty if only one text column
        description = ""
        text_fields = [strip_md_inline(v).strip() for k, v in row.items()
                       if v.strip() and k.strip().upper() not in ("ID", "#", "SEVERITY",
                                                                   "MITRE", "ATT&CK")]
        # Use the second field only if it differs from the first (avoids title duplicate)
        if len(text_fields) >= 2 and text_fields[1] != text_fields[0]:
            description = text_fields[1]

        # Severity
        sev = ""
        for k in row:
            if re.search(r'sever|priority|risk', k, re.IGNORECASE):
                sev = row[k].strip().upper()
                break
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev = _infer_finding_severity(title + " " + description)

        # MITRE
        mitre = ""
        for k in row:
            if re.search(r'mitre|att.?ck|technique', k, re.IGNORECASE):
                mitre_raw = row[k].strip()
                m = MITRE_PATTERN.search(mitre_raw)
                if m:
                    mitre = m.group()
                break
        if not mitre:
            m = MITRE_PATTERN.search(title + " " + description)
            if m:
                mitre = m.group()

        findings.append({
            "id":          fid,
            "title":       title,
            "severity":    sev,
            "description": description,
            "mitre":       mitre,
        })

    if findings:
        return findings, True

    # No table found — return a single placeholder finding
    return [
        {
            "id":          "FND-1",
            "title":       PLACEHOLDER,
            "severity":    "HIGH",
            "description": PLACEHOLDER,
            "mitre":       "",
        }
    ], False


def _infer_finding_severity(text: str) -> str:
    lc = text.lower()
    for sev, patterns in FINDING_SEVERITY_KEYWORDS.items():
        if not patterns:
            continue
        for pat in patterns:
            if re.search(pat, lc):
                return sev
    return "MEDIUM"


def extract_timeline(report_text: str) -> tuple:
    """Parse Section 3 Attack Timeline table; columns Time + Event."""
    sections = split_sections(report_text)
    tl_body = find_section(
        sections,
        r'^3[.\s].*timeline',
        r'^3[.\s]',
        r'attack\s+timeline',
        r'incident\s+timeline',
    )
    if not tl_body:
        tl_body = find_section(sections, r'timeline')

    rows = parse_md_table(tl_body) if tl_body else []

    timeline = []
    for row in rows:
        time_val  = ""
        event_val = ""
        actor_val = "System"

        for k, v in row.items():
            kl = k.lower()
            if re.search(r'\btime\b|\btimestamp\b', kl):
                time_val = v.strip()
            elif re.search(r'\bevent\b|\baction\b|\bdesc', kl):
                event_val = strip_md_inline(v).strip()
            elif re.search(r'\bactor\b|\bsource\b|\bwho\b', kl):
                actor_val = v.strip()

        if not time_val:
            # Grab first cell as time
            vals = list(row.values())
            if vals:
                time_val = vals[0].strip()
                event_val = strip_md_inline(vals[1]).strip() if len(vals) > 1 else event_val

        if not actor_val or actor_val == "System":
            el = event_val.lower()
            if any(kw in el for kw in ("attacker", "exploit", "c2", "beacon", "meterpreter",
                                        "dropper", "payload", "scan", "brute")):
                actor_val = "Attacker"
            elif any(kw in el for kw in ("user", "admin", "employee", "victim",
                                          "opened", "clicked", "logged")):
                actor_val = "Victim"

        if time_val and event_val:
            # Normalize UTC suffix
            if "utc" not in time_val.lower():
                time_val = time_val + " UTC"
            timeline.append({
                "time":  time_val,
                "event": event_val,
                "actor": actor_val,
            })

    if timeline:
        return timeline, True

    return [{"time": PLACEHOLDER, "event": PLACEHOLDER, "actor": "System"}], False


def extract_iocs(report_text: str) -> tuple:
    """Parse Section 12 IOC table; fall back to regex scan of full report."""
    sections = split_sections(report_text)
    ioc_body = find_section(
        sections,
        r'^12[.\s]',
        r'ioc',
        r'indicator',
    )

    iocs: dict = {"ipv4": [], "domains": [], "hashes": [], "paths": []}

    if ioc_body:
        rows = parse_md_table(ioc_body)
        for row in rows:
            type_val  = ""
            value_val = ""
            for k, v in row.items():
                kl = k.lower()
                if re.search(r'\btype\b|\bcategory\b|\bkind\b', kl):
                    type_val = v.strip().lower()
                elif re.search(r'\bvalue\b|\bioc\b|\bindicator\b|\bdata\b', kl):
                    value_val = v.strip()
            if not value_val:
                vals = list(row.values())
                if vals:
                    value_val = vals[-1].strip() if len(vals) > 1 else vals[0].strip()

            if not value_val:
                continue

            if "ip" in type_val or IPV4_PATTERN.fullmatch(value_val.split('/')[0]):
                if value_val not in iocs["ipv4"]:
                    iocs["ipv4"].append(value_val)
            elif "domain" in type_val or "host" in type_val or "fqdn" in type_val:
                if value_val not in iocs["domains"]:
                    iocs["domains"].append(value_val)
            elif re.search(r'hash|md5|sha', type_val) or re.match(r'^[0-9a-fA-F]{32,64}$', value_val):
                if value_val not in iocs["hashes"]:
                    iocs["hashes"].append(value_val)
            elif re.search(r'path|file|url', type_val) or re.match(r'^[A-Za-z]:\\', value_val) or value_val.startswith('/'):
                if value_val not in iocs["paths"]:
                    iocs["paths"].append(value_val)

    # Supplement with regex scan if tables were sparse
    scan_text = ioc_body if ioc_body else report_text

    for m in IPV4_PATTERN.finditer(scan_text):
        val = m.group()
        # Exclude common non-IOC IPs
        if not re.match(r'^(127\.|0\.0\.|255\.255\.)', val) and val not in iocs["ipv4"]:
            iocs["ipv4"].append(val)

    for m in HASH_PATTERN.finditer(scan_text):
        val = m.group()
        if val not in iocs["hashes"]:
            iocs["hashes"].append(val)

    for m in PATH_WIN_PATTERN.finditer(scan_text):
        val = m.group()
        if val not in iocs["paths"]:
            iocs["paths"].append(val)

    # Deduplicate and sort
    for k in iocs:
        iocs[k] = sorted(set(iocs[k]))

    has_any = any(iocs[k] for k in iocs)
    return iocs, has_any


def extract_recommended_actions(report_text: str, cop_text: str) -> tuple:
    """Parse Section 14/Recommended Actions — extract bullet/numbered points."""
    sections_r = split_sections(report_text)
    sections_c = split_sections(cop_text)

    body = find_section(sections_r, r'^14[.\s]', r'recommended\s+action', r'recommendation')
    if not body:
        body = find_section(sections_c, r'^14[.\s]', r'recommended\s+action', r'recommendation')

    actions = []
    if body:
        for line in body.splitlines():
            line = line.strip()
            # Match bullets: -, *, or numbered list
            m = re.match(r'^[-*•]\s+(.+)$', line) or re.match(r'^\d+[.)]\s+(.+)$', line)
            if m:
                action = strip_md_inline(m.group(1)).strip()
                if action:
                    actions.append(action)

    if actions:
        return actions, True
    return [PLACEHOLDER], False


def extract_workflow_phases(report_text: str, cop_text: str) -> tuple:
    """Parse Section 15/Workflow Coverage — extract phase names."""
    sections_r = split_sections(report_text)
    sections_c = split_sections(cop_text)

    body = find_section(sections_r, r'^15[.\s]', r'workflow\s+coverage', r'workflow\s+phase')
    if not body:
        body = find_section(sections_c, r'^15[.\s]', r'workflow\s+coverage', r'workflow\s+phase')

    phases = []
    if body:
        for line in body.splitlines():
            line = line.strip()
            m = re.match(r'^[-*•]\s+(.+)$', line) or re.match(r'^\d+[.)]\s+(.+)$', line)
            if m:
                phase = strip_md_inline(m.group(1)).strip()
                if phase:
                    phases.append(phase)
        if not phases:
            # Try table: one column of phase names
            rows = parse_md_table(body)
            for row in rows:
                for v in row.values():
                    v = strip_md_inline(v).strip()
                    if v and v not in phases:
                        phases.append(v)
                    break  # first column only

    if phases:
        return phases, True
    return [PLACEHOLDER], False


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <case_root>", file=sys.stderr)
        sys.exit(1)

    case_root = Path(sys.argv[1])
    if not case_root.is_dir():
        print(f"ERROR: {case_root} is not a directory", file=sys.stderr)
        sys.exit(1)

    report_path = case_root / "reports" / "investigation_report.md"
    cop_path    = case_root / "analysis" / "cop.md"
    out_path    = case_root / "reports" / "case_executive.json"

    # ── Read inputs ────────────────────────────────────────────────────────
    report_text = read_file(report_path)
    cop_text    = read_file(cop_path)

    if not report_text:
        print(f"[WARN] investigation_report.md not found at {report_path} — proceeding with empty text")
    if not cop_text:
        print(f"[WARN] cop.md not found at {cop_path} — proceeding with empty text")

    # ── Extract fields ─────────────────────────────────────────────────────
    # Each entry is a (value, extracted_bool) tuple stored under its JSON key.

    _cn   = extract_case_name(report_text)
    _ct   = extract_case_type(report_text, cop_text)
    _sv   = infer_severity(report_text, cop_text)
    _dr   = extract_date_range(report_text)
    _an   = extract_analyst(cop_text)
    _ss, _sp, _sum_ok = extract_summary(report_text)
    _fi   = extract_findings(cop_text, report_text)
    _tl   = extract_timeline(report_text)
    _io   = extract_iocs(report_text)
    _ra   = extract_recommended_actions(report_text, cop_text)
    _wp   = extract_workflow_phases(report_text, cop_text)

    case_name        = _cn[0]
    case_type        = _ct[0]
    severity_val     = _sv[0]
    date_range       = _dr[0]
    analyst          = _an[0]
    summary_short    = _ss
    summary_paragraphs = _sp
    findings         = _fi[0]
    timeline         = _tl[0]
    iocs             = _io[0]
    rec_actions      = _ra[0]
    workflow_phases  = _wp[0]

    # results dict for the extraction report — all (value, bool) tuples
    results = {
        "case_name":           _cn,
        "case_type":           _ct,
        "severity":            _sv,
        "date_range":          _dr,
        "analyst":             _an,
        "summary_short":       (_ss, _sum_ok),
        "summary_paragraphs":  (_sp, _sum_ok),
        "findings":            _fi,
        "timeline":            _tl,
        "iocs":                _io,
        "recommended_actions": _ra,
        "workflow_phases_run": _wp,
    }

    # ── Assemble JSON ──────────────────────────────────────────────────────
    config = {
        "case_name":           case_name,
        "case_type":           case_type,
        "severity":            severity_val,
        "date_range":          date_range,
        "analyst":             analyst,
        "summary_short":       summary_short,
        "summary_paragraphs":  summary_paragraphs,
        "findings":            findings,
        "timeline":            timeline,
        "iocs":                iocs,
        "recommended_actions": rec_actions,
        "workflow_phases_run": workflow_phases,
    }

    # ── Write output ───────────────────────────────────────────────────────
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # ── Extraction summary ─────────────────────────────────────────────────
    FIELD_LABELS = {
        "case_name":           "case_name",
        "case_type":           "case_type",
        "severity":            "severity",
        "date_range":          "date_range",
        "analyst":             "analyst",
        "summary_short":       "summary_short",
        "summary_paragraphs":  "summary_paragraphs",
        "findings":            "findings",
        "timeline":            "timeline",
        "iocs":                "iocs",
        "recommended_actions": "recommended_actions",
        "workflow_phases_run": "workflow_phases_run",
    }

    extracted = []
    placeholders = []
    for field, (val, ok) in results.items():
        label = FIELD_LABELS.get(field, field)
        if ok:
            extracted.append(label)
        else:
            placeholders.append(label)

    print()
    print(f"  Output : {out_path}")
    print()
    print(f"  Extracted ({len(extracted)}/{len(results)}):")
    for f in extracted:
        print(f"    [OK] {f}")
    if placeholders:
        print()
        print(f"  Fell back to placeholder ({len(placeholders)}):")
        for f in placeholders:
            print(f"    [--] {f}  => \"{PLACEHOLDER}\"")

    # Extra stats
    print()
    print(f"  findings count   : {len(findings)}")
    print(f"  timeline entries : {len(timeline)}")
    print(f"  ioc ipv4         : {len(iocs['ipv4'])}")
    print(f"  ioc domains      : {len(iocs['domains'])}")
    print(f"  ioc hashes       : {len(iocs['hashes'])}")
    print(f"  ioc paths        : {len(iocs['paths'])}")
    print()

    sys.exit(0)


if __name__ == "__main__":
    main()
