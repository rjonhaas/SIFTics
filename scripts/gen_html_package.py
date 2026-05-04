#!/usr/bin/env python3
"""gen_html_package.py — Generate a self-contained browsable HTML case package.

Reads CSVs from <case_root>/analysis/ and the investigation report from
<case_root>/reports/ and generates a navigable HTML site under
<case_root>/reports/html/.

Usage: python3 gen_html_package.py <case_root>
"""

import sys
import os
import csv
import shutil
import subprocess
import re
import html as _h
from pathlib import Path
from datetime import datetime, timezone

MAX_EMBED_ROWS = 5000   # embed all rows up to this; truncate larger files

# ─── CSS ──────────────────────────────────────────────────────────────────────

CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    background: #f0f2f5;
    color: #1d2433;
    display: flex;
    flex-direction: column;
    min-height: 100vh;
}

/* ── Header ── */
header {
    background: #0f1923;
    color: #e8edf4;
    padding: 14px 24px;
    display: flex;
    align-items: center;
    gap: 18px;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: 0 2px 8px rgba(0,0,0,.4);
}
header .badge {
    background: #00b4d8;
    color: #0f1923;
    font-weight: 700;
    font-size: 11px;
    letter-spacing: .05em;
    padding: 3px 8px;
    border-radius: 3px;
    text-transform: uppercase;
}
header h1 { font-size: 17px; font-weight: 600; letter-spacing: .02em; }
header .sub { font-size: 12px; color: #8a9bb5; margin-left: auto; }

/* ── Layout ── */
.layout { display: flex; flex: 1; min-height: 0; }

/* ── Sidebar ── */
nav.sidebar {
    width: 260px;
    min-width: 220px;
    background: #1a2535;
    color: #c5cfe0;
    padding: 16px 0;
    overflow-y: auto;
    position: sticky;
    top: 49px;
    height: calc(100vh - 49px);
    flex-shrink: 0;
}
nav.sidebar .nav-title {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: #5a7095;
    padding: 8px 16px 4px;
}
nav.sidebar ul { list-style: none; }
nav.sidebar li a {
    display: block;
    padding: 5px 16px 5px 24px;
    color: #a8b9d0;
    text-decoration: none;
    font-size: 12.5px;
    line-height: 1.5;
    border-left: 3px solid transparent;
    transition: background .12s, color .12s;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
nav.sidebar li a:hover,
nav.sidebar li a.active {
    background: rgba(0,180,216,.08);
    color: #00b4d8;
    border-left-color: #00b4d8;
}
nav.sidebar .nav-group > a {
    padding-left: 16px;
    font-weight: 600;
    color: #c5cfe0;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .04em;
}
nav.sidebar .nav-group ul { display: none; }
nav.sidebar .nav-group.open ul { display: block; }
nav.sidebar .nav-group > a::before { content: "▶ "; font-size: 9px; }
nav.sidebar .nav-group.open > a::before { content: "▼ "; }

/* ── Main content ── */
main {
    flex: 1;
    padding: 24px 28px;
    overflow-x: auto;
    max-width: 100%;
}

/* ── Cards ── */
.card {
    background: #fff;
    border-radius: 6px;
    box-shadow: 0 1px 4px rgba(0,0,0,.08);
    padding: 20px 24px;
    margin-bottom: 20px;
}
.card h2 {
    font-size: 15px;
    font-weight: 600;
    color: #0f1923;
    margin-bottom: 14px;
    padding-bottom: 10px;
    border-bottom: 1px solid #e8edf4;
}
.card h3 {
    font-size: 13px;
    font-weight: 600;
    color: #374151;
    margin: 16px 0 8px;
}

/* ── Stat tiles ── */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 14px;
    margin-bottom: 20px;
}
.stat-tile {
    background: #fff;
    border-radius: 6px;
    box-shadow: 0 1px 4px rgba(0,0,0,.08);
    padding: 16px;
    text-align: center;
    border-top: 3px solid #00b4d8;
}
.stat-tile .val {
    font-size: 26px;
    font-weight: 700;
    color: #0f1923;
    line-height: 1;
}
.stat-tile .lbl { font-size: 11px; color: #6b7280; margin-top: 4px; }

/* ── Table controls ── */
.tbl-controls {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 10px;
    flex-wrap: wrap;
}
.tbl-controls input[type=search] {
    padding: 6px 12px;
    border: 1px solid #d1d5db;
    border-radius: 4px;
    font-size: 13px;
    width: 260px;
    outline: none;
}
.tbl-controls input[type=search]:focus { border-color: #00b4d8; }
.tbl-controls .row-info { font-size: 12px; color: #6b7280; margin-left: auto; }
.tbl-controls select {
    padding: 5px 10px;
    border: 1px solid #d1d5db;
    border-radius: 4px;
    font-size: 12px;
    background: #fff;
    cursor: pointer;
}
.notice {
    background: #fef3c7;
    border-left: 4px solid #f59e0b;
    padding: 8px 14px;
    font-size: 12px;
    color: #92400e;
    margin-bottom: 10px;
    border-radius: 0 4px 4px 0;
}

/* ── Data table ── */
.tbl-wrap { overflow-x: auto; }
table.data-tbl {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
    white-space: nowrap;
}
table.data-tbl thead th {
    background: #1a2535;
    color: #c5cfe0;
    padding: 8px 12px;
    text-align: left;
    font-weight: 600;
    cursor: pointer;
    user-select: none;
    position: sticky;
    top: 0;
}
table.data-tbl thead th:hover { background: #243347; color: #00b4d8; }
table.data-tbl thead th.asc::after  { content: " ▲"; font-size: 10px; }
table.data-tbl thead th.desc::after { content: " ▼"; font-size: 10px; }
table.data-tbl tbody tr:nth-child(even) { background: #f8fafc; }
table.data-tbl tbody tr:hover { background: #e8f4ff; }
table.data-tbl td {
    padding: 6px 12px;
    border-bottom: 1px solid #e8edf4;
    max-width: 380px;
    overflow: hidden;
    text-overflow: ellipsis;
    vertical-align: top;
    white-space: nowrap;
}
table.data-tbl td.wrap {
    white-space: normal;
    word-break: break-all;
    max-width: 340px;
}

/* ── Pagination ── */
.pagination {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-top: 10px;
    font-size: 12px;
}
.pagination button {
    padding: 4px 10px;
    border: 1px solid #d1d5db;
    border-radius: 3px;
    background: #fff;
    cursor: pointer;
    font-size: 12px;
}
.pagination button:hover:not(:disabled) { background: #e8f4ff; border-color: #00b4d8; }
.pagination button:disabled { opacity: .4; cursor: default; }
.pagination .page-info { color: #6b7280; }

/* ── Report content ── */
.report-body h1 { font-size: 22px; margin: 24px 0 12px; color: #0f1923; }
.report-body h2 { font-size: 17px; margin: 20px 0 10px; color: #1a2535; border-bottom: 1px solid #e8edf4; padding-bottom: 6px; }
.report-body h3 { font-size: 14px; margin: 16px 0 8px; color: #374151; }
.report-body h4 { font-size: 13px; margin: 12px 0 6px; }
.report-body p  { margin-bottom: 10px; line-height: 1.6; }
.report-body ul, .report-body ol { margin: 8px 0 10px 24px; }
.report-body li { margin-bottom: 4px; line-height: 1.5; }
.report-body code {
    background: #f1f5f9;
    padding: 1px 5px;
    border-radius: 3px;
    font-family: 'SF Mono', 'Cascadia Code', Consolas, monospace;
    font-size: 12px;
}
.report-body pre {
    background: #1a2535;
    color: #c5cfe0;
    padding: 14px 18px;
    border-radius: 5px;
    overflow-x: auto;
    margin-bottom: 12px;
}
.report-body pre code { background: none; padding: 0; color: inherit; font-size: 12.5px; }
.report-body table { border-collapse: collapse; width: 100%; margin-bottom: 14px; font-size: 12.5px; }
.report-body table th {
    background: #1a2535;
    color: #c5cfe0;
    padding: 7px 12px;
    text-align: left;
    font-weight: 600;
}
.report-body table td {
    padding: 6px 12px;
    border-bottom: 1px solid #e8edf4;
}
.report-body table tr:nth-child(even) { background: #f8fafc; }
.report-body blockquote {
    border-left: 4px solid #00b4d8;
    padding: 8px 16px;
    background: #f0f9ff;
    margin-bottom: 10px;
    font-style: italic;
    color: #374151;
}
.report-body hr { border: none; border-top: 1px solid #e8edf4; margin: 20px 0; }
.report-body del { color: #9ca3af; }
.report-body strong { font-weight: 700; }

/* ── Footer ── */
footer {
    background: #0f1923;
    color: #5a7095;
    font-size: 11px;
    padding: 10px 24px;
    text-align: center;
}
"""

# ─── JavaScript ───────────────────────────────────────────────────────────────

JS = r"""
// ── Nav accordion ──────────────────────────────────────────────────────────
document.querySelectorAll('.nav-group > a').forEach(link => {
    link.addEventListener('click', e => {
        e.preventDefault();
        link.closest('.nav-group').classList.toggle('open');
    });
});

// Auto-open group containing active link
document.querySelectorAll('nav.sidebar li a.active').forEach(a => {
    const grp = a.closest('.nav-group');
    if (grp) grp.classList.add('open');
});

// ── Table engine ───────────────────────────────────────────────────────────
(function() {
    const tables = document.querySelectorAll('table.data-tbl');
    tables.forEach(tbl => {
        const tbody = tbl.querySelector('tbody');
        if (!tbody) return;
        const allRows = Array.from(tbody.querySelectorAll('tr'));
        let filtered = allRows.slice();
        let sortCol = -1, sortAsc = true, page = 1, pageSize = 100;

        const wrap = tbl.closest('.tbl-section') || tbl.parentElement;
        const searchEl  = wrap.querySelector('input[type=search]');
        const sizeEl    = wrap.querySelector('select.page-size');
        const infoEl    = wrap.querySelector('.row-info');
        const prevBtn   = wrap.querySelector('.prev-btn');
        const nextBtn   = wrap.querySelector('.next-btn');
        const pageInfoEl = wrap.querySelector('.page-info');

        function render() {
            tbody.innerHTML = '';
            const start = (page - 1) * pageSize;
            const end   = Math.min(start + pageSize, filtered.length);
            for (let i = start; i < end; i++) tbody.appendChild(filtered[i]);
            if (infoEl)    infoEl.textContent = `${filtered.length.toLocaleString()} row${filtered.length!==1?'s':''} (of ${allRows.length.toLocaleString()})`;
            if (prevBtn)   prevBtn.disabled = (page <= 1);
            if (nextBtn)   nextBtn.disabled = (end >= filtered.length);
            if (pageInfoEl) pageInfoEl.textContent = `Page ${page} of ${Math.max(1, Math.ceil(filtered.length/pageSize))}`;
        }

        function applyFilter() {
            const q = searchEl ? searchEl.value.toLowerCase() : '';
            filtered = q ? allRows.filter(r => r.textContent.toLowerCase().includes(q)) : allRows.slice();
            page = 1;
            applySort(false);
            render();
        }

        function applySort(rerender=true) {
            if (sortCol < 0) { if(rerender) render(); return; }
            filtered.sort((a, b) => {
                const av = a.cells[sortCol]?.textContent||'';
                const bv = b.cells[sortCol]?.textContent||'';
                const n  = parseFloat(av) - parseFloat(bv);
                const cmp = isNaN(n) ? av.localeCompare(bv, undefined, {numeric:true}) : n;
                return sortAsc ? cmp : -cmp;
            });
            if(rerender) render();
        }

        // Column sort
        tbl.querySelectorAll('thead th').forEach((th, i) => {
            th.addEventListener('click', () => {
                if (sortCol === i) { sortAsc = !sortAsc; }
                else { sortCol = i; sortAsc = true; }
                tbl.querySelectorAll('thead th').forEach(t => t.classList.remove('asc','desc'));
                th.classList.add(sortAsc ? 'asc' : 'desc');
                page = 1;
                applySort();
            });
        });

        if (searchEl) searchEl.addEventListener('input', applyFilter);
        if (sizeEl) sizeEl.addEventListener('change', () => { pageSize = parseInt(sizeEl.value)||100; page=1; render(); });
        if (prevBtn) prevBtn.addEventListener('click', () => { if(page>1){page--;render();} });
        if (nextBtn) nextBtn.addEventListener('click', () => { const maxPg=Math.ceil(filtered.length/pageSize); if(page<maxPg){page++;render();} });

        render();
    });
})();
"""

# ─── HTML template helpers ─────────────────────────────────────────────────────

def page(title, content, nav_html, active_href="", case_name="", generated=""):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_h.escape(title)} — {_h.escape(case_name)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <div class="badge">DFIR</div>
  <h1>{_h.escape(case_name)}</h1>
  <div class="sub">Generated {_h.escape(generated)} UTC</div>
</header>
<div class="layout">
  {nav_html}
  <main>{content}</main>
</div>
<footer>defcon2019_dfir Case Package &mdash; SIFT Workstation &mdash; FOR AUTHORIZED USE ONLY</footer>
<script>{JS}</script>
</body>
</html>"""


def table_page_content(csv_path, machine, rel_name, truncated_at=None):
    """Render CSV rows as an HTML table with search/sort/pagination."""
    rows = []
    headers = []
    try:
        with open(csv_path, newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            headers = next(reader, [])
            for i, row in enumerate(reader):
                if i >= MAX_EMBED_ROWS:
                    truncated_at = i + 1
                    break
                rows.append(row)
    except Exception as e:
        return f'<div class="card"><p style="color:red">Error reading CSV: {_h.escape(str(e))}</p></div>'

    total_embedded = len(rows)
    notice = ""
    if truncated_at:
        notice = f'<div class="notice">⚠ Large file — showing first {total_embedded:,} rows of {truncated_at:,}+ total rows. Download the CSV for full data.</div>'

    th_html = "".join(f"<th>{_h.escape(h)}</th>" for h in headers)
    td_rows = []
    for row in rows:
        cells = "".join(
            f'<td title="{_h.escape(c)}">{_h.escape(c[:200])}</td>'
            for c in (row + [""] * max(0, len(headers) - len(row)))
        )
        td_rows.append(f"<tr>{cells}</tr>")
    tbody_html = "\n".join(td_rows)

    return f"""
<div class="card">
  <h2>{_h.escape(rel_name)}</h2>
  <div class="tbl-section">
    {notice}
    <div class="tbl-controls">
      <input type="search" placeholder="Search all columns…">
      <label style="font-size:12px;color:#6b7280;">Rows/page:
        <select class="page-size">
          <option value="50">50</option>
          <option value="100" selected>100</option>
          <option value="250">250</option>
          <option value="500">500</option>
        </select>
      </label>
      <span class="row-info"></span>
    </div>
    <div class="tbl-wrap">
      <table class="data-tbl">
        <thead><tr>{th_html}</tr></thead>
        <tbody>{tbody_html}</tbody>
      </table>
    </div>
    <div class="pagination">
      <button class="prev-btn">&#8592; Prev</button>
      <span class="page-info"></span>
      <button class="next-btn">Next &#8594;</button>
    </div>
  </div>
</div>"""


# ─── Navigation builder ───────────────────────────────────────────────────────

def build_nav(nav_tree, active_href="", depth=0):
    """
    nav_tree: list of (label, href, children)
    children is list of (label, href, [])  or None
    depth=0  : page lives in html/ root (index.html, report.html)
    depth=1  : page lives in html/csv/ — adjust hrefs so links resolve correctly:
               csv/foo.html  → foo.html   (sibling in same dir)
               index.html    → ../index.html  (parent dir)
    Comparison against active_href always uses the canonical (unadjusted) href.
    """
    def adjust(h):
        if h in ('#', ''):
            return h
        if depth == 0:
            return h
        # depth=1: page is inside csv/ subdirectory
        if h.startswith('csv/'):
            return h[4:]      # strip prefix — sibling file in same dir
        return '../' + h      # root-level page — go up one level

    lines = ['<nav class="sidebar">']
    lines.append('<div class="nav-title">Case Navigator</div>')
    lines.append('<ul>')

    for label, href, children in nav_tree:
        if children:
            act = "open" if any(c[1] == active_href for c in children) else ""
            lines.append(f'<li class="nav-group {act}"><a href="#">{_h.escape(label)}</a><ul>')
            for clabel, chref, _ in children:
                active_cls = ' class="active"' if chref == active_href else ''
                lines.append(f'  <li><a href="{adjust(chref)}"{active_cls}>{_h.escape(clabel)}</a></li>')
            lines.append('</ul></li>')
        else:
            active_cls = ' class="active"' if href == active_href else ''
            lines.append(f'<li><a href="{adjust(href)}"{active_cls}>{_h.escape(label)}</a></li>')

    lines.append('</ul></nav>')
    return "\n".join(lines)


# ─── Markdown → HTML ──────────────────────────────────────────────────────────

def md_to_html(md_path):
    """Convert markdown to HTML.
    Priority: pandoc → python-markdown → regex fallback.
    """
    # 1. Try pandoc (best table / GFM support)
    try:
        result = subprocess.run(
            ['pandoc', '--from', 'gfm', '--to', 'html', str(md_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass

    # 2. Try python-markdown with tables + fenced-code extensions
    try:
        import markdown as _md
        text = Path(md_path).read_text(encoding='utf-8', errors='replace')
        return _md.markdown(text, extensions=[
            'tables', 'fenced_code', 'nl2br', 'sane_lists', 'toc'
        ])
    except Exception:
        pass

    # 3. Minimal regex fallback
    try:
        text = Path(md_path).read_text(encoding='utf-8', errors='replace')
    except Exception:
        return '<p>Could not read report file.</p>'

    text = _h.escape(text)
    for n in range(6, 0, -1):
        hashes = '#' * n
        text = re.sub(rf'^{hashes}\s+(.+)$', rf'<h{n}>\1</h{n}>', text, flags=re.MULTILINE)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    text = re.sub(r'^---+$', '<hr>', text, flags=re.MULTILINE)
    text = text.replace('\n\n', '</p><p>')
    return f'<p>{text}</p>'


# ─── CSV discovery ────────────────────────────────────────────────────────────

PHASE_LABELS = {
    'MFT':            'NTFS / MFT',
    'Registry':       'Registry',
    'EventLogs':      'Event Logs',
    'Artifacts':      'Artifacts',
    'Execution':      'Execution',
    'Hunting':        'Hunting',
    'CredAccess':     'Cred Access',
    'AntiForensics':  'Anti-Forensics',
    'Browser':        'Browser',
    'Ransomware':     'Ransomware',
    'WebServer':      'Web Server',
    'Email':          'Email',
    'Linux':          'Linux Partition',
}

def discover_csvs(analysis_dir):
    """
    Returns dict: {machine: {phase: [(label, path)]}}
    Plus a top-level list for root-level CSVs.
    """
    root_csvs = []
    machine_map = {}

    adir = Path(analysis_dir)
    for p in sorted(adir.rglob('*.csv')):
        rel = p.relative_to(adir)
        parts = rel.parts

        if len(parts) == 1:
            # Root-level CSV (ioc_master.csv, etc.)
            root_csvs.append((p.name, p))
            continue

        machine = parts[0]
        if len(parts) == 2:
            phase = 'Root'
        else:
            phase = parts[1]

        machine_map.setdefault(machine, {}).setdefault(phase, []).append(
            (p.name, p)
        )

    return root_csvs, machine_map


def slug(path):
    """Turn a path into a safe filename slug."""
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', str(path))


# ─── Index page ───────────────────────────────────────────────────────────────

def gen_index(case_root, analysis_dir, root_csvs, machine_map, nav_html, case_name, generated):
    """Generate the landing page with case summary stats."""

    # Count totals
    total_csvs = len(root_csvs)
    total_rows = 0
    machine_stats = {}
    for machine, phases in machine_map.items():
        m_rows = 0
        m_files = 0
        for phase, files in phases.items():
            for fname, fpath in files:
                total_csvs += 1
                m_files += 1
                try:
                    with open(fpath, encoding='utf-8', errors='replace') as f:
                        n = sum(1 for _ in f) - 1
                        m_rows += max(n, 0)
                        total_rows += max(n, 0)
                except Exception:
                    pass
        machine_stats[machine] = (m_files, m_rows)

    for fname, fpath in root_csvs:
        try:
            with open(fpath, encoding='utf-8', errors='replace') as f:
                n = sum(1 for _ in f) - 1
                total_rows += max(n, 0)
        except Exception:
            pass

    tiles = f"""
<div class="stats-grid">
  <div class="stat-tile"><div class="val">{len(machine_map)}</div><div class="lbl">Machines</div></div>
  <div class="stat-tile"><div class="val">{total_csvs:,}</div><div class="lbl">CSV Artifacts</div></div>
  <div class="stat-tile"><div class="val">{total_rows:,}</div><div class="lbl">Total Data Rows</div></div>
  <div class="stat-tile"><div class="val">{len(root_csvs)}</div><div class="lbl">Root-Level Reports</div></div>
</div>"""

    # Machine summary table
    mach_rows = ""
    for machine, (nfiles, nrows) in sorted(machine_stats.items()):
        mach_rows += f"<tr><td><strong>{_h.escape(machine)}</strong></td><td>{nfiles}</td><td>{nrows:,}</td></tr>"

    machine_table = f"""
<div class="card">
  <h2>Evidence Summary by Machine</h2>
  <div class="tbl-wrap">
  <table class="data-tbl">
    <thead><tr><th>Machine</th><th>Artifact Files</th><th>Data Rows</th></tr></thead>
    <tbody>{mach_rows}</tbody>
  </table>
  </div>
</div>"""

    # Phase coverage table
    all_phases = set()
    for machine, phases in machine_map.items():
        all_phases.update(phases.keys())

    phase_rows = ""
    for phase in sorted(all_phases):
        label = PHASE_LABELS.get(phase, phase)
        coverage = ""
        for machine in sorted(machine_map.keys()):
            files = machine_map[machine].get(phase, [])
            if files:
                n_rows = 0
                for _, fpath in files:
                    try:
                        with open(fpath, encoding='utf-8', errors='replace') as f:
                            n_rows += max(sum(1 for _ in f) - 1, 0)
                    except Exception:
                        pass
                coverage += f" {machine}: {n_rows:,} rows;"
            else:
                coverage += f" {machine}: —;"
        phase_rows += f"<tr><td>{_h.escape(label)}</td><td style='font-size:11px;color:#6b7280'>{_h.escape(coverage.strip())}</td></tr>"

    phase_table = f"""
<div class="card">
  <h2>Phase Coverage</h2>
  <div class="tbl-wrap">
  <table class="data-tbl">
    <thead><tr><th>Phase</th><th>Coverage</th></tr></thead>
    <tbody>{phase_rows}</tbody>
  </table>
  </div>
</div>"""

    # Quick links
    links_html = '<div class="card"><h2>Quick Links</h2><ul style="list-style:none;display:flex;flex-wrap:wrap;gap:10px;">'
    links_html += '<li><a href="report.html" style="display:inline-block;background:#0f1923;color:#00b4d8;padding:7px 14px;border-radius:4px;text-decoration:none;font-size:13px;">📄 Investigation Report</a></li>'
    for fname, fpath in root_csvs:
        safe = slug(fpath.name) + '.html'
        links_html += f'<li><a href="csv/{_h.escape(safe)}" style="display:inline-block;background:#f0f2f5;border:1px solid #d1d5db;color:#374151;padding:7px 14px;border-radius:4px;text-decoration:none;font-size:12px;">{_h.escape(fname)}</a></li>'
    links_html += '</ul></div>'

    content = tiles + machine_table + phase_table + links_html

    return page(
        title="Case Overview",
        content=content,
        nav_html=nav_html,
        active_href="index.html",
        case_name=case_name,
        generated=generated,
    )


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <case_root>", file=sys.stderr)
        sys.exit(1)

    case_root = Path(sys.argv[1])
    if not case_root.is_dir():
        print(f"ERROR: {case_root} is not a directory", file=sys.stderr)
        sys.exit(1)

    analysis_dir = case_root / 'analysis'
    report_md = case_root / 'reports' / 'investigation_report.md'
    out_dir = case_root / 'reports' / 'html'
    csv_dir = out_dir / 'csv'

    out_dir.mkdir(parents=True, exist_ok=True)
    csv_dir.mkdir(parents=True, exist_ok=True)

    case_name = case_root.name
    generated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')

    print(f"[*] Case root    : {case_root}")
    print(f"[*] Analysis dir : {analysis_dir}")
    print(f"[*] Output dir   : {out_dir}")

    # ── Discover CSVs ──────────────────────────────────────────────────────
    root_csvs, machine_map = discover_csvs(analysis_dir)
    print(f"[*] Machines     : {list(machine_map.keys())}")
    total_csv = len(root_csvs) + sum(
        len(files) for phases in machine_map.values() for files in phases.values()
    )
    print(f"[*] CSV files    : {total_csv}")

    # ── Build navigation tree ──────────────────────────────────────────────
    nav_tree = [
        ("Case Overview",        "index.html",  []),
        ("Investigation Report", "report.html", []),
    ]

    # Per-machine groups
    csv_file_map = {}  # href -> (label, fpath)

    for machine in sorted(machine_map.keys()):
        children = []
        for phase in sorted(machine_map[machine].keys()):
            label = PHASE_LABELS.get(phase, phase)
            for fname, fpath in sorted(machine_map[machine][phase]):
                href_slug = slug(fpath.relative_to(analysis_dir)) + '.html'
                href = f"csv/{href_slug}"
                short = fname.replace('.csv', '').replace(f'{machine}_', '')
                children.append((f"{label}: {short}", href, []))
                csv_file_map[href] = (fname, fpath)
        nav_tree.append((f"Machine: {machine}", "#", children))

    # Root-level CSVs group
    root_children = []
    for fname, fpath in sorted(root_csvs):
        href_slug = slug(fpath.name) + '.html'
        href = f"csv/{href_slug}"
        root_children.append((fname.replace('.csv',''), href, []))
        csv_file_map[href] = (fname, fpath)
    if root_children:
        nav_tree.append(("Analysis Root", "#", root_children))

    # ── Generate CSV table pages ───────────────────────────────────────────
    for href, (fname, fpath) in csv_file_map.items():
        nav_html = build_nav(nav_tree, active_href=href, depth=1)
        content  = table_page_content(fpath, machine="", rel_name=fname)
        html_out = page(
            title=fname,
            content=content,
            nav_html=nav_html,
            active_href=href,
            case_name=case_name,
            generated=generated,
        )
        # href is "csv/<slug>.html"
        out_path = out_dir / href
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html_out, encoding='utf-8')

    print(f"[*] Generated {len(csv_file_map)} table pages")

    # ── Generate investigation report page ─────────────────────────────────
    nav_html = build_nav(nav_tree, active_href="report.html", depth=0)
    if report_md.exists():
        body_html = md_to_html(report_md)
        if shutil.which('pandoc'):
            method = "pandoc"
        else:
            try:
                import markdown as _chk; method = "python-markdown"
            except ImportError:
                method = "regex-fallback"
        print(f"[*] Report converted via {method}")
    else:
        body_html = f"<p>Report not found at {_h.escape(str(report_md))}</p>"

    report_content = f'<div class="card report-body">{body_html}</div>'
    report_html = page(
        title="Investigation Report",
        content=report_content,
        nav_html=nav_html,
        active_href="report.html",
        case_name=case_name,
        generated=generated,
    )
    (out_dir / 'report.html').write_text(report_html, encoding='utf-8')
    print(f"[*] Report page  : {out_dir / 'report.html'}")

    # ── Generate index page ────────────────────────────────────────────────
    nav_html = build_nav(nav_tree, active_href="index.html", depth=0)
    index_html = gen_index(
        case_root=case_root,
        analysis_dir=analysis_dir,
        root_csvs=root_csvs,
        machine_map=machine_map,
        nav_html=nav_html,
        case_name=case_name,
        generated=generated,
    )
    (out_dir / 'index.html').write_text(index_html, encoding='utf-8')
    print(f"[*] Index page   : {out_dir / 'index.html'}")

    # ── Final summary ──────────────────────────────────────────────────────
    print()
    print(f"  HTML package ready:")
    print(f"    {out_dir}/index.html")
    print(f"    {out_dir}/report.html")
    print(f"    {out_dir}/csv/  ({len(csv_file_map)} table pages)")


if __name__ == '__main__':
    main()
