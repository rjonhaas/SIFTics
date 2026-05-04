#!/usr/bin/env python3
"""Convert a DFIR investigation report from Markdown to standalone HTML.

Usage:
    python3 report_to_html.py <input.md> [output.html]

If output path is omitted, the HTML file is written alongside the input file
with the same stem and a .html extension.
"""

import sys
import re
import html as html_module
from pathlib import Path
from datetime import datetime, timezone

import markdown
from markdown.extensions.tables import TableExtension
from markdown.extensions.toc import TocExtension

CSS = """
/* ── Reset & base ─────────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
    --bg:          #0f1117;
    --surface:     #1a1d27;
    --surface2:    #22263a;
    --border:      #2d3354;
    --accent:      #4f9eff;
    --accent2:     #7c5cbf;
    --text:        #d4d8f0;
    --text-muted:  #8890b0;
    --text-strong: #eef0ff;
    --green:       #3ddc84;
    --yellow:      #f0c040;
    --red:         #f05050;
    --red-bg:      rgba(240,80,80,0.08);
    --yellow-bg:   rgba(240,192,64,0.08);
    --green-bg:    rgba(61,220,132,0.08);
    --code-bg:     #131622;
    --radius:      6px;
}

body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    font-size: 14px;
    line-height: 1.65;
    background: var(--bg);
    color: var(--text);
    padding: 0;
    margin: 0;
}

/* ── Layout ───────────────────────────────────────────────────────────── */
.wrapper {
    display: grid;
    grid-template-columns: 260px 1fr;
    min-height: 100vh;
}

nav#toc {
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
    background: var(--surface);
    border-right: 1px solid var(--border);
    padding: 24px 16px;
    font-size: 12px;
}

nav#toc h2 {
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border);
}

nav#toc ul { list-style: none; padding-left: 0; }
nav#toc li { margin: 2px 0; }
nav#toc a {
    display: block;
    padding: 3px 8px;
    color: var(--text-muted);
    text-decoration: none;
    border-radius: 4px;
    transition: background 0.15s, color 0.15s;
    line-height: 1.4;
}
nav#toc a:hover { background: var(--surface2); color: var(--text); }
nav#toc li.toc-h3 > a { padding-left: 18px; font-size: 11px; }
nav#toc li.toc-h4 > a { padding-left: 28px; font-size: 11px; color: #606880; }

article {
    padding: 48px 56px;
    max-width: 1100px;
}

/* ── Header block ─────────────────────────────────────────────────────── */
.report-header {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 28px 32px;
    margin-bottom: 40px;
}

.report-header h1 {
    font-size: 22px;
    font-weight: 700;
    color: var(--text-strong);
    margin-bottom: 16px;
    letter-spacing: -0.01em;
}

.report-header .meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 6px 24px;
    font-size: 12px;
}

.report-header .meta-grid p { color: var(--text-muted); }
.report-header .meta-grid strong { color: var(--text); }

.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    background: rgba(79,158,255,0.15);
    color: var(--accent);
    border: 1px solid rgba(79,158,255,0.3);
    margin-bottom: 12px;
}

/* ── Typography ───────────────────────────────────────────────────────── */
h1, h2, h3, h4 {
    color: var(--text-strong);
    font-weight: 600;
    line-height: 1.3;
}

h2 {
    font-size: 17px;
    margin: 48px 0 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    position: relative;
}

h2::before {
    content: '';
    position: absolute;
    bottom: -1px;
    left: 0;
    width: 40px;
    height: 2px;
    background: var(--accent);
    border-radius: 2px;
}

h3 {
    font-size: 14px;
    margin: 28px 0 10px;
    color: var(--accent);
}

h4 {
    font-size: 13px;
    margin: 20px 0 8px;
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-size: 11px;
}

p { margin: 0 0 12px; }
p:last-child { margin-bottom: 0; }

strong { color: var(--text-strong); font-weight: 600; }
em { color: var(--text-muted); font-style: italic; }

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

hr {
    border: none;
    border-top: 1px solid var(--border);
    margin: 40px 0;
}

/* ── Tables ───────────────────────────────────────────────────────────── */
.table-wrap { overflow-x: auto; margin: 16px 0 24px; border-radius: var(--radius); }

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
}

thead tr {
    background: var(--surface2);
    border-bottom: 2px solid var(--border);
}

th {
    text-align: left;
    padding: 8px 12px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-muted);
    white-space: nowrap;
}

td {
    padding: 7px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    word-break: break-word;
}

tbody tr:hover { background: var(--surface2); }

/* Severity colouring via content patterns */
td:has(> strong) { }

/* ── Code ─────────────────────────────────────────────────────────────── */
code {
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
    font-size: 12px;
    background: var(--code-bg);
    color: #a0d0ff;
    padding: 1px 5px;
    border-radius: 3px;
    border: 1px solid rgba(79,158,255,0.15);
}

pre {
    background: var(--code-bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 20px;
    overflow-x: auto;
    margin: 16px 0;
}

pre code {
    background: none;
    border: none;
    padding: 0;
    color: #c0d8ff;
    font-size: 12px;
    line-height: 1.6;
}

/* ── Lists ────────────────────────────────────────────────────────────── */
ul, ol {
    padding-left: 20px;
    margin: 8px 0 12px;
}

li { margin: 4px 0; }

/* Checklist items */
li input[type=checkbox] { margin-right: 6px; accent-color: var(--accent); }

/* ── Callout blocks ───────────────────────────────────────────────────── */
blockquote {
    border-left: 3px solid var(--accent2);
    background: var(--surface);
    padding: 12px 16px;
    margin: 16px 0;
    border-radius: 0 var(--radius) var(--radius) 0;
    color: var(--text-muted);
    font-style: italic;
}

/* ── IOC severity helpers (applied via JS) ────────────────────────────── */
.sev-high { color: var(--red); font-weight: 600; }
.sev-med  { color: var(--yellow); }
.sev-low  { color: var(--text-muted); }
.sev-ioc  { color: var(--red); font-family: monospace; font-size: 12px; }

tr.row-high td:first-child { border-left: 3px solid var(--red); }
tr.row-med  td:first-child { border-left: 3px solid var(--yellow); }

/* ── Footer ───────────────────────────────────────────────────────────── */
footer {
    margin-top: 64px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--text-muted);
}

/* ── Scrollbar ────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #3d4466; }

/* ── Print ────────────────────────────────────────────────────────────── */
@media print {
    .wrapper { display: block; }
    nav#toc { display: none; }
    body { background: #fff; color: #111; font-size: 10pt; }
    h2, h3, h4 { color: #111; }
    code, pre { background: #f4f4f4; color: #222; border-color: #ccc; }
    table { font-size: 9pt; }
    th { color: #333; }
    td { border-color: #ddd; }
    thead tr { background: #eee; }
}
"""

JS = """
document.addEventListener('DOMContentLoaded', () => {
    // Wrap tables for horizontal scroll
    document.querySelectorAll('table').forEach(t => {
        const wrap = document.createElement('div');
        wrap.className = 'table-wrap';
        t.parentNode.insertBefore(wrap, t);
        wrap.appendChild(t);
    });

    // Colour rows containing HIGH/MALICIOUS/CONFIRMED COMPROMISED etc.
    document.querySelectorAll('tbody tr').forEach(row => {
        const txt = row.textContent;
        if (/\\bHIGH\\b|MALICIOUS|CONFIRMED COMPROMISED/i.test(txt))
            row.classList.add('row-high');
        else if (/\\bMED(IUM)?\\b|POSSIBLE/i.test(txt))
            row.classList.add('row-med');
    });

    // Build sidebar TOC from headings
    const toc = document.getElementById('toc-list');
    document.querySelectorAll('article h2, article h3').forEach((h, i) => {
        if (!h.id) h.id = 'h-' + i;
        const li = document.createElement('li');
        li.className = h.tagName === 'H2' ? 'toc-h2' : 'toc-h3';
        const a = document.createElement('a');
        a.href = '#' + h.id;
        a.textContent = h.textContent.replace(/^[\\d]+[A-Z]?\\. /, '').replace(/^#+\\s*/, '');
        li.appendChild(a);
        toc.appendChild(li);
    });

    // Active TOC highlight on scroll
    const headings = Array.from(document.querySelectorAll('article h2, article h3'));
    const tocLinks = Array.from(document.querySelectorAll('nav#toc a'));
    const obs = new IntersectionObserver(entries => {
        entries.forEach(e => {
            if (e.isIntersecting) {
                tocLinks.forEach(l => l.style.color = '');
                const active = document.querySelector(`nav#toc a[href="#${e.target.id}"]`);
                if (active) active.style.color = 'var(--accent)';
            }
        });
    }, { rootMargin: '-10% 0px -80% 0px' });
    headings.forEach(h => obs.observe(h));
});
"""

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
{css}
</style>
</head>
<body>
<div class="wrapper">
  <nav id="toc">
    <h2>Contents</h2>
    <ul id="toc-list"></ul>
  </nav>
  <article>
{body}
    <footer>
      <p>All timestamps UTC &nbsp;·&nbsp; Generated {generated} &nbsp;·&nbsp; Source: <code>{source}</code></p>
    </footer>
  </article>
</div>
<script>
{js}
</script>
</body>
</html>
"""

def extract_title(md_text: str) -> str:
    for line in md_text.splitlines():
        line = line.strip()
        if line.startswith("# "):
            return line[2:].strip()
    return "Investigation Report"


def preprocess_md(md_text: str) -> str:
    """Light pre-processing to improve rendering."""
    # Convert [ ] / [x] task list items
    md_text = re.sub(r"^(\s*)-\s+\[ \]", r"\1- <input type='checkbox' disabled>", md_text, flags=re.MULTILINE)
    md_text = re.sub(r"^(\s*)-\s+\[x\]", r"\1- <input type='checkbox' checked disabled>", md_text, flags=re.MULTILINE)
    return md_text


def md_to_html(md_path: Path, html_path: Path) -> None:
    md_text = md_path.read_text(encoding="utf-8")
    title = extract_title(md_text)
    md_text = preprocess_md(md_text)

    md_converter = markdown.Markdown(
        extensions=[
            TableExtension(),
            "fenced_code",
            "attr_list",
            "def_list",
            "md_in_html",
            "nl2br",
            TocExtension(permalink=False),
        ]
    )
    body_html = md_converter.convert(md_text)

    # Lift the first h1 + metadata block into a styled header card
    header_match = re.match(
        r'(<h1[^>]*>.*?</h1>)(.*?)(<hr\s*/>)',
        body_html, re.DOTALL
    )
    if header_match:
        h1_block   = header_match.group(1)
        meta_block = header_match.group(2).strip()
        hr_tag     = header_match.group(3)
        # Convert the meta paragraphs into a grid
        meta_inner = re.sub(r'<p>(.*?)</p>', r'<p>\1</p>', meta_block, flags=re.DOTALL)
        header_card = (
            '<div class="report-header">\n'
            f'  <div class="badge">FOR OFFICIAL USE ONLY</div>\n'
            f'  {h1_block}\n'
            f'  <div class="meta-grid">{meta_inner}</div>\n'
            '</div>\n'
        )
        body_html = body_html[header_match.end():]
        body_html = header_card + body_html

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html_out = HTML_TEMPLATE.format(
        title=html_module.escape(title),
        css=CSS,
        body=body_html,
        js=JS,
        generated=generated,
        source=html_module.escape(str(md_path)),
    )
    html_path.write_text(html_out, encoding="utf-8")
    print(f"Written: {html_path}  ({html_path.stat().st_size // 1024} KB)")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input.md> [output.html]", file=sys.stderr)
        sys.exit(1)

    md_path = Path(sys.argv[1]).resolve()
    if not md_path.exists():
        print(f"ERROR: {md_path} not found", file=sys.stderr)
        sys.exit(1)

    html_path = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else md_path.with_suffix(".html")
    html_path.parent.mkdir(parents=True, exist_ok=True)
    md_to_html(md_path, html_path)


if __name__ == "__main__":
    main()
