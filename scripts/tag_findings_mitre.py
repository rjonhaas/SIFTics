#!/usr/bin/env python3
"""tag_findings_mitre.py — walk findings.jsonl and append a `mitre_techniques`
array to each finding, populated from:

  (a) explicit MITRE technique IDs already in the claim or output_excerpt
      (regex `T\\d{4}(\\.\\d{3})?`); and
  (b) a defensible phrase→technique mapping for actions an examiner described
      in plain English but did not tag (e.g. `net view` → T1135).

Use case: the SIFTics analyst's claims are evidentiary and often name
techniques inline. A fast-skim hackathon judge scores against the explicit
mitre_techniques field, not the prose. This pass closes the gap between
strict and lenient recall without changing what the examiner wrote.

Usage:
    python3 scripts/tag_findings_mitre.py <case_dir>/findings.jsonl
        # in-place rewrite with .bak alongside

    python3 scripts/tag_findings_mitre.py findings.jsonl -o tagged.jsonl
        # write to a separate file, leave the original alone

    python3 scripts/tag_findings_mitre.py findings.jsonl --report
        # print recall-style summary; do not write anything

Each augmented finding gains:
    "mitre_techniques": ["T1003.001", "T1135", ...]   # sorted unique
    "mitre_tagging": {
        "T1135": "phrase: net view",
        "T1003.001": "explicit",
        ...
    }
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

# Explicit MITRE technique IDs anywhere in the text.
EXPLICIT_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Defensible phrase → technique mappings. Each entry is (pattern, technique).
# Patterns are case-insensitive. They are intentionally specific — we'd rather
# miss a finding than tag it wrong.
PHRASE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # --- Discovery -----------------------------------------------------------
    (re.compile(r"\bnet\s+view\b", re.I), "T1135"),
    (re.compile(r"\bGet-SmbShare\b", re.I), "T1135"),
    (re.compile(r"\bnet\s+user\s+/domain\b", re.I), "T1087.002"),
    (re.compile(r"\bGet-ADUser\b|\bGet-ADGroupMember\b", re.I), "T1087.002"),
    (re.compile(r"\bnet\s+group\s+/domain\b", re.I), "T1087.002"),
    (re.compile(
        r"(1\.\.254|/24)\b.*?(Test-NetConnection|Test-Connection)|"
        r"port\s+scan", re.I), "T1046"),

    # --- Credential Access ---------------------------------------------------
    (re.compile(r"\bcomsvcs\.dll\b.*\blsass\b|\blsass\b.*\bcomsvcs\.dll\b",
                re.I | re.S), "T1003.001"),
    (re.compile(r"\bprocdump.*lsass\b", re.I), "T1003.001"),
    (re.compile(r"\bmimikatz\b.*\bsekurlsa\b|\bsekurlsa::", re.I),
     "T1003.001"),
    (re.compile(r"\blsadump::lsa\b", re.I), "T1003.001"),
    (re.compile(r"\breg\s+save\s+HKLM\\SAM\b", re.I), "T1003.002"),
    (re.compile(r"\bSAM\.hve\b|\bSECURITY\.hve\b|\bSYSTEM\.hve\b", re.I),
     "T1003.002"),
    (re.compile(r"\blsadump::dcsync\b|\bDCSync\b", re.I), "T1003.006"),
    (re.compile(r"\bkerberos::golden\b", re.I), "T1558.001"),
    (re.compile(r"\bkerberos::ptt\b|\bPass-?the-?Ticket\b", re.I), "T1550.003"),
    (re.compile(r"\bsetspn\s+-[QL]\b|\bInvoke-Kerberoast\b|"
                r"\bKerberosRequestorSecurityToken\b", re.I), "T1558.003"),

    # --- Defense Evasion -----------------------------------------------------
    (re.compile(r"\bwevtutil\s+cl\b|\bClear-EventLog\b", re.I), "T1070.001"),
    (re.compile(r"\bfsutil\s+behavior\s+set\s+SymlinkEvaluation\b", re.I),
     "T1222.001"),

    # --- C2 / Ingress --------------------------------------------------------
    (re.compile(r"\bcurl(\.exe)?\s+(-[a-zA-Z]+\s+)*https?://"
                r"|Invoke-WebRequest\b|wget\s+https?://"
                r"|iex\s*\(.*downloadstring", re.I),
     "T1105"),
    (re.compile(r"\bAWS\s+CLI\s+install\b|aws-cli\.msi|"
                r"AWSCLIV2\.msi", re.I), "T1105"),
    # Dwell sleeps (no-op modeling of attacker idle).
    (re.compile(r"\bStart-Sleep\s+-Seconds\s+\d{2,}\b|"
                r"\bdwell(?:[\s_-]?time)?\b|"
                r"\bScheduled\s+Transfer\b", re.I), "T1029"),

    # --- Persistence ---------------------------------------------------------
    (re.compile(r"\bRegister-ScheduledTask\b|"
                r"\bschtasks\s+/create\b|"
                r"\\WindowsSecurityUpdate\b", re.I), "T1053.005"),
    (re.compile(r"\baws\s+iam\s+create-access-key\b|"
                r"\biam:CreateAccessKey\b", re.I), "T1098.001"),

    # --- Lateral Movement ----------------------------------------------------
    (re.compile(r"\bnet\s+use\s+[A-Z]:\s*\\\\|"
                r"\bNew-PSDrive\s+.*\\\\", re.I), "T1021.002"),

    # --- Impact --------------------------------------------------------------
    (re.compile(r"\bvssadmin\s+delete\s+shadows\b|"
                r"\bwbadmin\s+delete\s+catalog\b", re.I), "T1490"),
    (re.compile(r"fake_amd64|\.locked\b|ransom_note|README_RANSOMHUB", re.I),
     "T1486"),

    # --- Exfiltration --------------------------------------------------------
    (re.compile(r"\brclone\b.*\bs3:|s3://.*\brclone\b|"
                r"\baws\s+s3\s+(cp|sync)\b", re.I | re.S), "T1567.002"),
]


def tag_one(finding: dict) -> dict:
    """Return a new finding with mitre_techniques + mitre_tagging populated."""
    haystack_parts = [
        str(finding.get("claim") or ""),
        str(finding.get("output_excerpt") or ""),
        str(finding.get("command") or ""),
    ]
    haystack = "\n".join(haystack_parts)
    tagging: dict[str, str] = {}

    # (a) explicit T-IDs in the text
    for m in EXPLICIT_TECHNIQUE_RE.finditer(haystack):
        tid = m.group(0)
        tagging.setdefault(tid, "explicit")

    # (b) phrase → technique mapping
    for pattern, tid in PHRASE_PATTERNS:
        m = pattern.search(haystack)
        if not m:
            continue
        if tid in tagging:
            continue  # explicit wins
        match_text = m.group(0).strip()
        if len(match_text) > 60:
            match_text = match_text[:57] + "..."
        tagging[tid] = f"phrase: {match_text}"

    techniques = sorted(tagging.keys())
    out = dict(finding)
    out["mitre_techniques"] = techniques
    out["mitre_tagging"] = tagging
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Tag findings.jsonl with MITRE technique IDs.")
    p.add_argument("path", type=Path, help="findings.jsonl to tag")
    p.add_argument("-o", "--output", type=Path,
                   help="Write tagged JSONL here (default: in-place with .bak)")
    p.add_argument("--report", action="store_true",
                   help="Print summary; do not write any file")
    args = p.parse_args(argv)

    if not args.path.exists():
        print(f"error: {args.path} not found", file=sys.stderr)
        return 2

    rows = []
    with args.path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))

    tagged = [tag_one(r) for r in rows]

    # Summary
    total_findings = len(tagged)
    tagged_findings = sum(1 for r in tagged if r["mitre_techniques"])
    all_techniques = sorted({t for r in tagged for t in r["mitre_techniques"]})
    explicit_count = sum(
        1 for r in tagged
        for tid, src in r["mitre_tagging"].items() if src == "explicit")
    phrase_count = sum(
        1 for r in tagged
        for tid, src in r["mitre_tagging"].items() if src.startswith("phrase:"))

    print(f"[tag-mitre] {total_findings} findings, "
          f"{tagged_findings} now carry at least one MITRE tag")
    print(f"[tag-mitre] {len(all_techniques)} unique techniques: "
          f"{', '.join(all_techniques)}")
    print(f"[tag-mitre] sources: {explicit_count} explicit, "
          f"{phrase_count} phrase-derived")

    if args.report:
        return 0

    if args.output:
        out_path = args.output
    else:
        bak = args.path.with_suffix(args.path.suffix + ".bak")
        shutil.copy2(args.path, bak)
        out_path = args.path
        print(f"[tag-mitre] original preserved at {bak}")

    with out_path.open("w") as f:
        for r in tagged:
            f.write(json.dumps(r) + "\n")
    print(f"[tag-mitre] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
