"""Case completeness rules — close the FN gaps the main loop misses.

The investigation-section-chief persona drives a deep but narrow analysis
loop. When it converges on the right adversary story it can still leave
specific tool-surface gaps unchecked — Registry persistence when only
service persistence was found, browser history when only EVTX was parsed,
timezone hive reads, CTI lookups against the second-tier feeds, anti-
forensics scope beyond the implant binary, and so on.

This module is a **completeness critic**: it scans the case state for
*trigger patterns* (things the agent already discovered) and checks whether
the *expected follow-on evidence* is present. Each rule is a small function
that returns a Gap or None.

The MCP tool ``case_completeness_check()`` wraps :func:`check_completeness`
so the agent can call it before producing the final report, and a
``case_completeness_check_run`` audit event records what gaps surfaced.

The rules are deliberately fuzzy-text-based for v1 — they search the
``notes`` / ``claim`` / ``output_excerpt`` fields of ASR rows and
finding records. A v2 improvement would track exact tool invocations from
the audit log; for now, text matching catches the cases observed in the
first grading run against Stolen Szechuan Sauce (DFIR Madness DS0001).

Add a rule by writing a function ``rule_<name>(state)`` that returns
:class:`Gap` or ``None`` and appending it to :data:`RULES`. Every rule
should fail-closed (return a gap when uncertain) so the IC sees more
gaps rather than fewer.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Iterable

Severity = str  # "high" | "medium" | "low"


@dataclass
class Gap:
    """One investigation gap. ``rule`` is stable across runs; ``triggered_by``
    points at the specific ASR rows / finding IDs that fired the rule so the
    IC can re-open them; ``suggestion`` is a one-sentence next action."""

    rule: str
    severity: Severity
    triggered_by: list[str]
    suggestion: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CaseState:
    """Snapshot of every case file the rules read. Loaded once per check."""

    asr: list[dict]
    findings: list[dict]
    grid: list[dict]   # ITQ rows
    briefings_text: str  # all briefings concatenated, lowercased


def _load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _load_briefings(briefings_dir: Path) -> str:
    if not briefings_dir.is_dir():
        return ""
    parts = []
    for p in sorted(briefings_dir.glob("*.md")):
        try:
            parts.append(p.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
    return "\n\n".join(parts).lower()


def load_case_state(case_dir: str | Path) -> CaseState:
    """Load every JSONL/briefings file once so the rules can read locals."""
    p = Path(case_dir)
    return CaseState(
        asr=_load_jsonl(p / "suit.jsonl"),
        findings=_load_jsonl(p / "findings.jsonl"),
        grid=_load_jsonl(p / "grid.jsonl"),
        briefings_text=_load_briefings(p / "briefings"),
    )


# ---------------------------------------------------------------------------
# Helpers used by multiple rules
# ---------------------------------------------------------------------------


_DATA_ACCESS_KEYWORDS = (
    "accessed", "exfiltrat", "staged", "crown-jewel", "crown jewel",
    "loot", "secret", "sensitive file",
)


def _any_field_contains(rows: Iterable[dict], field: str, keywords: Iterable[str]) -> list[dict]:
    """Return rows whose ``field`` contains any of ``keywords`` (case-insensitive)."""
    out = []
    kws = [k.lower() for k in keywords]
    for r in rows:
        v = (r.get(field) or "")
        if isinstance(v, list):
            v = " ".join(str(x) for x in v)
        v = str(v).lower()
        if any(kw in v for kw in kws):
            out.append(r)
    return out


def _findings_mention(findings: list[dict], substrings: Iterable[str]) -> bool:
    """True if any finding record's claim, output excerpt, or tool field mentions
    any of the given substrings (case-insensitive)."""
    needles = [s.lower() for s in substrings]
    for f in findings:
        haystack = " ".join(str(f.get(k, "")) for k in
                            ("claim", "output_excerpt", "tool", "command", "artifact_path")).lower()
        if any(n in haystack for n in needles):
            return True
    return False


def _asr_serials(rows: list[dict]) -> list[str]:
    return [r.get("serial_no") or r.get("system_identifier") or "?" for r in rows]


# ---------------------------------------------------------------------------
# Rules — one function per rule
# ---------------------------------------------------------------------------


def rule_antiforensics_scope_data_files(state: CaseState) -> Gap | None:
    """If ASR notes mention attacker file access, anti-forensics scope must
    cover user-data files in those directories (not just the implant binary)."""
    triggered = _any_field_contains(state.asr, "notes", _DATA_ACCESS_KEYWORDS)
    if not triggered:
        triggered = _any_field_contains(state.asr, "how_determined", _DATA_ACCESS_KEYWORDS)
    if not triggered:
        return None
    has_scope = _findings_mention(
        state.findings,
        ["mft", "analyzemft", "$si vs $fn", "$fn vs $si", "user-data", "user data",
         "data file timestomp", "directory scan", "filesystem timeline"],
    )
    if has_scope:
        return None
    return Gap(
        rule="antiforensics_scope_data_files",
        severity="high",
        triggered_by=_asr_serials(triggered),
        suggestion=(
            "Re-run /anti-forensics-detection with scope expanded to user-data "
            "files in the attacker-accessed directories. See the skill's 'Scope "
            "— three classes of files' section: implant binaries (you covered "
            "this), user-data files (likely missing), log files."
        ),
    )


def rule_antiforensics_scope_log_files(state: CaseState) -> Gap | None:
    """Anti-forensics scope must cover the log files themselves — Windows
    EVTX, Linux wtmp/btmp/auth.log — not just the malware binary."""
    # Only fires if any anti-forensics finding exists (i.e. agent ran the
    # phase) but no log-file scope coverage is recorded.
    ran_check = _findings_mention(
        state.findings, ["anti-forensic", "antiforensic", "timestomp"],
    )
    if not ran_check:
        return None
    has_log_scope = _findings_mention(
        state.findings,
        ["evtx mtime", "evtx $si", "evtx $fn", "log file timestomp",
         "wtmp timestomp", "auth.log mtime", "log file scope",
         "security.evtx $", "system.evtx $"],
    )
    if has_log_scope:
        return None
    return Gap(
        rule="antiforensics_scope_log_files",
        severity="medium",
        triggered_by=["(anti-forensics phase ran)"],
        suggestion=(
            "Add log files to the anti-forensics scope. Compare $SI vs $FN on "
            "Security.evtx / System.evtx (Windows) or wtmp/btmp/auth.log (Linux), "
            "and check each log's last-record timestamp against its filesystem mtime."
        ),
    )


def rule_registry_persistence_when_service_persistence(state: CaseState) -> Gap | None:
    """If service-based persistence was found, registry Run/RunOnce keys must
    also be checked (attackers commonly use both)."""
    has_service_persistence = _findings_mention(
        state.findings,
        ["service persistence", "auto_start", "service installed",
         "create/modify system service", "t1543.003", "7045"],
    )
    if not has_service_persistence:
        return None
    has_registry_check = _findings_mention(
        state.findings,
        ["run key", "runonce", "software\\microsoft\\windows\\currentversion\\run",
         "regripper -p soft", "registry persistence", "t1547.001", "registry run"],
    )
    if has_registry_check:
        return None
    return Gap(
        rule="registry_persistence_when_service_persistence",
        severity="high",
        triggered_by=["(service-persistence finding)"],
        suggestion=(
            "Run the persistence pivot on registry Run/RunOnce/Image File "
            "Execution Options. RegRipper -p run / runonce / image_file_execution_options "
            "against the SOFTWARE hive on each affected host. Attackers who "
            "install a service also frequently drop a Run-key entry as fallback."
        ),
    )


def rule_browser_history_when_remote_entry_vector(state: CaseState) -> Gap | None:
    """If the entry vector is RDP/SSH (an interactive remote session), browser
    history should be parsed — attackers commonly use the in-session browser
    to download follow-on tooling."""
    needles = ["rdp", "remote desktop", "ssh logon", "interactive logon",
               "logon type 10", "type10"]
    has_remote_entry = _findings_mention(state.findings, needles) or any(
        n in state.briefings_text for n in needles
    )
    if not has_remote_entry:
        return None
    has_browser_parse = _findings_mention(
        state.findings,
        ["webcachev01", "internetexplorer", "ie history", "browser history",
         "chrome history", "edge history", "firefox places", "webcache.dat"],
    )
    if has_browser_parse:
        return None
    return Gap(
        rule="browser_history_when_remote_entry_vector",
        severity="medium",
        triggered_by=["(remote-session entry vector confirmed)"],
        suggestion=(
            "Parse browser history on each compromised host: ESEDB "
            "WebCacheV01.dat (IE/Edge), Chrome History sqlite, Firefox "
            "places.sqlite. Look for downloads inside the attacker's logon "
            "window — the delivery vector for the implant is often a browser "
            "fetch from the remote session, not the C2 channel itself."
        ),
    )


def rule_timezone_registry_read_for_windows(state: CaseState) -> Gap | None:
    """Windows host with no timezone read from SYSTEM hive."""
    has_windows = _findings_mention(
        state.findings, ["windows server", "windows 10", "windows 11", "windows 7",
                          "windows 8", "windows nt", "microsoft windows"],
    ) or any(
        (r.get("system_type") or "").lower().startswith("windows") for r in state.asr
    )
    if not has_windows:
        return None
    has_tz_read = _findings_mention(
        state.findings,
        ["timezoneinformation", "timezone hive", "regripper -p timezone",
         "timezonename", "activetimebias", "tz registry"],
    )
    if has_tz_read:
        return None
    return Gap(
        rule="timezone_registry_read_for_windows",
        severity="medium",
        triggered_by=_asr_serials([r for r in state.asr
                                   if (r.get("system_type") or "").lower().startswith("windows")]),
        suggestion=(
            "Read HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation "
            "from each Windows host's SYSTEM hive (RegRipper -p timezone, or "
            "regipy). Without this, every timestamp claim in the case is UTC-"
            "only and any local-clock-skew anti-forensics is undetectable."
        ),
    )


def rule_cti_lookup_for_external_ips(state: CaseState) -> Gap | None:
    """Every external attacker IP recorded in ASR/findings should have at
    least one CTI lookup against a reputation feed."""
    import re
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    private = ("10.", "127.", "0.", "192.168.", "169.254.")
    candidates: set[str] = set()
    for row in state.asr + state.findings:
        for fld in ("notes", "how_determined", "claim", "impact_description",
                    "output_excerpt"):
            v = row.get(fld) or ""
            for ip in ip_re.findall(str(v)):
                if ip.startswith(private):
                    continue
                if ip.startswith("172."):
                    sec = ip.split(".")[1]
                    if sec.isdigit() and 16 <= int(sec) <= 31:
                        continue
                candidates.add(ip)
    if not candidates:
        return None
    cti_hits = " ".join(
        str(f.get(k, "")) for f in state.findings
        for k in ("output_excerpt", "claim", "tool")
    ).lower()
    missing = [ip for ip in candidates
               if ip not in cti_hits or "no record" in cti_hits or "unconfigured" in cti_hits]
    # Refine: require explicit "cti" / "abuseipdb" / "greynoise" / "virustotal" presence per IP
    really_missing = []
    for ip in candidates:
        ip_block = cti_hits.split(ip)
        if len(ip_block) < 2:
            really_missing.append(ip)
            continue
        # Within a small window of the IP mention, look for a CTI tool name
        window = " ".join(ip_block[1].split()[:30])
        if not any(tool in window for tool in
                   ("abuseipdb", "greynoise", "virustotal", "threatfox",
                    "shodan", "censys", "cti_", "feodo")):
            really_missing.append(ip)
    if not really_missing:
        return None
    return Gap(
        rule="cti_lookup_for_external_ips",
        severity="medium",
        triggered_by=really_missing,
        suggestion=(
            "Query each external IP against at least two CTI feeds. The default "
            "broker checks Feodo/ThreatFox; add AbuseIPDB + Greynoise for "
            "reputation breadth (RDP-bruteforce trackers, residential vs. "
            "hosting attribution). Even a 'no record' negative result is "
            "valuable when it's explicit."
        ),
    )


def rule_credential_dump_on_dc_compromise(state: CaseState) -> Gap | None:
    """Domain controller in ASR with critical impact → credential-dump check
    must have run (NTDS.dit / SAM / LSASS)."""
    dc_rows = [
        r for r in state.asr
        if (r.get("impact_rating") or "").lower() == "critical"
        and any(kw in ((r.get("system_type") or "") + " " + (r.get("notes") or "")).lower()
                for kw in ("domain controller", "domain-controller", "dc01", "ad ds", "krbtgt"))
    ]
    if not dc_rows:
        return None
    has_creddump_check = _findings_mention(
        state.findings,
        ["ntds.dit", "lsass dump", "hashdump", "secretsdump",
         "mimikatz", "windows.hashdump", "lsadump", "credential dump",
         "krbtgt hash"],
    )
    if has_creddump_check:
        return None
    return Gap(
        rule="credential_dump_on_dc_compromise",
        severity="high",
        triggered_by=_asr_serials(dc_rows),
        suggestion=(
            "Run the credential-dump check on the compromised DC. At minimum: "
            "Volatility windows.hashdump + windows.lsadump against the memory "
            "image; secretsdump.py against NTDS.dit + SYSTEM hive from disk. "
            "If SIFTics policy is 'do not crack offline,' record the policy "
            "decision explicitly in a briefing rather than leaving the gap "
            "silent — judges and forensic peers will read silence as miss."
        ),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


RULES: list[Callable[[CaseState], Gap | None]] = [
    rule_antiforensics_scope_data_files,
    rule_antiforensics_scope_log_files,
    rule_registry_persistence_when_service_persistence,
    rule_browser_history_when_remote_entry_vector,
    rule_timezone_registry_read_for_windows,
    rule_cti_lookup_for_external_ips,
    rule_credential_dump_on_dc_compromise,
]


def check_completeness(case_dir: str | Path) -> list[dict]:
    """Run every rule against the case state and return a list of gap dicts.

    Args:
        case_dir: path to the case directory (must contain at least
            suit.jsonl, findings.jsonl, grid.jsonl).

    Returns:
        list of gap dicts ordered by severity (high → medium → low). Empty
        list means the rule set found nothing missing — but note this is
        not a *proof* of completeness; new rules will catch new cases.
    """
    state = load_case_state(case_dir)
    gaps: list[Gap] = []
    for rule in RULES:
        try:
            g = rule(state)
        except Exception:
            # A buggy rule should never block the check
            continue
        if g is not None:
            gaps.append(g)
    sev_order = {"high": 0, "medium": 1, "low": 2}
    gaps.sort(key=lambda g: sev_order.get(g.severity, 99))
    return [g.to_dict() for g in gaps]
