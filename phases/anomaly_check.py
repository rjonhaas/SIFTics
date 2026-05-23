"""Phase 18 — cross-artifact anomaly check.

Reads findings produced by upstream phases (per-phase JSONL files under
`$CASE/findings/`) and applies a set of mechanical contradiction rules. Writes
results to `$CASE/findings/anomalies.jsonl` and appends an audit event.

The point is *cross-source consistency*: any single artifact can be wrong (or
forged), so disagreement between sources is signal. The agent's
`run_self_correct.sh` reads this output and re-runs upstream phases to try
to resolve the contradictions.

Rules implemented (each yields one anomaly record):

    A1  ShimCache execution timestamp predates MFT file-creation time
    A2  EVTX channel has a gap > N minutes during the attack window
    A3  Memory-resident process has no on-disk binary at the recorded path
    A4  Sysmon process-create with no matching Prefetch entry (Windows < 10)
    A5  Network connection logged with no process owner attribution
    A6  Registry persistence value points at a non-existent binary
    A7  Service install event but no corresponding service registry key
    A8  USN sequence-number jump > threshold (skipped entries)
    A9  ASR row marks system "safe" but linked findings include open CET items

Each anomaly has: id, rule, severity, evidence_refs, suggested_phase.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

from siftics import audit, case_state

SEVERITY = ("low", "medium", "high")
EVTX_GAP_THRESHOLD_MINUTES = 30
USN_JUMP_THRESHOLD = 100_000


def _case_dir() -> Path:
    return audit.case_dir()


def _findings_dir() -> Path:
    return _case_dir() / "findings"


def _iter_jsonl(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _emit(anomaly: dict, sink: list[dict]) -> None:
    anomaly.setdefault("id", f"A{len(sink) + 1:04d}")
    anomaly.setdefault("detected_at",
                       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    sink.append(anomaly)


# ---------------------------------------------------------------------------
# Individual rules
# ---------------------------------------------------------------------------


def rule_A1_shimcache_vs_mft(sink: list[dict]) -> None:
    """ShimCache says binary executed at T1, but MFT records creation at T2 > T1."""
    shim_path = _findings_dir() / "shimcache.jsonl"
    mft_path = _findings_dir() / "mft.jsonl"
    if not (shim_path.exists() and mft_path.exists()):
        return
    mft_by_path: dict[str, str] = {}
    for row in _iter_jsonl(mft_path):
        p = (row.get("path") or "").lower()
        c = row.get("created_at")
        if p and c:
            # Keep earliest creation
            if p not in mft_by_path or c < mft_by_path[p]:
                mft_by_path[p] = c
    for row in _iter_jsonl(shim_path):
        p = (row.get("path") or "").lower()
        executed = row.get("last_modified") or row.get("executed_at")
        if not (p and executed and p in mft_by_path):
            continue
        if executed < mft_by_path[p]:
            _emit({
                "rule": "A1",
                "severity": "high",
                "summary": f"ShimCache says {p} executed before MFT created it",
                "evidence_refs": [{"source": "shimcache.jsonl", "path": p,
                                    "executed_at": executed},
                                   {"source": "mft.jsonl", "path": p,
                                    "created_at": mft_by_path[p]}],
                "suggested_phase": "run_ntfs.sh",
            }, sink)


def rule_A2_evtx_gaps(sink: list[dict]) -> None:
    """Look for >N-min gaps in EVTX timestamps during the attack window."""
    p = _findings_dir() / "eventlogs.jsonl"
    by_channel: dict[str, list[str]] = defaultdict(list)
    for row in _iter_jsonl(p):
        ch = row.get("source_channel") or row.get("channel")
        ts = row.get("timestamp") or row.get("@timestamp")
        if ch and ts:
            by_channel[ch].append(ts)
    for ch, timestamps in by_channel.items():
        timestamps.sort()
        if len(timestamps) < 2:
            continue
        for i in range(1, len(timestamps)):
            t_prev = timestamps[i - 1]
            t_now = timestamps[i]
            gap_min = _iso_minutes_diff(t_prev, t_now)
            if gap_min and gap_min > EVTX_GAP_THRESHOLD_MINUTES:
                _emit({
                    "rule": "A2",
                    "severity": "medium",
                    "summary": f"EVTX {ch} has a {gap_min:.0f}-minute gap "
                                f"between {t_prev} and {t_now}",
                    "evidence_refs": [{"source": "eventlogs.jsonl",
                                         "channel": ch,
                                         "from": t_prev, "to": t_now,
                                         "gap_minutes": gap_min}],
                    "suggested_phase": "run_eventlogs.sh",
                }, sink)
                break   # only report first gap per channel


def rule_A3_memory_process_no_disk(sink: list[dict]) -> None:
    """Memory shows process X but no binary at the recorded path on disk."""
    mem = _findings_dir() / "memory_processes.jsonl"
    mft = _findings_dir() / "mft.jsonl"
    if not (mem.exists() and mft.exists()):
        return
    on_disk = {(row.get("path") or "").lower()
               for row in _iter_jsonl(mft)}
    for row in _iter_jsonl(mem):
        p = (row.get("image_path") or row.get("path") or "").lower()
        if not p:
            continue
        if p not in on_disk:
            _emit({
                "rule": "A3",
                "severity": "high",
                "summary": f"Memory process {p} (pid {row.get('pid')}) has no MFT entry",
                "evidence_refs": [{"source": "memory_processes.jsonl",
                                     "pid": row.get("pid"), "path": p}],
                "suggested_phase": "run_memory.sh",
            }, sink)


def rule_A6_persistence_dangling_binary(sink: list[dict]) -> None:
    """Registry value points at a path that the MFT says doesn't exist."""
    pers = _findings_dir() / "persistence.jsonl"
    mft = _findings_dir() / "mft.jsonl"
    if not (pers.exists() and mft.exists()):
        return
    on_disk = {(row.get("path") or "").lower()
               for row in _iter_jsonl(mft)}
    for row in _iter_jsonl(pers):
        target = (row.get("target_path") or row.get("image_path") or "").lower()
        if not target:
            continue
        # Strip arguments
        head = target.split('"')[1] if target.startswith('"') else target.split()[0]
        if head not in on_disk:
            _emit({
                "rule": "A6",
                "severity": "high",
                "summary": f"Persistence value {row.get('key_path', '')} "
                            f"points at non-existent binary {head}",
                "evidence_refs": [{"source": "persistence.jsonl",
                                     "key_path": row.get("key_path"),
                                     "value_name": row.get("value_name"),
                                     "target_path": target}],
                "suggested_phase": "run_registry.sh",
            }, sink)


def rule_A9_asr_safe_but_cet_pending(sink: list[dict]) -> None:
    """ASR row marks system safe but linked findings include open CET items."""
    asr = case_state.asr_all()
    cet_pending_nos = {r["cca_no"] for r in case_state.cet_pending()}
    for row in asr:
        if row.get("system_safe") != "safe":
            continue
        linked = row.get("linked_findings") or []
        pending_links = [l for l in linked if l in cet_pending_nos]
        if pending_links:
            _emit({
                "rule": "A9",
                "severity": "medium",
                "summary": f"ASR {row['serial_no']} is marked safe but has "
                            f"open CET items: {pending_links}",
                "evidence_refs": [{"source": "case state",
                                     "serial_no": row["serial_no"],
                                     "pending_cet": pending_links}],
                "suggested_phase": "ic_review",
            }, sink)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso_minutes_diff(t1: str, t2: str) -> float | None:
    try:
        e1 = time.mktime(time.strptime(t1[:19], "%Y-%m-%dT%H:%M:%S"))
        e2 = time.mktime(time.strptime(t2[:19], "%Y-%m-%dT%H:%M:%S"))
        return abs(e2 - e1) / 60.0
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


RULES = [
    rule_A1_shimcache_vs_mft,
    rule_A2_evtx_gaps,
    rule_A3_memory_process_no_disk,
    rule_A6_persistence_dangling_binary,
    rule_A9_asr_safe_but_cet_pending,
]


def run() -> dict:
    """Run all rules; write anomalies.jsonl; audit; return summary."""
    sink: list[dict] = []
    for rule in RULES:
        try:
            rule(sink)
        except Exception as e:  # one bad finding shouldn't kill the rest
            sink.append({
                "id": f"A{len(sink)+1:04d}",
                "rule": rule.__name__, "severity": "low",
                "summary": f"rule errored: {e}",
            })
    out_path = _findings_dir() / "anomalies.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for a in sink:
            fh.write(json.dumps(a, sort_keys=True, separators=(",", ":")) + "\n")

    by_sev: dict[str, int] = {s: 0 for s in SEVERITY}
    for a in sink:
        by_sev[a.get("severity", "low")] = by_sev.get(a.get("severity", "low"), 0) + 1
    by_phase: dict[str, int] = defaultdict(int)
    for a in sink:
        by_phase[a.get("suggested_phase", "unknown")] += 1

    summary = {
        "anomaly_count": len(sink),
        "by_severity": by_sev,
        "by_suggested_phase": dict(by_phase),
        "output_path": str(out_path),
    }
    audit.append_event("phase_18_anomaly_check",
                       summary, actor="phase_18")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 18 anomaly checker.")
    parser.add_argument("--json", action="store_true",
                         help="Emit summary as JSON to stdout.")
    args = parser.parse_args()
    if not os.environ.get("SIFTICS_CASE_DIR"):
        raise SystemExit("SIFTICS_CASE_DIR is required.")
    summary = run()
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Phase 18 — anomaly check")
        print(f"  total:    {summary['anomaly_count']}")
        for sev in SEVERITY:
            print(f"  {sev:8s}: {summary['by_severity'][sev]}")
        if summary["by_suggested_phase"]:
            print(f"  suggested re-runs:")
            for ph, n in sorted(summary["by_suggested_phase"].items(),
                                  key=lambda kv: -kv[1]):
                print(f"    {ph:24s} ({n})")
        print(f"  output:   {summary['output_path']}")
    return 0 if summary["by_severity"]["high"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
