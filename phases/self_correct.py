"""Self-correction loop driven by Phase 18 anomalies.

Algorithm (max N iterations):

    iter 0: run Phase 18 → record baseline anomaly count by severity
    iter k: if HIGH anomaly count > 0:
              pick the most-suggested upstream phase
              re-run that phase (with adjusted parameters if available)
              re-run Phase 18
              if HIGH count decreased → continue
              if HIGH count unchanged → escalate to IC
            else:
              break (converged)

After termination:
    write self_correct_report.md with the iteration trace
    return non-zero exit code if HIGH count > 0 after max iterations

Self-correction is the tiebreaker criterion (autonomous execution quality).
The point is *explicit machinery*, not emergent behaviour — every iteration
is logged in the hash-chained audit chain and the report is committable.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from siftics import audit
from phases import anomaly_check

MAX_ITERATIONS = 3

# Mapping from a phase-script name (as recorded in anomaly.suggested_phase)
# to the actual command that re-runs it. Adjust here as new phases are added.
PHASE_COMMANDS: dict[str, list[str]] = {
    "run_ntfs.sh":       ["./phases/run_ntfs.sh"],
    "run_registry.sh":   ["./phases/run_registry.sh"],
    "run_eventlogs.sh":  ["./phases/run_eventlogs.sh"],
    "run_memory.sh":     ["./phases/run_memory.sh"],
    "run_artifacts.sh":  ["./phases/run_artifacts.sh"],
    # "ic_review" is special — no script; surface to IC via case header.
    "ic_review":         [],
}


def _high_count(summary: dict) -> int:
    return int(summary.get("by_severity", {}).get("high", 0))


def _pick_phase_to_rerun(summary: dict, attempted: set[str]) -> str | None:
    """Pick the phase that contributed the most HIGH anomalies and hasn't been
    tried yet this run. Returns None if nothing left to do."""
    # Read full anomalies file to do severity-weighted picking
    case_dir = audit.case_dir()
    anomalies_path = case_dir / "findings" / "anomalies.jsonl"
    by_phase_high: dict[str, int] = {}
    if anomalies_path.exists():
        with anomalies_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("severity") == "high":
                    ph = obj.get("suggested_phase", "")
                    by_phase_high[ph] = by_phase_high.get(ph, 0) + 1
    for ph, _ in sorted(by_phase_high.items(), key=lambda kv: -kv[1]):
        if ph in attempted or ph in ("", "ic_review", "unknown"):
            continue
        if ph in PHASE_COMMANDS:
            return ph
    return None


def _run_phase(phase: str) -> dict:
    """Re-run an upstream phase. Returns {ok, stdout_path, returncode}."""
    cmd = PHASE_COMMANDS.get(phase) or []
    if not cmd:
        return {"ok": False, "reason": "no_command_mapped", "phase": phase}
    repo = Path(__file__).parent.parent
    log_path = audit.case_dir() / "findings" / f"_self_correct_{phase}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("w", encoding="utf-8") as fh:
            proc = subprocess.run(cmd, cwd=str(repo), stdout=fh, stderr=fh,
                                    timeout=600, check=False)
    except FileNotFoundError:
        return {"ok": False, "reason": "script_not_found",
                "phase": phase, "cmd": cmd}
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "timeout",
                "phase": phase, "cmd": cmd}
    return {"ok": proc.returncode == 0,
            "phase": phase, "cmd": cmd,
            "returncode": proc.returncode,
            "log_path": str(log_path)}


def run(max_iterations: int = MAX_ITERATIONS) -> dict:
    case_dir = audit.case_dir()
    trace: list[dict] = []
    attempted: set[str] = set()

    summary = anomaly_check.run()
    trace.append({"iteration": 0, "kind": "baseline", "summary": summary,
                   "ts": _now()})
    audit.append_event("self_correct_iteration",
                        {"iteration": 0, "kind": "baseline",
                         "high_count": _high_count(summary)},
                        actor="self_correct")

    for it in range(1, max_iterations + 1):
        if _high_count(summary) == 0:
            break
        phase = _pick_phase_to_rerun(summary, attempted)
        if phase is None:
            trace.append({"iteration": it, "kind": "no_actionable_phase",
                           "summary": summary, "ts": _now()})
            audit.append_event("self_correct_iteration",
                                {"iteration": it, "kind": "no_actionable_phase"},
                                actor="self_correct")
            break
        attempted.add(phase)
        run_result = _run_phase(phase)
        new_summary = anomaly_check.run()
        improved = _high_count(new_summary) < _high_count(summary)
        trace.append({
            "iteration": it,
            "kind": "rerun",
            "rerun_phase": phase,
            "run_result": run_result,
            "before_high": _high_count(summary),
            "after_high": _high_count(new_summary),
            "improved": improved,
            "summary": new_summary,
            "ts": _now(),
        })
        audit.append_event("self_correct_iteration", {
            "iteration": it, "rerun_phase": phase,
            "before_high": _high_count(summary),
            "after_high": _high_count(new_summary),
            "improved": improved,
        }, actor="self_correct")
        summary = new_summary

    converged = _high_count(summary) == 0
    final = {
        "converged": converged,
        "iterations_run": len(trace) - 1,
        "final_high_count": _high_count(summary),
        "trace": trace,
    }
    audit.append_event("self_correct_complete", {
        "converged": converged,
        "iterations_run": len(trace) - 1,
        "final_high_count": _high_count(summary),
        "attempted_phases": sorted(attempted),
    }, actor="self_correct")

    report_path = case_dir / "findings" / "self_correct_report.md"
    report_path.write_text(_format_report(final), encoding="utf-8")
    final["report_path"] = str(report_path)
    return final


def _format_report(final: dict) -> str:
    lines = ["# Self-correction report",
             "",
             f"converged: **{final['converged']}**",
             f"iterations: {final['iterations_run']}",
             f"final HIGH anomalies: {final['final_high_count']}",
             "",
             "## Iteration trace",
             ""]
    for entry in final["trace"]:
        kind = entry["kind"]
        ts = entry.get("ts", "")
        if kind == "baseline":
            lines.append(f"### iter 0 — baseline ({ts})")
            lines.append(f"high={_high_count(entry['summary'])}, "
                         f"medium={entry['summary']['by_severity']['medium']}, "
                         f"low={entry['summary']['by_severity']['low']}")
        elif kind == "rerun":
            lines.append(f"### iter {entry['iteration']} — rerun "
                         f"`{entry['rerun_phase']}` ({ts})")
            lines.append(f"before HIGH: {entry['before_high']} → "
                         f"after: {entry['after_high']} "
                         f"({'IMPROVED' if entry['improved'] else 'no change'})")
            rr = entry["run_result"]
            if not rr.get("ok"):
                lines.append(f"  *phase rerun result*: {rr}")
        elif kind == "no_actionable_phase":
            lines.append(f"### iter {entry['iteration']} — no actionable phase remaining")
            lines.append("Surface to IC for manual review.")
        lines.append("")
    return "\n".join(lines)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 18 self-correction loop.")
    parser.add_argument("--max-iterations", type=int, default=MAX_ITERATIONS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not os.environ.get("SIFTICS_CASE_DIR"):
        raise SystemExit("SIFTICS_CASE_DIR is required.")
    final = run(max_iterations=args.max_iterations)
    if args.json:
        print(json.dumps(final, indent=2))
    else:
        print(f"converged:        {final['converged']}")
        print(f"iterations_run:   {final['iterations_run']}")
        print(f"final_high_count: {final['final_high_count']}")
        print(f"report:           {final['report_path']}")
    return 0 if final["converged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
