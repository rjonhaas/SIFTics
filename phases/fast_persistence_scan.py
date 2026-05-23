"""HOT-layer: fast persistence scan.

Inputs (either via CLI flags or by reading $CASE/evidence/):
    --run-keys-json       JSON list of {hive, key_path, value_name, target_path}
    --services-json       JSON list of {name, image_path}
    --scheduled-json      JSON list of {task_name, action}

For each entry: diff against mcp_baseline. Anything not in baseline becomes a
finding. Writes results to $CASE/findings/persistence.jsonl with a severity
based on the kind of mismatch.

Speed budget: < 10 s for typical host (hundreds of values).
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from siftics import audit


def _baseline():
    """Lazy import — only required when we actually run a check."""
    from mcp_baseline import server
    return server


def _unwrap(tool):
    return tool.fn if hasattr(tool, "fn") else tool


def scan_run_keys(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    b = _baseline()
    for row in rows:
        hive = row.get("hive", "")
        key_path = row.get("key_path", "")
        value_name = row.get("value_name", "")
        target_path = row.get("target_path", "")
        lookup = _unwrap(b.lookup_registry_value)(hive, key_path, value_name)
        if lookup.get("known"):
            continue
        finding = {
            "kind": "persistence",
            "subkind": "registry_run_key",
            "hive": hive,
            "key_path": key_path,
            "value_name": value_name,
            "target_path": target_path,
            "severity": "medium",
            "reason": "value not in Rathbun baseline",
        }
        if target_path:
            # Higher severity if the target path is also outside baseline
            head = target_path.strip('"').split()[0]
            target_lookup = _unwrap(b.classify_path_anomaly)("", head)
            # classify_path_anomaly returns anomaly:True if name not in baseline
            if target_lookup.get("reason") in (
                    "name_not_in_baseline", "name_exists_but_wrong_location"):
                finding["severity"] = "high"
                finding["reason"] += f"; target path {target_lookup['reason']}"
        out.append(finding)
    return out


def scan_services(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    b = _baseline()
    for row in rows:
        name = row.get("name", "")
        image_path = row.get("image_path", "")
        lookup = _unwrap(b.lookup_service)(name, image_path)
        if lookup.get("known"):
            continue
        finding = {
            "kind": "persistence",
            "subkind": "service",
            "service_name": name,
            "image_path": image_path,
            "severity": "high" if image_path and "system32" not in image_path.lower() else "medium",
            "reason": "service not in Rathbun baseline",
        }
        out.append(finding)
    return out


def scan_scheduled_tasks(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    b = _baseline()
    for row in rows:
        task_name = row.get("task_name", "")
        action = row.get("action", "")
        lookup = _unwrap(b.lookup_scheduled_task)(task_name)
        if lookup.get("known"):
            continue
        out.append({
            "kind": "persistence",
            "subkind": "scheduled_task",
            "task_name": task_name,
            "action": action,
            "severity": "high" if any(s in task_name for s in
                                        ("Update", "Security", "Defender"))
                         else "medium",
            "reason": "scheduled task not in Rathbun baseline",
        })
    return out


def _load_json(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else []


def run(run_keys_path: Path | None = None,
        services_path: Path | None = None,
        scheduled_path: Path | None = None) -> dict:
    findings: list[dict] = []
    if run_keys_path:
        findings += scan_run_keys(_load_json(run_keys_path))
    if services_path:
        findings += scan_services(_load_json(services_path))
    if scheduled_path:
        findings += scan_scheduled_tasks(_load_json(scheduled_path))

    output = audit.case_dir() / "findings" / "persistence.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f, sort_keys=True, separators=(",", ":")) + "\n")
    by_sev = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_sev[f.get("severity", "low")] = by_sev.get(f.get("severity", "low"), 0) + 1
    summary = {
        "total": len(findings),
        "by_severity": by_sev,
        "output_path": str(output),
        "elapsed_seconds": None,
    }
    audit.append_event("fast_persistence_scan", summary, actor="hot_layer")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="HOT-layer fast persistence scan.")
    parser.add_argument("--run-keys-json", type=Path)
    parser.add_argument("--services-json", type=Path)
    parser.add_argument("--scheduled-json", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not os.environ.get("SIFTICS_CASE_DIR"):
        raise SystemExit("SIFTICS_CASE_DIR is required.")
    started = time.time()
    summary = run(args.run_keys_json, args.services_json, args.scheduled_json)
    summary["elapsed_seconds"] = round(time.time() - started, 3)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"persistence findings:  {summary['total']}")
        print(f"  high:    {summary['by_severity']['high']}")
        print(f"  medium:  {summary['by_severity']['medium']}")
        print(f"  low:     {summary['by_severity']['low']}")
        print(f"  output:  {summary['output_path']}")
        print(f"  elapsed: {summary['elapsed_seconds']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
