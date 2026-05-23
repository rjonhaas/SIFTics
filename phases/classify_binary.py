"""Multi-signal binary classifier — the HOT-layer fan-out.

For one candidate binary, fan out (in parallel where it makes sense) to:

    Rathbun baseline    (mcp_baseline)
        • is the hash in the known-good corpus?
        • does the name + path match a stock location?
    abuse.ch lookups    (mcp_cti)
        • MalwareBazaar hash hit?
        • ThreatFox IOC hit?
    capa behavioural    (subprocess to `capa` if installed)
        • capability tags (credential dumping, anti-debug, etc.)
    forensic RAG        (mcp_rag)
        • semantic match to Sigma / ATT&CK / LOLBAS / Atomic

Fuse the signals into a single verdict:

    classification: stock_known_good / unknown / suspicious / malicious
    confidence:     0..1   (Hypothesis-Engine-style weighted aggregate)
    signals:        [{source, finding, weight}, ...]
    recommended_action: ["pass", "warm_review", "isolate_proposal", ...]

This is the multi-signal-fusion pattern that closes the gap on Valhuntir's
2.6M-record windows-triage-mcp: instead of one big known-good list, four
narrower signals combine into a more confident verdict.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from siftics import audit


def _unwrap(tool):
    return tool.fn if hasattr(tool, "fn") else tool


# ---------------------------------------------------------------------------
# Per-signal collectors
# ---------------------------------------------------------------------------


def signal_baseline_hash(sha256: str | None) -> dict | None:
    if not sha256:
        return None
    try:
        from mcp_baseline import server as base
        r = _unwrap(base.lookup_by_sha256)(sha256)
    except RuntimeError as e:
        return {"source": "baseline_hash", "ok": False, "error": str(e)}
    if r["known"]:
        return {"source": "baseline_hash", "finding": "stock_known_good",
                "weight": -4, "details": {"matches": r["matches"][:3]}}
    return {"source": "baseline_hash", "finding": "hash_not_in_baseline",
            "weight": 1}


def signal_baseline_path(name: str | None, observed_path: str | None) -> dict | None:
    if not (name and observed_path):
        return None
    try:
        from mcp_baseline import server as base
        r = _unwrap(base.classify_path_anomaly)(name, observed_path)
    except RuntimeError as e:
        return {"source": "baseline_path", "ok": False, "error": str(e)}
    reason = r.get("reason", "")
    if reason == "matches_baseline_location":
        return {"source": "baseline_path", "finding": "path_matches_baseline",
                "weight": -3, "details": r}
    if reason == "name_exists_but_wrong_location":
        return {"source": "baseline_path", "finding": "masquerade",
                "weight": 4, "details": r}
    return {"source": "baseline_path", "finding": "name_not_in_baseline",
            "weight": 2, "details": r}


def signal_cti_hash(sha256: str | None) -> dict | None:
    if not sha256:
        return None
    try:
        from mcp_cti import server as cti
        r = _unwrap(cti.lookup_hash)(sha256)
    except RuntimeError as e:
        return {"source": "cti_hash", "ok": False, "error": str(e)}
    if r.get("found"):
        return {"source": "cti_hash", "finding": "malwarebazaar_hit",
                "weight": 5, "details": r.get("sample", {})}
    return {"source": "cti_hash", "finding": "no_malware_bazaar_match",
            "weight": -0.5}


def signal_capa(file_path: Path | None) -> dict | None:
    if not file_path or not file_path.exists():
        return None
    capa = shutil.which("capa")
    if not capa:
        return {"source": "capa", "ok": False,
                "error": "capa CLI not installed; install via "
                          "https://github.com/mandiant/capa/releases"}
    try:
        proc = subprocess.run(
            [capa, "--quiet", "--json", str(file_path)],
            capture_output=True, text=True, timeout=120, check=False)
    except subprocess.TimeoutExpired:
        return {"source": "capa", "ok": False, "error": "capa timed out"}
    if proc.returncode != 0 and not proc.stdout:
        return {"source": "capa", "ok": False,
                "error": (proc.stderr or proc.stdout)[:200]}
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"source": "capa", "ok": False, "error": "couldn't parse capa json"}
    # capa json structure: rules → ATT&CK / capability tags
    rules = list((report.get("rules") or {}).keys())
    tags = []
    for r_name, r_obj in (report.get("rules") or {}).items():
        meta = r_obj.get("meta", {})
        for att in (meta.get("att&ck") or []):
            tag = att.get("id") or att.get("technique") or ""
            if tag:
                tags.append(tag)
    bad_caps = [r for r in rules if any(k in r.lower() for k in
                ("credential", "lsass", "dump", "inject", "anti-debug",
                 "ransom", "encrypt files"))]
    if bad_caps:
        return {"source": "capa", "finding": "suspicious_capabilities",
                "weight": min(5.0, 1.0 + 0.5 * len(bad_caps)),
                "details": {"rules": bad_caps[:8], "attack": list(set(tags))[:10]}}
    return {"source": "capa", "finding": "no_suspicious_capabilities",
            "weight": -1, "details": {"rules_count": len(rules)}}


def signal_rag(query: str | None) -> dict | None:
    if not query:
        return None
    try:
        from mcp_rag import server as rag
        r = _unwrap(rag.forensic_rag_search)(query, top_k=5,
                                              source_filter=None, rerank=True)
    except RuntimeError as e:
        return {"source": "rag", "ok": False, "error": str(e)}
    hits = r.get("results", [])
    if not hits:
        return {"source": "rag", "finding": "no_rag_matches", "weight": 0}
    top = hits[0]
    return {"source": "rag", "finding": "rag_match",
            "weight": min(3.0, top.get("_rerank_score", top.get("_score", 0)) * 3),
            "details": {"top_id": top.get("id"),
                         "top_title": top.get("title", "")[:80],
                         "top_attack": top.get("attack_techniques", []),
                         "matches": len(hits)}}


# ---------------------------------------------------------------------------
# Fusion
# ---------------------------------------------------------------------------


def _classify(score: float) -> str:
    if score >= 5:
        return "malicious"
    if score >= 2:
        return "suspicious"
    if score <= -3:
        return "stock_known_good"
    return "unknown"


def _recommended_action(classification: str, signals: list[dict]) -> list[str]:
    if classification == "malicious":
        return ["propose_authority_gate:isolate_host",
                "propose_authority_gate:execute_hunt_package",
                "asr_append"]
    if classification == "suspicious":
        return ["warm_review", "asr_append:linked_findings",
                "consider_hunt_proposal"]
    if classification == "stock_known_good":
        return ["pass"]
    return ["warm_review_low_priority"]


def classify_binary(*,
                    sha256: str | None = None,
                    name: str | None = None,
                    observed_path: str | None = None,
                    file_path: Path | None = None,
                    description: str | None = None) -> dict:
    """Run all available signals and fuse into a single verdict.

    Any signal source whose backend isn't installed is recorded as an error
    but does not crash the call — the fusion still happens over the available
    signals.
    """
    started = time.time()
    raw_signals: list[dict | None] = [
        signal_baseline_hash(sha256),
        signal_baseline_path(name, observed_path),
        signal_cti_hash(sha256),
        signal_capa(file_path),
        signal_rag(description or
                    (f"binary {name} at {observed_path}" if name else None)),
    ]
    signals = [s for s in raw_signals if s is not None]
    weighted = [s for s in signals if "weight" in s]
    aggregate = sum(s["weight"] for s in weighted)
    classification = _classify(aggregate)
    pos = sum(s["weight"] for s in weighted if s["weight"] > 0)
    neg = sum(-s["weight"] for s in weighted if s["weight"] < 0)
    confidence = round(pos / (pos + neg), 3) if (pos + neg) else 0.0

    verdict = {
        "classification": classification,
        "aggregate_score": round(aggregate, 3),
        "confidence": confidence,
        "signals": signals,
        "recommended_action": _recommended_action(classification, signals),
        "input": {
            "sha256": sha256, "name": name,
            "observed_path": observed_path,
            "file_path": str(file_path) if file_path else None,
            "description": description,
        },
        "elapsed_seconds": round(time.time() - started, 3),
    }
    audit.append_event("classify_binary",
                       {"classification": classification,
                         "aggregate_score": verdict["aggregate_score"],
                         "confidence": confidence,
                         "name": name, "observed_path": observed_path,
                         "sha256": sha256,
                         "signals_used": [s["source"] for s in signals]},
                       actor="hot_layer")
    return verdict


def main() -> int:
    parser = argparse.ArgumentParser(description="Multi-signal binary classifier.")
    parser.add_argument("--sha256")
    parser.add_argument("--name", help="filename (e.g. lsass_helper.exe)")
    parser.add_argument("--observed-path")
    parser.add_argument("--file", type=Path,
                         help="local path to the binary (for capa)")
    parser.add_argument("--description",
                         help="natural-language description for the RAG step")
    args = parser.parse_args()
    if not (args.sha256 or args.name or args.observed_path or args.file):
        parser.error("at least one of --sha256/--name/--observed-path/--file is required.")
    if not os.environ.get("SIFTICS_CASE_DIR"):
        raise SystemExit("SIFTICS_CASE_DIR is required.")
    verdict = classify_binary(
        sha256=args.sha256, name=args.name,
        observed_path=args.observed_path,
        file_path=args.file, description=args.description,
    )
    print(json.dumps(verdict, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
