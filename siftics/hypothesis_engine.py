"""Hypothesis Engine — mechanical signal-weighted theory tracking.

Append-only JSONL ledger at `$CASE/hypotheses.jsonl`. Confidence is computed
arithmetically from signal weights — never LLM-estimated. This is the
deliberate counter-anchor described in `skills/hypothesis-engine.md`.

CLI (registered as `hypothesis_score`):
    add     "<statement>"                            → opens hypothesis, prints id
    signal  <id> <weight> "<reason>" [--audit-event N]
    score   <id>                                     → prints confidence number
    report                                           → markdown table
    retire  <id> --reason "..."                      → marks closed
"""
from __future__ import annotations

import argparse
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from .audit import append_event, case_dir

Status = Literal["open", "retired", "confirmed", "disconfirmed"]


@dataclass
class Signal:
    weight: float
    reason: str
    added_at: str
    audit_event_seq: int | None = None


@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    opened_at: str
    status: Status = "open"
    signals: list[Signal] = field(default_factory=list)
    closed_at: str | None = None
    closed_reason: str | None = None


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------


def _path() -> Path:
    return case_dir() / "hypotheses.jsonl"


def _read_all() -> list[Hypothesis]:
    p = _path()
    if not p.exists():
        return []
    out: list[Hypothesis] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            signals = [Signal(**s) for s in d.get("signals", [])]
            d["signals"] = signals
            out.append(Hypothesis(**d))
    return out


def _write_all(hyps: list[Hypothesis]) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        for h in hyps:
            d = asdict(h)
            fh.write(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _id() -> str:
    return f"H-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------


def add(statement: str) -> Hypothesis:
    h = Hypothesis(hypothesis_id=_id(), statement=statement, opened_at=_now())
    hyps = _read_all()
    hyps.append(h)
    _write_all(hyps)
    append_event("hypothesis_opened",
                 {"hypothesis_id": h.hypothesis_id,
                  "statement_first_120": statement[:120]},
                 actor="hypothesis_engine")
    return h


def signal(hypothesis_id: str, weight: float, reason: str,
           audit_event_seq: int | None = None) -> Hypothesis:
    hyps = _read_all()
    target = next((h for h in hyps if h.hypothesis_id == hypothesis_id), None)
    if target is None:
        raise KeyError(f"unknown hypothesis: {hypothesis_id}")
    if target.status != "open":
        raise ValueError(f"hypothesis {hypothesis_id} is {target.status}, can't add signal")
    target.signals.append(Signal(weight=float(weight), reason=reason,
                                  added_at=_now(),
                                  audit_event_seq=audit_event_seq))
    _write_all(hyps)
    append_event("hypothesis_signal",
                 {"hypothesis_id": hypothesis_id, "weight": float(weight),
                  "audit_event_seq": audit_event_seq,
                  "reason_first_80": reason[:80]},
                 actor="hypothesis_engine")
    return target


def score(hypothesis_id: str) -> float:
    """Compute mechanical confidence in [0, 1]."""
    h = get(hypothesis_id)
    return _score_h(h)


def _score_h(h: Hypothesis) -> float:
    if not h.signals:
        return 0.0
    pos = sum(s.weight for s in h.signals if s.weight > 0)
    neg = sum(-s.weight for s in h.signals if s.weight < 0)
    if pos + neg == 0:
        return 0.0
    return round(pos / (pos + neg), 3)


def get(hypothesis_id: str) -> Hypothesis:
    h = next((x for x in _read_all() if x.hypothesis_id == hypothesis_id), None)
    if h is None:
        raise KeyError(f"unknown hypothesis: {hypothesis_id}")
    return h


def retire(hypothesis_id: str, reason: str,
           new_status: Status = "retired") -> Hypothesis:
    hyps = _read_all()
    target = next((h for h in hyps if h.hypothesis_id == hypothesis_id), None)
    if target is None:
        raise KeyError(f"unknown hypothesis: {hypothesis_id}")
    target.status = new_status
    target.closed_at = _now()
    target.closed_reason = reason
    _write_all(hyps)
    append_event("hypothesis_closed",
                 {"hypothesis_id": hypothesis_id,
                  "status": new_status, "reason_first_120": reason[:120]},
                 actor="hypothesis_engine")
    return target


def report_markdown() -> str:
    hyps = _read_all()
    open_h = sorted([h for h in hyps if h.status == "open"],
                     key=lambda h: -_score_h(h))
    closed_h = [h for h in hyps if h.status != "open"]

    lines = ["# Hypothesis ledger", ""]
    if open_h:
        lines += ["## Open theories (descending confidence)", "",
                  "| ID | Confidence | Signals | Statement |",
                  "|---|---|---|---|"]
        for h in open_h:
            lines.append(
                f"| `{h.hypothesis_id}` | **{_score_h(h):.3f}** "
                f"| {len(h.signals)} | {h.statement[:80].replace('|','/')} |"
            )
        lines.append("")
    if closed_h:
        lines += ["## Closed theories", "",
                  "| ID | Status | Reason | Statement |",
                  "|---|---|---|---|"]
        for h in closed_h:
            lines.append(
                f"| `{h.hypothesis_id}` | {h.status} "
                f"| {(h.closed_reason or '')[:60].replace('|','/')} "
                f"| {h.statement[:80].replace('|','/')} |"
            )
    if not (open_h or closed_h):
        lines.append("*no hypotheses recorded yet*")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="SIFTics Hypothesis Engine.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="Open a new hypothesis.")
    p_add.add_argument("statement")

    p_sig = sub.add_parser("signal", help="Add a weighted signal.")
    p_sig.add_argument("hypothesis_id")
    p_sig.add_argument("weight", type=float)
    p_sig.add_argument("reason")
    p_sig.add_argument("--audit-event", type=int, default=None)

    p_sc = sub.add_parser("score", help="Print current confidence.")
    p_sc.add_argument("hypothesis_id")

    p_rep = sub.add_parser("report", help="Markdown report of all theories.")

    p_ret = sub.add_parser("retire", help="Close a hypothesis.")
    p_ret.add_argument("hypothesis_id")
    p_ret.add_argument("--reason", required=True)
    p_ret.add_argument("--status",
                        choices=["retired", "confirmed", "disconfirmed"],
                        default="retired")

    args = parser.parse_args()

    if args.cmd == "add":
        h = add(args.statement)
        print(h.hypothesis_id)
    elif args.cmd == "signal":
        h = signal(args.hypothesis_id, args.weight, args.reason,
                    audit_event_seq=args.audit_event)
        print(f"{h.hypothesis_id}  confidence={_score_h(h):.3f}  "
              f"(signals={len(h.signals)})")
    elif args.cmd == "score":
        print(f"{score(args.hypothesis_id):.3f}")
    elif args.cmd == "report":
        print(report_markdown())
    elif args.cmd == "retire":
        h = retire(args.hypothesis_id, args.reason, new_status=args.status)
        print(f"{h.hypothesis_id}  status={h.status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
