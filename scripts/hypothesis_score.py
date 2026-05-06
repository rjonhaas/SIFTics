#!/usr/bin/env python3
"""
hypothesis_score.py — Hypothesis Engine for SIFTics.

Maintains an append-only JSONL ledger at <CASE_ROOT>/analysis/hypotheses.jsonl.
Each line is a hypothesis state at a point in time; the latest entry per `id`
is the current state.

Subcommands:
  add       — Create a new hypothesis (auto-assigns next H### ID)
  signal    — Add a signal_for or signal_against to an existing hypothesis
  score     — Re-score every active hypothesis based on signals; apply
              confirmation cap and stale-decay
  report    — Print current ledger summary to stdout (and write
              hypotheses_current.md for COP injection)
  retire    — Manually retire a hypothesis with a reason

Each operation writes a NEW JSONL line for the affected hypothesis (append-only).

Confidence formula:
    confidence = clamp(0.0, 1.0,
        sum(signals_for[i].weight) - sum(signals_against[i].weight))

Status transitions:
    confidence >= 0.85           → confirmed
    any signal_against weight >= 0.5 → contradicted (overrides confirmation)
    confidence < 0.2             → retired
    otherwise                    → active

Stale decay (applied during `score`):
    If hypothesis not updated for >=2 periods AND status==active,
    confidence *= 0.7 per stale period.
"""

import argparse
import datetime
import json
import os
import sys
from collections import defaultdict


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def ledger_path(case_root):
    return os.path.join(case_root, "analysis", "hypotheses.jsonl")


def load_ledger(case_root):
    """Return list of all entries in append order."""
    path = ledger_path(case_root)
    if not os.path.isfile(path):
        return []
    entries = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"WARN: skipping malformed line: {exc}", file=sys.stderr)
    return entries


def latest_per_id(entries):
    """Return dict id → latest entry (by file order, last wins)."""
    by_id = {}
    for e in entries:
        by_id[e["id"]] = e
    return by_id


def append_entry(case_root, entry):
    path = ledger_path(case_root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def next_id(case_root):
    entries = load_ledger(case_root)
    used = {e["id"] for e in entries}
    n = 1
    while True:
        candidate = f"H{n:03d}"
        if candidate not in used:
            return candidate
        n += 1


def parse_signal(raw):
    """Parse signal arg of form 'source|finding|weight' or
    a JSON-quoted dict. Returns dict."""
    if raw.startswith("{"):
        return json.loads(raw)
    parts = raw.split("|")
    if len(parts) != 3:
        raise ValueError(
            f"signal must be 'source|finding|weight' or JSON; got: {raw}"
        )
    return {
        "source": parts[0].strip(),
        "finding": parts[1].strip(),
        "weight": float(parts[2].strip()),
    }


# ── subcommands ──────────────────────────────────────────────────────────


def cmd_add(args):
    case_root = args.case_root
    hyp_id = next_id(case_root)
    signals_for = []
    for sf in args.signal_for or []:
        sig = parse_signal(sf)
        sig["added_period"] = args.period
        signals_for.append(sig)
    signals_against = []
    for sa in args.signal_against or []:
        sig = parse_signal(sa)
        sig["added_period"] = args.period
        signals_against.append(sig)
    confidence = max(
        0.0,
        min(
            1.0,
            sum(s["weight"] for s in signals_for)
            - sum(s["weight"] for s in signals_against),
        ),
    )
    status = "active"
    if confidence >= 0.85:
        status = "confirmed"
    if any(s["weight"] >= 0.5 for s in signals_against):
        status = "contradicted"
    if confidence < 0.2:
        status = "retired"

    entry = {
        "id": hyp_id,
        "period": args.period,
        "hypothesis": args.hypothesis,
        "status": status,
        "created_period": args.period,
        "last_updated_utc": now_utc(),
        "signals_for": signals_for,
        "signals_against": signals_against,
        "confidence": round(confidence, 3),
        "alternatives_considered": args.alternatives or [],
    }
    append_entry(case_root, entry)
    print(
        f"Added {hyp_id} (period {args.period}, status={status}, "
        f"confidence={confidence:.2f})"
    )


def cmd_signal(args):
    case_root = args.case_root
    entries = load_ledger(case_root)
    cur = latest_per_id(entries)
    if args.id not in cur:
        print(f"ERROR: hypothesis {args.id} not found", file=sys.stderr)
        sys.exit(2)
    h = json.loads(json.dumps(cur[args.id]))  # deep copy

    new_signal = {
        "source": args.source,
        "finding": args.finding,
        "weight": args.weight,
        "added_period": args.period,
    }
    if args.kind == "for":
        h["signals_for"].append(new_signal)
    else:
        h["signals_against"].append(new_signal)

    confidence = max(
        0.0,
        min(
            1.0,
            sum(s["weight"] for s in h["signals_for"])
            - sum(s["weight"] for s in h["signals_against"]),
        ),
    )
    status = "active"
    if confidence >= 0.85:
        status = "confirmed"
    if any(s["weight"] >= 0.5 for s in h["signals_against"]):
        status = "contradicted"
    if confidence < 0.2:
        status = "retired"

    h["period"] = args.period
    h["status"] = status
    h["confidence"] = round(confidence, 3)
    h["last_updated_utc"] = now_utc()

    append_entry(case_root, h)
    print(
        f"{args.id} updated: signal_{args.kind} added "
        f"(weight={args.weight}); confidence={confidence:.2f} status={status}"
    )


def cmd_score(args):
    case_root = args.case_root
    entries = load_ledger(case_root)
    cur = latest_per_id(entries)
    period = args.period

    rescored = 0
    for hyp_id, h in cur.items():
        if h["status"] in ("retired", "confirmed", "contradicted"):
            continue
        # Stale decay
        last_period = h.get("period", 0)
        gap = period - last_period
        confidence = max(
            0.0,
            min(
                1.0,
                sum(s["weight"] for s in h["signals_for"])
                - sum(s["weight"] for s in h["signals_against"]),
            ),
        )
        if gap >= 2 and h["status"] == "active":
            confidence *= 0.7 ** (gap - 1)

        status = "active"
        if confidence >= 0.85:
            status = "confirmed"
        if any(s["weight"] >= 0.5 for s in h["signals_against"]):
            status = "contradicted"
        if confidence < 0.2:
            status = "retired"

        if (
            abs(confidence - h.get("confidence", 0.0)) > 1e-3
            or status != h.get("status")
        ):
            new = json.loads(json.dumps(h))
            new["period"] = period
            new["confidence"] = round(confidence, 3)
            new["status"] = status
            new["last_updated_utc"] = now_utc()
            append_entry(case_root, new)
            rescored += 1

    # Validation gate: at least one active >= 0.5?
    cur = latest_per_id(load_ledger(case_root))
    actives = {k: v for k, v in cur.items() if v["status"] == "active"}
    max_conf = max((h["confidence"] for h in actives.values()), default=0.0)

    print(f"Re-scored {rescored} hypothesis state transitions for period {period}.")
    print(f"Active hypotheses: {len(actives)}; max confidence: {max_conf:.2f}")
    if actives and max_conf < 0.5:
        print(
            "WARNING: no active hypothesis exceeds 0.5 confidence — "
            "ISC should generate an alternative."
        )
    if not actives:
        print(
            "WARNING: no active hypotheses — ISC should add at least one explaining "
            "current evidence."
        )


def cmd_report(args):
    case_root = args.case_root
    entries = load_ledger(case_root)
    cur = latest_per_id(entries)

    by_status = defaultdict(list)
    for h in cur.values():
        by_status[h["status"]].append(h)

    md_path = os.path.join(case_root, "analysis", "hypotheses_current.md")
    os.makedirs(os.path.dirname(md_path), exist_ok=True)

    lines = []
    lines.append("# Active Hypotheses (current ledger snapshot)")
    lines.append(f"_Generated {now_utc()}_\n")
    for status in ["confirmed", "active", "contradicted", "retired"]:
        items = sorted(
            by_status.get(status, []), key=lambda h: -h["confidence"]
        )
        if not items:
            continue
        lines.append(f"## {status.upper()} ({len(items)})\n")
        lines.append(
            "| ID | Hypothesis | Conf. | Signals For | Signals Against | Period |"
        )
        lines.append("|----|-----------|------:|-------------|-----------------|-------|")
        for h in items:
            sfor = "<br>".join(
                f"`{s['source']}` w={s['weight']}" for s in h["signals_for"][:3]
            ) or "—"
            sagainst = "<br>".join(
                f"`{s['source']}` w={s['weight']}" for s in h["signals_against"][:3]
            ) or "—"
            hyp = h["hypothesis"].replace("|", "\\|")
            lines.append(
                f"| {h['id']} | {hyp} | {h['confidence']:.2f} | "
                f"{sfor} | {sagainst} | {h['period']} |"
            )
        lines.append("")

    if not cur:
        lines.append(
            "_No hypotheses in ledger. Use `hypothesis_score.py add` to create the "
            "first one._"
        )

    body = "\n".join(lines)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(body + "\n")

    print(body)
    print(f"\n[Snapshot written to {md_path}]")


def cmd_retire(args):
    case_root = args.case_root
    entries = load_ledger(case_root)
    cur = latest_per_id(entries)
    if args.id not in cur:
        print(f"ERROR: hypothesis {args.id} not found", file=sys.stderr)
        sys.exit(2)
    h = json.loads(json.dumps(cur[args.id]))
    h["status"] = "retired"
    h["period"] = args.period
    h["last_updated_utc"] = now_utc()
    if args.reason:
        h.setdefault("retire_reasons", []).append(
            {"period": args.period, "reason": args.reason}
        )
    append_entry(case_root, h)
    print(f"{args.id} retired at period {args.period}")


# ── main ─────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Hypothesis Engine for SIFTics")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="Add a new hypothesis")
    p_add.add_argument("case_root")
    p_add.add_argument("--hypothesis", required=True)
    p_add.add_argument("--period", type=int, required=True)
    p_add.add_argument(
        "--signal-for", action="append",
        help="'source|finding|weight' — repeatable",
    )
    p_add.add_argument(
        "--signal-against", action="append",
        help="'source|finding|weight' — repeatable",
    )
    p_add.add_argument("--alternatives", nargs="*", help="competing hypothesis IDs")
    p_add.set_defaults(func=cmd_add)

    p_sig = sub.add_parser("signal", help="Add a signal to an existing hypothesis")
    p_sig.add_argument("case_root")
    p_sig.add_argument("--id", required=True)
    p_sig.add_argument("--period", type=int, required=True)
    p_sig.add_argument("--kind", choices=["for", "against"], required=True)
    p_sig.add_argument("--source", required=True)
    p_sig.add_argument("--finding", required=True)
    p_sig.add_argument("--weight", type=float, required=True)
    p_sig.set_defaults(func=cmd_signal)

    p_score = sub.add_parser(
        "score", help="Re-score all active hypotheses for a given period"
    )
    p_score.add_argument("case_root")
    p_score.add_argument("--period", type=int, required=True)
    p_score.set_defaults(func=cmd_score)

    p_rep = sub.add_parser("report", help="Print current ledger snapshot")
    p_rep.add_argument("case_root")
    p_rep.set_defaults(func=cmd_report)

    p_ret = sub.add_parser("retire", help="Manually retire a hypothesis")
    p_ret.add_argument("case_root")
    p_ret.add_argument("--id", required=True)
    p_ret.add_argument("--period", type=int, required=True)
    p_ret.add_argument("--reason")
    p_ret.set_defaults(func=cmd_retire)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
