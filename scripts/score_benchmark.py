#!/usr/bin/env python3
"""
score_benchmark.py — SIFTics accuracy benchmark scorer

Evaluates SIFTics analysis output against documented ground truth for
publicly available DFIR cases, producing recall metrics that can be
independently verified by judges.

Usage:
    python3 scripts/score_benchmark.py \\
        --case-dir /cases/defcon2019_dfir \\
        --ground-truth benchmark/ground_truth/defcon2019.json

    python3 scripts/score_benchmark.py \\
        --case-dir /cases/166-spottedinthewild \\
        --ground-truth benchmark/ground_truth/spottedinwild.json \\
        --output /tmp/benchmark_results.json

Exit codes:
    0 — all checks passed
    1 — one or more checks failed
    2 — usage error (bad paths, invalid JSON)
"""

import argparse
import csv
import json
import os
import sys
import glob
from collections import defaultdict
from datetime import datetime, timezone


# ── Path resolution ───────────────────────────────────────────────────────────

def resolve_path(case_dir, rel_path):
    """Return absolute path; resolve glob patterns to first match."""
    if '*' in rel_path or '?' in rel_path:
        matches = sorted(glob.glob(os.path.join(case_dir, rel_path)))
        return matches[0] if matches else None
    return os.path.join(case_dir, rel_path)


# ── Check evaluators ──────────────────────────────────────────────────────────

def check_file_exists(case_dir, chk):
    path = resolve_path(case_dir, chk['file'])
    if path is None:
        return False, f"no glob match: {chk['file']}"
    if not os.path.isfile(path):
        return False, f"file not found: {os.path.relpath(path, case_dir)}"
    if os.path.getsize(path) == 0:
        return False, f"file is empty: {os.path.relpath(path, case_dir)}"
    return True, os.path.relpath(path, case_dir)


def check_file_contains(case_dir, chk):
    path = resolve_path(case_dir, chk['file'])
    if path is None:
        return False, f"no glob match: {chk['file']}"
    if not os.path.isfile(path):
        return False, f"file not found: {os.path.relpath(path, case_dir)}"
    needle = chk['value']
    try:
        with open(path, errors='replace') as f:
            content = f.read()
    except OSError as e:
        return False, str(e)
    if needle in content:
        return True, f"found '{needle}'"
    return False, f"'{needle}' not found in {os.path.basename(path)}"


def check_csv_contains(case_dir, chk):
    path = resolve_path(case_dir, chk['file'])
    if path is None:
        return False, f"no glob match: {chk['file']}"
    if not os.path.isfile(path):
        return False, f"file not found: {os.path.relpath(path, case_dir)}"
    field = chk['field']
    needle = chk['value']
    match_type = chk.get('match', 'exact')
    try:
        with open(path, errors='replace') as f:
            reader = csv.DictReader(f)
            headers = None
            for row in reader:
                if headers is None:
                    headers = list(row.keys())
                if field not in row:
                    return False, f"field '{field}' not in CSV headers: {headers[:6]}"
                cell = row[field] or ''
                if match_type == 'exact' and cell == needle:
                    return True, f"exact match '{needle}' in {field}"
                elif match_type == 'contains' and needle in cell:
                    return True, f"'{needle}' found in {field}"
    except OSError as e:
        return False, str(e)
    if headers is None:
        return False, f"CSV appears empty: {os.path.basename(path)}"
    return False, f"'{needle}' not found in '{field}' column of {os.path.basename(path)}"


def check_csv_min_rows(case_dir, chk):
    path = resolve_path(case_dir, chk['file'])
    if path is None:
        return False, f"no glob match: {chk['file']}"
    if not os.path.isfile(path):
        return False, f"file not found: {os.path.relpath(path, case_dir)}"
    min_rows = chk['min_rows']
    field = chk.get('field')
    needle = chk.get('value')
    count = 0
    try:
        with open(path, errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if field and needle:
                    if row.get(field) == needle:
                        count += 1
                else:
                    count += 1
    except OSError as e:
        return False, str(e)
    if count >= min_rows:
        return True, f"{count:,} rows (≥{min_rows:,} required)"
    return False, f"{count:,} rows — need ≥{min_rows:,}"


EVALUATORS = {
    'file_exists':    check_file_exists,
    'file_contains':  check_file_contains,
    'csv_contains':   check_csv_contains,
    'csv_min_rows':   check_csv_min_rows,
}


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(case_dir, ground_truth):
    results = []
    for chk in ground_truth['checks']:
        chk_type = chk['check']['type']
        evaluator = EVALUATORS.get(chk_type)
        if evaluator is None:
            results.append({
                **chk,
                'result': 'ERROR',
                'detail': f"unknown check type: {chk_type}",
            })
            continue
        try:
            passed, detail = evaluator(case_dir, chk['check'])
        except Exception as e:
            passed, detail = False, f"exception: {e}"
        results.append({**chk, 'result': 'PASS' if passed else 'FAIL', 'detail': detail})
    return results


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_report(ground_truth, results, case_dir):
    W = 72
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    print()
    print(f"SIFTics Benchmark — {ground_truth['case_name']}")
    print('=' * W)
    print(f"  Case dir:      {case_dir}")
    print(f"  Ground truth:  v{ground_truth['ground_truth_version']}  ({ground_truth['public_source'][:60]}...)" if len(ground_truth['public_source']) > 60 else f"  Ground truth:  v{ground_truth['ground_truth_version']}  ({ground_truth['public_source']})")
    print(f"  Evaluated:     {now}")
    print()

    print("CHECK RESULTS")
    print('─' * W)
    failures = []
    for r in results:
        marker = "\033[32m[PASS]\033[0m" if r['result'] == 'PASS' else "\033[31m[FAIL]\033[0m"
        phase = r.get('phase', '')[:32].ljust(32)
        rid = r['id'].ljust(10)
        print(f"  {rid} {marker}  {phase}")
        if r['result'] != 'PASS':
            print(f"             \033[33m{r['detail']}\033[0m")
            failures.append(r)
    print('─' * W)
    print()

    # Phase summary
    by_phase = defaultdict(lambda: {'pass': 0, 'total': 0})
    for r in results:
        phase = r.get('phase', 'Other')
        by_phase[phase]['total'] += 1
        if r['result'] == 'PASS':
            by_phase[phase]['pass'] += 1

    print("PHASE SUMMARY")
    for phase in sorted(by_phase):
        p = by_phase[phase]['pass']
        t = by_phase[phase]['total']
        pct = 100 * p / t if t else 0
        bar = '█' * p + '░' * (t - p)
        print(f"  {phase:<40}  {p}/{t}  {bar}  ({pct:.0f}%)")
    print()

    total = len(results)
    passed = sum(1 for r in results if r['result'] == 'PASS')
    recall = 100 * passed / total if total else 0
    print(f"OVERALL RECALL:  {passed}/{total} ({recall:.1f}%)")

    for conf in ('CONFIRMED', 'INFERRED'):
        sub = [r for r in results if r.get('confidence') == conf]
        if sub:
            sp = sum(1 for r in sub if r['result'] == 'PASS')
            st = len(sub)
            pct = 100 * sp / st if st else 0
            print(f"  {conf:<12}  {sp}/{st} ({pct:.1f}%)")
    print()

    if failures:
        print("FAILED CHECKS — details")
        print('─' * W)
        for r in failures:
            print(f"  {r['id']}  {r.get('description', '')}")
            print(f"    → {r['detail']}")
        print()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Score SIFTics analysis output against documented ground truth',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('--case-dir',     required=True, metavar='PATH',
                    help='Path to case root directory (e.g. /cases/defcon2019_dfir)')
    ap.add_argument('--ground-truth', required=True, metavar='JSON',
                    help='Path to ground truth JSON file')
    ap.add_argument('--output',       metavar='JSON',
                    help='Write machine-readable results to this JSON file')
    args = ap.parse_args()

    if not os.path.isdir(args.case_dir):
        print(f"ERROR: --case-dir not found: {args.case_dir}", file=sys.stderr)
        sys.exit(2)
    if not os.path.isfile(args.ground_truth):
        print(f"ERROR: --ground-truth not found: {args.ground_truth}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.ground_truth) as f:
            gt = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid JSON in ground truth file: {e}", file=sys.stderr)
        sys.exit(2)

    results = evaluate(args.case_dir, gt)
    print_report(gt, results, args.case_dir)

    if args.output:
        total = len(results)
        passed = sum(1 for r in results if r['result'] == 'PASS')
        out = {
            'case_id': gt['case_id'],
            'evaluated_at': datetime.now(timezone.utc).isoformat(),
            'case_dir': args.case_dir,
            'ground_truth_file': args.ground_truth,
            'ground_truth_version': gt.get('ground_truth_version'),
            'summary': {
                'total_checks': total,
                'passed': passed,
                'failed': total - passed,
                'recall_pct': round(100 * passed / total, 1) if total else 0,
            },
            'checks': results,
        }
        with open(args.output, 'w') as f:
            json.dump(out, f, indent=2, default=str)
        print(f"JSON results written to: {args.output}")

    sys.exit(0 if all(r['result'] == 'PASS' for r in results) else 1)


if __name__ == '__main__':
    main()
