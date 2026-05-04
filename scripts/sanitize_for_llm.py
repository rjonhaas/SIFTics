#!/usr/bin/env python3
"""
sanitize_for_llm.py — SIFTics DFIR Triage Framework
Sanitizes attacker-controlled CSV content before passing to an LLM,
to prevent prompt injection attacks.

Usage:
    python3 sanitize_for_llm.py <input.csv> [--output-dir DIR]
"""

import argparse
import csv
import re
import shutil
import sys
from pathlib import Path

# Patterns that indicate a potential prompt injection attempt
# Each tuple is (description, compiled_regex)
INJECTION_PATTERNS = [
    # Line-start patterns (check against each line in the cell)
    re.compile(r'(?:^|\n)\s*you are\b', re.IGNORECASE),
    re.compile(r'(?:^|\n)\s*ignore previous\b', re.IGNORECASE),
    re.compile(r'(?:^|\n)\s*system\s*:', re.IGNORECASE),
    re.compile(r'(?:^|\n)\s*assistant\s*:', re.IGNORECASE),
    re.compile(r'(?:^|\n)\s*user\s*:', re.IGNORECASE),
    re.compile(r'(?:^|\n)\s*human\s*:', re.IGNORECASE),
    re.compile(r'(?:^|\n)\s*```', re.IGNORECASE),
    # Substring patterns (anywhere in the cell)
    re.compile(r'ignore all prior instructions', re.IGNORECASE),
    re.compile(r'new instructions', re.IGNORECASE),
    re.compile(r'disregard', re.IGNORECASE),
    re.compile(r'override', re.IGNORECASE),
    re.compile(r'forget your', re.IGNORECASE),
    re.compile(r'act as', re.IGNORECASE),
    re.compile(r'pretend you are', re.IGNORECASE),
    re.compile(r'your new role', re.IGNORECASE),
]


def is_injection(cell_content: str) -> bool:
    """Return True if cell_content matches any injection pattern."""
    for pattern in INJECTION_PATTERNS:
        if pattern.search(cell_content):
            return True
    return False


def sanitize_csv(input_path: Path, output_dir: Path) -> None:
    input_path = input_path.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    stem = input_path.stem
    sanitized_path = output_dir / f"{stem}_sanitized.csv"
    unsanitized_path = output_dir / f"{stem}_unsanitized.csv"

    # Safety check: never write back to the input file
    if sanitized_path.resolve() == input_path or unsanitized_path.resolve() == input_path:
        print(
            "ERROR: Output path would overwrite the input file. "
            "Use --output-dir to specify a different directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Preserve the original as the unsanitized copy
    shutil.copy2(input_path, unsanitized_path)

    unsanitized_basename = unsanitized_path.name
    total_sanitized_cells = 0
    affected_rows = set()

    # Read all rows first so we can detect the dialect
    with open(input_path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.reader(fh)
        rows = list(reader)

    sanitized_rows = []
    for row_idx, row in enumerate(rows):
        row_num = row_idx + 1  # 1-based for human-readable messages
        new_row = []
        for col_idx, cell in enumerate(row):
            col_num = col_idx + 1  # 1-based
            if is_injection(cell):
                replacement = (
                    f"[SANITIZED: potential injection in row {row_num}, "
                    f"col {col_num} — see {unsanitized_basename}]"
                )
                new_row.append(replacement)
                total_sanitized_cells += 1
                affected_rows.add(row_num)
            else:
                new_row.append(cell)
        sanitized_rows.append(new_row)

    with open(sanitized_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerows(sanitized_rows)

    # Summary
    if total_sanitized_cells == 0:
        print("No injection patterns detected")
    else:
        print(
            f"Sanitized {total_sanitized_cells} cell"
            f"{'s' if total_sanitized_cells != 1 else ''} "
            f"across {len(affected_rows)} row"
            f"{'s' if len(affected_rows) != 1 else ''}"
        )

    print(f"  Sanitized : {sanitized_path}")
    print(f"  Unsanitized (original): {unsanitized_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sanitize attacker-controlled CSV content before passing to an LLM."
    )
    parser.add_argument("input_csv", help="Path to the input CSV file")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory for output files (default: same directory as input file)",
    )
    args = parser.parse_args()

    input_path = Path(args.input_csv)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)
    if not input_path.is_file():
        print(f"ERROR: Input path is not a file: {input_path}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir) if args.output_dir else input_path.parent

    sanitize_csv(input_path, output_dir)
    sys.exit(0)


if __name__ == "__main__":
    main()
