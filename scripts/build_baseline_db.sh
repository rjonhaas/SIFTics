#!/usr/bin/env bash
# Build (or rebuild) the Rathbun-derived baseline SQLite.
#
# Two paths:
#   --seed    quick: ~50 curated demo rows, runs in < 1 s.
#   --full    canonical: clones Rathbun's repos and ingests every CSV. Slow on
#             first run (network bound). Disk: ~5 GB cached under _rathbun_cache.
#
# Usage:
#   ./scripts/build_baseline_db.sh --seed
#   ./scripts/build_baseline_db.sh --full
#   ./scripts/build_baseline_db.sh --full --output /custom/path/baseline.sqlite
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MODE="seed"
EXTRA_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --seed) MODE="seed"; shift ;;
        --full) MODE="full"; shift ;;
        --output)
            EXTRA_ARGS+=(--output "$2"); shift 2 ;;
        --skip-files|--skip-registry)
            EXTRA_ARGS+=("$1"); shift ;;
        -h|--help)
            sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -x ./.venv/bin/python ]]; then
    echo "no .venv; create one with 'python -m venv .venv && .venv/bin/pip install -e .' first" >&2
    exit 1
fi

case "$MODE" in
    seed)
        echo "[baseline] running seed_sample (curated demo subset)..."
        ./.venv/bin/python -m mcp_baseline.seed_sample "${EXTRA_ARGS[@]}"
        ;;
    full)
        echo "[baseline] running canonical builder (this can take 30+ min on first run)..."
        ./.venv/bin/python -m mcp_baseline.build_baseline_db "${EXTRA_ARGS[@]}"
        ;;
esac
