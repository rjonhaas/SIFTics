#!/usr/bin/env bash
# Fetch the full Rathbun-derived baseline SQLite from a SIFTics GitHub Release.
#
# This is the high-coverage path. For demo / quick-start use the seed instead:
#   ./scripts/build_baseline_db.sh --seed
#
# Usage:
#   ./scripts/download_baseline.sh                     # latest Release asset
#   ./scripts/download_baseline.sh --tag find-evil-v1  # specific tag
#   ./scripts/download_baseline.sh --build             # build locally (~30 min)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DB_PATH="${SIFTICS_BASELINE_DB:-$REPO_ROOT/mcp_baseline/baseline.sqlite}"
REPO_SLUG="${SIFTICS_REPO_SLUG:-rjonhaas/SIFTics}"
ASSET_NAME="baseline_full.sqlite.gz"
TAG=""
MODE="download"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)  MODE="build"; shift ;;
        --tag)    TAG="$2"; shift 2 ;;
        --output) DB_PATH="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$(dirname "$DB_PATH")"
TMP="/tmp/${ASSET_NAME}"

if [[ "$MODE" == "download" ]]; then
    if [[ -n "$TAG" ]]; then
        URL="https://github.com/$REPO_SLUG/releases/download/$TAG/$ASSET_NAME"
    else
        URL="https://github.com/$REPO_SLUG/releases/latest/download/$ASSET_NAME"
    fi
    echo "[baseline] downloading: $URL"
    if curl -fL --progress-bar -o "$TMP" "$URL"; then
        gunzip -c "$TMP" > "$DB_PATH"
        rm -f "$TMP"
        size=$(du -h "$DB_PATH" | cut -f1)
        echo "[baseline] extracted to $DB_PATH (${size})"
        # Quick verification
        rows=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM files" 2>/dev/null || echo "?")
        echo "[baseline] files row count: $rows"
        exit 0
    fi
    echo "[baseline] download failed; falling back to local build."
    MODE="build"
fi

if [[ "$MODE" == "build" ]]; then
    if [[ ! -x ./.venv/bin/python ]]; then
        echo "no .venv; create one with:" >&2
        echo "  python -m venv .venv && .venv/bin/pip install -e ." >&2
        exit 1
    fi
    echo "[baseline] building full DB locally (clones Rathbun, ~30 min, ~5 GB disk)..."
    ./.venv/bin/python -m mcp_baseline.build_baseline_db --output "$DB_PATH"
    echo "[baseline] done."
fi
