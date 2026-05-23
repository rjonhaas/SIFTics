#!/usr/bin/env bash
# Fetch the prebuilt forensic-RAG index from the SIFTics GitHub Releases,
# or fall back to building it locally if the release isn't available.
#
# Index lands at mcp_rag/index/.
#
# Usage:
#   ./scripts/download_rag_index.sh                  # latest release asset
#   ./scripts/download_rag_index.sh --build          # build locally instead
#   ./scripts/download_rag_index.sh --tag v0.1.0     # specific release tag
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

INDEX_DIR="${SIFTICS_RAG_INDEX_DIR:-$REPO_ROOT/mcp_rag/index}"
REPO_SLUG="${SIFTICS_REPO_SLUG:-rjonhaas/SIFTics}"
TAG=""
MODE="download"
OSM_BUNDLE="${SIFTICS_OSM_BUNDLE_PATH:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build) MODE="build"; shift ;;
        --tag) TAG="$2"; shift 2 ;;
        --osm-bundle) OSM_BUNDLE="$2"; shift 2 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$INDEX_DIR"

if [[ "$MODE" == "download" ]]; then
    URL="https://github.com/$REPO_SLUG/releases/${TAG:+download/$TAG}/latest/download/forensic_rag_index.tar.gz"
    [[ -n "$TAG" ]] && URL="https://github.com/$REPO_SLUG/releases/download/$TAG/forensic_rag_index.tar.gz"
    echo "[rag] attempting download: $URL"
    if curl -fL --progress-bar -o /tmp/forensic_rag_index.tar.gz "$URL"; then
        tar -xzf /tmp/forensic_rag_index.tar.gz -C "$INDEX_DIR"
        rm /tmp/forensic_rag_index.tar.gz
        echo "[rag] extracted to $INDEX_DIR"
        exit 0
    fi
    echo "[rag] download failed; falling back to local build."
    MODE="build"
fi

if [[ "$MODE" == "build" ]]; then
    if [[ ! -x ./.venv/bin/python ]]; then
        echo "no .venv; create one with 'python -m venv .venv && .venv/bin/pip install -e .' first" >&2
        exit 1
    fi
    EXTRA=()
    [[ -n "$OSM_BUNDLE" ]] && EXTRA+=(--osm-bundle "$OSM_BUNDLE")
    echo "[rag] building index locally (this can take 10-30 min on first run)..."
    ./.venv/bin/python -m mcp_rag.build_index --output "$INDEX_DIR" "${EXTRA[@]}"
fi
