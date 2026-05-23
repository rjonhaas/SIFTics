#!/usr/bin/env bash
# Sync the working tree from the host to a SIFT VM and restart the UI service.
#
# Usage:
#   SIFT_HOST=siftvm                ./scripts/sync_to_sift.sh
#   SIFT_HOST=192.168.4.52          ./scripts/sync_to_sift.sh
#   SIFT_HOST=user@siftvm:/home/x   ./scripts/sync_to_sift.sh
#
# Optional env:
#   SIFT_REMOTE_PATH   default ~/SIFTics
#   SIFT_RESTART_UI    "yes" (default) | "no"
#   SIFT_RUN_TESTS     "no" (default) | "yes"
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

HOST="${SIFT_HOST:-}"
if [[ -z "$HOST" ]]; then
    echo "SIFT_HOST not set. e.g. SIFT_HOST=user@192.168.4.52 ./scripts/sync_to_sift.sh" >&2
    exit 2
fi

REMOTE_PATH="${SIFT_REMOTE_PATH:-~/SIFTics}"
RESTART_UI="${SIFT_RESTART_UI:-yes}"
RUN_TESTS="${SIFT_RUN_TESTS:-no}"

if [[ "$HOST" == *":"* ]]; then
    DEST="$HOST"
else
    DEST="$HOST:$REMOTE_PATH"
fi

echo "[sync] $REPO_ROOT/ -> $DEST"
rsync -av --delete \
    --exclude '.venv/' \
    --exclude '__pycache__/' \
    --exclude '.pytest_cache/' \
    --exclude '_rathbun_cache/' \
    --exclude '_rag_cache/' \
    --exclude 'mcp_baseline/baseline.sqlite' \
    --exclude 'mcp_rag/index/' \
    --exclude '.git/' \
    "$REPO_ROOT/" \
    "$DEST/"

# Run remote commands
REMOTE_USER_HOST="${HOST%%:*}"
ssh_exec() {
    ssh "$REMOTE_USER_HOST" "cd $REMOTE_PATH && $1"
}

if [[ "$RUN_TESTS" == "yes" ]]; then
    echo "[sync] running tests on remote..."
    ssh_exec ".venv/bin/python -m pytest tests/test_constraints.py -q"
fi

if [[ "$RESTART_UI" == "yes" ]]; then
    echo "[sync] restarting siftics-ui on remote..."
    ssh_exec "pkill -f 'siftics-ui run' || true; \
              nohup .venv/bin/siftics-ui run --case-dir \$SIFTICS_CASE_DIR \
                > /tmp/siftics-ui.log 2>&1 &"
    echo "[sync] UI restarted; tail /tmp/siftics-ui.log on the VM if needed."
fi

echo "[sync] done."
