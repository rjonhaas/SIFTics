#!/usr/bin/env bash
# One-shot bootstrap: get SIFTics running on a SIFT VM from a fresh host.
#
# Steps (idempotent — safe to re-run):
#   1. Confirm SSH key-based auth to the VM (prompts for password once)
#   2. rsync the repo to the VM
#   3. Install Python deps inside a venv on the VM
#   4. Run pytest tests/test_constraints.py
#   5. Seed the demo baseline DB
#   6. Optionally start siftics-ui in the background
#
# Required env:
#   SIFT_HOST     user@ip   (default: sansforensics@192.168.4.52)
# Optional:
#   SIFT_REMOTE_PATH   default ~/SIFTics
#   SIFT_START_UI      "yes" (default) | "no"
#   SIFT_CASE_DIR      default ~/cases/dry_run
set -euo pipefail

SIFT_HOST="${SIFT_HOST:-sansforensics@192.168.4.52}"
SIFT_REMOTE_PATH="${SIFT_REMOTE_PATH:-~/SIFTics}"
SIFT_START_UI="${SIFT_START_UI:-yes}"
SIFT_CASE_DIR="${SIFT_CASE_DIR:-~/cases/dry_run}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[bootstrap] target: $SIFT_HOST"
echo "[bootstrap] remote path: $SIFT_REMOTE_PATH"

# ---------------------------------------------------------------------------
# Step 1 — SSH key auth
# ---------------------------------------------------------------------------

if ssh -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
       "$SIFT_HOST" 'echo connected' >/dev/null 2>&1; then
    echo "[bootstrap] key auth already works ✓"
else
    echo "[bootstrap] key auth is not configured."
    echo
    echo "Run this one command interactively (it will prompt for the SIFT password"
    echo "once — typically 'forensics' for sansforensics on a stock SIFT 2026 OVA):"
    echo
    echo "    ssh-copy-id -o StrictHostKeyChecking=accept-new $SIFT_HOST"
    echo
    echo "Then re-run this script."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 2 — rsync
# ---------------------------------------------------------------------------

echo "[bootstrap] rsyncing repo → ${SIFT_HOST}:${SIFT_REMOTE_PATH}"
ssh "$SIFT_HOST" "mkdir -p $SIFT_REMOTE_PATH"
rsync -av --delete \
    --exclude '.venv/' \
    --exclude '__pycache__/' \
    --exclude '.pytest_cache/' \
    --exclude '_rathbun_cache/' \
    --exclude '_rag_cache/' \
    --exclude '.git/' \
    --exclude 'mcp_rag/index/' \
    "$REPO_ROOT/" \
    "$SIFT_HOST:$SIFT_REMOTE_PATH/" \
    | tail -10

# ---------------------------------------------------------------------------
# Step 3 — venv + deps on the VM
# ---------------------------------------------------------------------------

echo "[bootstrap] setting up venv + dependencies on VM"
ssh "$SIFT_HOST" bash <<EOF
set -euo pipefail
cd $SIFT_REMOTE_PATH
which python3 || { echo "no python3 on the VM"; exit 1; }
PY_VER=\$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "python: \$PY_VER"

if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
.venv/bin/pip install --upgrade pip --quiet
.venv/bin/pip install -e . --quiet
echo "[VM] deps installed"
EOF

# ---------------------------------------------------------------------------
# Step 4 — bypass tests on the VM
# ---------------------------------------------------------------------------

echo "[bootstrap] running T1-T8 bypass tests on VM"
ssh "$SIFT_HOST" bash <<EOF
set -euo pipefail
cd $SIFT_REMOTE_PATH
.venv/bin/python -m pytest tests/test_constraints.py -q
EOF

# ---------------------------------------------------------------------------
# Step 5 — seed baseline DB + init case dir
# ---------------------------------------------------------------------------

echo "[bootstrap] seeding baseline DB + initialising case dir on VM"
ssh "$SIFT_HOST" bash <<EOF
set -euo pipefail
cd $SIFT_REMOTE_PATH
.venv/bin/python -m mcp_baseline.seed_sample
mkdir -p $SIFT_CASE_DIR
if [ ! -f $SIFT_CASE_DIR/case.json ]; then
    .venv/bin/sift-case-init \
        --case-dir $SIFT_CASE_DIR \
        --case-id dry_run_\$(date +%Y%m%d) \
        --name "Dry run on SIFT VM" \
        --ic-name \$USER \
        --no-key \
        --itq-template ./siftics/templates/itq_questions.yaml
    echo "[VM] case dir initialised at $SIFT_CASE_DIR (no IC key — use sift-case-init later for the demo)"
else
    echo "[VM] case dir already exists at $SIFT_CASE_DIR (left in place)"
fi
EOF

# ---------------------------------------------------------------------------
# Step 6 — start the UI (optional)
# ---------------------------------------------------------------------------

if [ "$SIFT_START_UI" = "yes" ]; then
    echo "[bootstrap] starting siftics-ui on the VM"
    ssh "$SIFT_HOST" bash <<EOF
set -euo pipefail
cd $SIFT_REMOTE_PATH
pkill -f 'siftics-ui run' || true
sleep 1
export SIFTICS_CASE_DIR=$SIFT_CASE_DIR
nohup .venv/bin/siftics-ui run --case-dir \$SIFTICS_CASE_DIR \
    > /tmp/siftics-ui.log 2>&1 &
sleep 2
if pgrep -af 'siftics-ui run' >/dev/null; then
    echo "[VM] siftics-ui running. Tail: ssh $SIFT_HOST 'tail -20 /tmp/siftics-ui.log'"
    echo "[VM] Open the UI: ssh -L 8080:127.0.0.1:8080 $SIFT_HOST"
    echo "[VM]   then point a browser at http://127.0.0.1:8080"
else
    echo "[VM] siftics-ui did not start cleanly. Check /tmp/siftics-ui.log on the VM."
fi
EOF
fi

echo "[bootstrap] done."
