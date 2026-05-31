#!/usr/bin/env bash
# SIFTics one-shot setup — express path for hackathon judges and operators.
#
# Idempotent — re-running picks up where the last run left off. The README's
# manual steps remain the canonical reference; this script just collapses them.
#
# Usage:
#   ./setup.sh                      # venv + deps + seed baseline
#   ./setup.sh --full-baseline      # ...but fetch the full DB from a GitHub Release
#   ./setup.sh --build-baseline     # ...but build the full DB locally (~30 min)
#   ./setup.sh --no-baseline        # skip baseline step entirely
#   ./setup.sh --init-case          # also create ~/cases/dry_run + IC HMAC key
#   ./setup.sh --start-ui           # also launch siftics-ui at 127.0.0.1:8080
#   ./setup.sh --help               # this message
#
# Flags can be combined: ./setup.sh --full-baseline --init-case --start-ui

set -euo pipefail

# ---------------------------------------------------------------------------
# Flags + defaults
# ---------------------------------------------------------------------------

BASELINE_MODE="seed"        # seed | full | build | none
INIT_CASE="no"
START_UI="no"
CASE_DIR="${SIFTICS_CASE_DIR:-$HOME/cases/dry_run}"
CASE_ID="dry_run_$(date +%Y%m%d)"
QUIET="no"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --full-baseline)  BASELINE_MODE="full";  shift ;;
        --build-baseline) BASELINE_MODE="build"; shift ;;
        --no-baseline)    BASELINE_MODE="none";  shift ;;
        --init-case)      INIT_CASE="yes";       shift ;;
        --start-ui)       START_UI="yes";        shift ;;
        --case-dir)       CASE_DIR="$2";         shift 2 ;;
        --case-id)        CASE_ID="$2";          shift 2 ;;
        --quiet)          QUIET="yes";           shift ;;
        -h|--help)        sed -n '2,16p' "$0";   exit 0 ;;
        *) echo "unknown arg: $1 (use --help)" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

START_TS=$(date +%s)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yel()   { printf '\033[1;33m%s\033[0m\n' "$*"; }
cyan()  { printf '\033[0;36m%s\033[0m\n' "$*"; }

step()  {
    local n="$1" total="$2" msg="$3"
    printf "[%s/%s] %-58s " "$n" "$total" "$msg"
}
ok()    { green "ok${1:+ ($1)}"; }
skip()  { cyan "skip${1:+ ($1)}"; }
warn()  { yel  "warn${1:+ ($1)}"; }
die()   { red  "fail${1:+ ($1)}"; echo; red "$2"; exit 1; }

TOTAL_STEPS=4
[[ "$BASELINE_MODE" == "none" ]] && TOTAL_STEPS=$((TOTAL_STEPS - 1))
[[ "$INIT_CASE" == "yes"      ]] && TOTAL_STEPS=$((TOTAL_STEPS + 1))
[[ "$START_UI"  == "yes"      ]] && TOTAL_STEPS=$((TOTAL_STEPS + 1))

# ---------------------------------------------------------------------------
# Step 1 — system prereqs
# ---------------------------------------------------------------------------

step 1 "$TOTAL_STEPS" "checking system prereqs"

if ! command -v python3 >/dev/null; then
    die "" "python3 is required. Install with: sudo apt install python3"
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=${PY_VER%%.*}
PY_MINOR=${PY_VER##*.}
if (( PY_MAJOR < 3 || (PY_MAJOR == 3 && PY_MINOR < 10) )); then
    die "" "Python 3.10+ required (you have $PY_VER)."
fi

# Probe that `python3 -m venv` works (Debian/Ubuntu sometimes ships without ensurepip)
if ! python3 -c "import venv, ensurepip" 2>/dev/null; then
    die "" "python3-venv is missing. Install with:
       sudo apt install -y python${PY_VER}-venv python3-pip python3-dev build-essential
    Then re-run ./setup.sh"
fi

if ! command -v curl >/dev/null; then
    die "" "curl is required (used by download scripts). Install with: sudo apt install curl"
fi

ok "python $PY_VER"

# ---------------------------------------------------------------------------
# Step 2 — venv
# ---------------------------------------------------------------------------

step 2 "$TOTAL_STEPS" "creating venv at .venv/"

if [[ -x .venv/bin/python ]]; then
    skip "already present"
else
    python3 -m venv .venv 2>/dev/null || die "" "venv creation failed."
    ok "created"
fi

# Activate for the rest of the script
PY=".venv/bin/python"
PIP=".venv/bin/pip"

# ---------------------------------------------------------------------------
# Step 3 — dependencies
# ---------------------------------------------------------------------------

step 3 "$TOTAL_STEPS" "installing dependencies (~1-3 min on first run)"

# Idempotency check: confirm one of the deeper deps is importable
if "$PY" -c "import flask, mcp, anthropic, numpy, evtx" 2>/dev/null; then
    skip "already installed"
else
    if [[ "$QUIET" == "yes" ]]; then
        "$PIP" install --upgrade pip --quiet
        "$PIP" install -e . --quiet
        "$PIP" install pytest --quiet
    else
        "$PIP" install --upgrade pip 2>&1 | tail -1
        "$PIP" install -e . 2>&1 | tail -3
        "$PIP" install pytest 2>&1 | tail -1
    fi
    "$PY" -c "import flask, mcp, anthropic, numpy, evtx" 2>/dev/null \
        || die "" "core deps did not import after install. See pip output above."
    ok "installed"
fi

# ---------------------------------------------------------------------------
# Step 4 — baseline DB
# ---------------------------------------------------------------------------

if [[ "$BASELINE_MODE" != "none" ]]; then
    step 4 "$TOTAL_STEPS" "baseline DB ($BASELINE_MODE)"

    if [[ -s mcp_baseline/baseline.sqlite ]]; then
        size=$(du -h mcp_baseline/baseline.sqlite | cut -f1)
        skip "already present ($size)"
    else
        case "$BASELINE_MODE" in
            seed)
                "$PY" -m mcp_baseline.seed_sample > /tmp/siftics_seed.log 2>&1 \
                    && ok "$(grep -oP '\d+ files' /tmp/siftics_seed.log | head -1)" \
                    || die "" "seed failed (see /tmp/siftics_seed.log)"
                ;;
            full)
                ./scripts/download_baseline.sh > /tmp/siftics_baseline.log 2>&1 \
                    && ok "$(du -h mcp_baseline/baseline.sqlite | cut -f1) downloaded" \
                    || die "" "download failed (see /tmp/siftics_baseline.log).
       The Release asset may not exist yet. Try: ./setup.sh --build-baseline"
                ;;
            build)
                yel "(this will take ~30 minutes and ~5 GB of disk)"
                step 4 "$TOTAL_STEPS" "baseline DB (build)"   # re-print
                "$PY" -m mcp_baseline.build_baseline_db > /tmp/siftics_baseline.log 2>&1 \
                    && ok "$(du -h mcp_baseline/baseline.sqlite | cut -f1)" \
                    || die "" "local build failed (see /tmp/siftics_baseline.log)"
                ;;
        esac
    fi
fi

# ---------------------------------------------------------------------------
# Step 5 — init case dir (optional)
# ---------------------------------------------------------------------------

CUR_STEP=4
[[ "$BASELINE_MODE" == "none" ]] && CUR_STEP=3

if [[ "$INIT_CASE" == "yes" ]]; then
    CUR_STEP=$((CUR_STEP + 1))
    step "$CUR_STEP" "$TOTAL_STEPS" "initialising case dir at $CASE_DIR"

    if [[ -f "$CASE_DIR/case.json" ]]; then
        skip "case already exists"
    else
        export SIFTICS_CASE_DIR="$CASE_DIR"
        mkdir -p "$CASE_DIR"

        # If stdin is a TTY, prompt; else use --no-key so unattended runs don't hang.
        KEY_ARGS=()
        if [[ ! -t 0 ]]; then
            KEY_ARGS=(--no-key)
            warn "non-interactive — skipping IC HMAC key creation"
        fi

        .venv/bin/sift-case-init \
            --case-dir "$CASE_DIR" \
            --case-id  "$CASE_ID" \
            --name     "SIFTics dry-run case ($CASE_ID)" \
            --ic-name  "${USER:-operator}" \
            --itq-template ./templates/itq_questions.yaml \
            "${KEY_ARGS[@]}" \
            > /tmp/siftics_case.log 2>&1 \
            && ok "$CASE_ID" \
            || die "" "case-init failed (see /tmp/siftics_case.log)"
    fi
fi

# ---------------------------------------------------------------------------
# Step 6 — start UI (optional)
# ---------------------------------------------------------------------------

if [[ "$START_UI" == "yes" ]]; then
    CUR_STEP=$((CUR_STEP + 1))
    UI_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    UI_IP="${UI_IP:-127.0.0.1}"
    step "$CUR_STEP" "$TOTAL_STEPS" "starting siftics-ui at http://${UI_IP}:8080"

    if pgrep -f "siftics-ui run" >/dev/null; then
        skip "already running (pid $(pgrep -f 'siftics-ui run' | head -1))"
    else
        export SIFTICS_CASE_DIR="$CASE_DIR"
        nohup .venv/bin/siftics-ui run --case-dir "$CASE_DIR" \
            > /tmp/siftics-ui.log 2>&1 &
        UI_PID=$!
        sleep 2
        if kill -0 "$UI_PID" 2>/dev/null; then
            ok "pid $UI_PID"
        else
            die "" "siftics-ui exited immediately. See /tmp/siftics-ui.log"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

ELAPSED=$(( $(date +%s) - START_TS ))
MINS=$((ELAPSED / 60))
SECS=$((ELAPSED % 60))

UI_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
UI_IP="${UI_IP:-127.0.0.1}"

echo
green "Setup complete in ${MINS}m ${SECS}s."
echo
echo "Next steps:"
if [[ "$START_UI" == "yes" ]]; then
    echo "  • Open the UI:        http://${UI_IP}:8080"
    echo "  • Tail UI log:        tail -F /tmp/siftics-ui.log"
fi
if [[ "$INIT_CASE" != "yes" ]]; then
    echo "  • Create a case:      see README QUICKSTART, or rerun with --init-case"
fi
echo "  • Bypass tests:       .venv/bin/python -m pytest tests/test_constraints.py -v"
echo "  • Start the agent:    claude  → /investigation-section-chief"
echo "  • Choose runtime:     http://${UI_IP}:8080/setup"
echo
echo "Docs: docs/QUICKSTART.md  ·  docs/architecture.md"
