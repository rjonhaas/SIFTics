#!/usr/bin/env bash
# SIFTics one-shot setup — express path for hackathon judges and operators.
# Idempotent: re-running picks up where the last run left off.

usage() {
cat <<'EOF'
USAGE
  ./setup.sh [OPTIONS]

DESCRIPTION
  Idempotent installer for SIFTics on a SANS SIFT Workstation (or any
  Ubuntu/Debian host). Re-running is safe — completed steps are skipped.

OPTIONS
  Baseline DB (mutually exclusive; default: --seed-baseline)
    (no flag)           Seed a ~50-row demo baseline (instant, no network)
    --full-baseline     Download the full ~100 MB Rathbun DB from the latest
                        GitHub Release (~30 s, requires network)
    --build-baseline    Build the full DB locally from Rathbun sources
                        (~30 min, ~5 GB disk cache, requires git + network)
    --no-baseline       Skip the baseline step entirely

  Forensic RAG index (default: build if missing)
    --no-rag            Skip the RAG index step (mcp_rag will return empty results)

  Case initialisation
    --init-case         Create the case directory, hash-chained audit log,
                        IC HMAC key, and 35-question ITQ seed
    --case-dir DIR      Case directory path  (default: ~/Desktop/cases/dry_run)
    --case-id  ID       Case identifier      (default: dry_run_YYYYMMDD)

  AI runtimes (optional — prompted interactively if none specified)
    --install-claude    Install Claude Code CLI (npm install -g @anthropic-ai/claude-code)
    --install-codex     Install OpenAI Codex CLI (npm install -g @openai/codex)
    --install-ollama    Install Ollama local LLM server (ollama.com/install.sh)
    --no-runtimes       Skip the runtime prompt and install nothing

  Web UI
    --start-ui          Launch siftics-ui on port 8080 after setup completes (default: ON)
                        (binds to 0.0.0.0 — reachable from host browser)
    --no-ui             Skip launching the UI

  Misc
    -q, --quiet         Suppress verbose pip output
    -h, --help          Show this help and exit

EXAMPLES
  # Express path — UI starts automatically, no flags needed:
  ./setup.sh

  # Full baseline + case + UI:
  ./setup.sh --full-baseline --init-case

  # Custom case directory:
  ./setup.sh --init-case --case-dir ~/Desktop/cases/defcon2019 --case-id defcon2019

  # Headless / CI (no TTY, skip IC key, no UI):
  ./setup.sh --no-baseline --init-case --no-ui

  # Re-run after a partial install (safe, UI restarts too):
  ./setup.sh

FILES
  .venv/                     Python virtual environment
  mcp_baseline/baseline.sqlite  Rathbun known-good Windows baseline DB
  mcp_rag/index/             Forensic RAG index (Sigma + ATT&CK + LOLBAS + Atomic Red Team)
  ~/Desktop/cases/<case-id>/         Case directory (audit log, ASR, CET, ITQ, IC key)
  /tmp/siftics-ui.log        Web UI stdout / stderr
  /tmp/siftics_*.log         Per-step log files for baseline build / case init

SEE ALSO
  docs/QUICKSTART.md    30-second path for judges
  docs/architecture.md  Full architecture overview
  man siftics-setup     This page (after: sudo cp docs/man/siftics-setup.1 /usr/local/man/man1/)

EOF
}

# Flags can be combined: ./setup.sh --full-baseline --init-case --start-ui

set -euo pipefail

# ---------------------------------------------------------------------------
# Flags + defaults
# ---------------------------------------------------------------------------

BASELINE_MODE="seed"        # seed | full | build | none
BUILD_RAG="yes"             # yes | no
INIT_CASE="no"
START_UI="yes"
CASE_DIR="${SIFTICS_CASE_DIR:-$HOME/Desktop/cases}"
CASE_ID="case_$(date +%Y%m%d)"
QUIET="no"
INSTALL_CLAUDE="no"
INSTALL_CODEX="no"
INSTALL_OLLAMA="no"
NO_RUNTIMES="no"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --full-baseline)   BASELINE_MODE="full";   shift ;;
        --build-baseline)  BASELINE_MODE="build";  shift ;;
        --no-baseline)     BASELINE_MODE="none";   shift ;;
        --no-rag)          BUILD_RAG="no";         shift ;;
        --init-case)       INIT_CASE="yes";        shift ;;
        --start-ui)        START_UI="yes";         shift ;;
        --no-ui)           START_UI="no";          shift ;;
        --case-dir)        CASE_DIR="$2";          shift 2 ;;
        --case-id)         CASE_ID="$2";           shift 2 ;;
        --install-claude)  INSTALL_CLAUDE="yes";   shift ;;
        --install-codex)   INSTALL_CODEX="yes";    shift ;;
        --install-ollama)  INSTALL_OLLAMA="yes";   shift ;;
        --no-runtimes)     NO_RUNTIMES="yes";      shift ;;
        -q|--quiet)        QUIET="yes";            shift ;;
        -h|--help)         usage; exit 0 ;;
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

# Run a command in the background while showing an animated spinner.
# Usage: _progress_install "Label" cmd [args...]
# Prints its own line — call AFTER a step() that ended with echo/newline.
_progress_install() {
    local label="$1"; shift
    local spinchars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    printf "      → %-18s " "$label"
    "$@" &>/dev/null &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        printf "%s\b" "${spinchars:$((i % ${#spinchars})):1}"
        (( i++ )) || true
        sleep 0.1
    done
    printf " "
    wait "$pid"
    local rc=$?
    if [[ $rc -eq 0 ]]; then green "ok"; else red "FAILED"; fi
    return $rc
}

TOTAL_STEPS=7
[[ "$BASELINE_MODE" == "none" ]] && TOTAL_STEPS=$((TOTAL_STEPS - 1))
[[ "$BUILD_RAG"      == "no"  ]] && TOTAL_STEPS=$((TOTAL_STEPS - 1))
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
# Step 3b — fix evtx_dump if shadowed by broken pip shim
# ---------------------------------------------------------------------------
# The `pip install evtx` package installs a Python entry-point shim at
# ~/.local/bin/evtx_dump that often breaks (`ModuleNotFoundError: scripts`).
# We install the canonical Rust binary in its place, which is faster, has no
# Python dependency, and shadows the broken shim cleanly.

step "3b" "$TOTAL_STEPS" "evtx_dump (Rust binary)"

EVTX_BIN="$HOME/.local/bin/evtx_dump"
EVTX_VER="v0.11.2"
EVTX_URL="https://github.com/omerbenamram/evtx/releases/download/${EVTX_VER}/evtx_dump-${EVTX_VER}-x86_64-unknown-linux-musl"

if [[ -x "$EVTX_BIN" ]] && "$EVTX_BIN" --version 2>/dev/null | grep -q "EVTX Parser"; then
    skip "already installed ($("$EVTX_BIN" --version 2>/dev/null))"
else
    mkdir -p "$(dirname "$EVTX_BIN")"
    if curl -fL --silent --show-error -o "$EVTX_BIN.new" "$EVTX_URL" 2>/tmp/siftics_evtx.log; then
        chmod +x "$EVTX_BIN.new"
        mv -f "$EVTX_BIN.new" "$EVTX_BIN"
        ok "$EVTX_VER installed"
    else
        warn "download failed (see /tmp/siftics_evtx.log). EVTX parsing will fall back to evtx_dump.py."
        rm -f "$EVTX_BIN.new"
    fi
fi

# ---------------------------------------------------------------------------
# Step 4 — man pages
# ---------------------------------------------------------------------------

step 4 "$TOTAL_STEPS" "installing man page (siftics-setup)"

MAN_SRC="$REPO_ROOT/docs/man/siftics-setup.1"
MAN_DEST="/usr/local/man/man1/siftics-setup.1"

if [[ -f "$MAN_DEST" ]]; then
    skip "already installed"
elif sudo cp "$MAN_SRC" "$MAN_DEST" 2>/dev/null && sudo mandb -q 2>/dev/null; then
    ok "man siftics-setup"
else
    warn "sudo not available — skipping (run manually: sudo cp $MAN_SRC $MAN_DEST && sudo mandb)"
fi

# ---------------------------------------------------------------------------
# Step 5 — AI runtime installation
# ---------------------------------------------------------------------------

# Interactive prompt when TTY and no runtime flag was passed
if [[ "$NO_RUNTIMES" != "yes" && "$INSTALL_CLAUDE$INSTALL_CODEX$INSTALL_OLLAMA" == "nonono" && -t 0 ]]; then
    echo
    echo "  Install AI runtimes? (all are optional — SIFTics works with any)"
    echo "    [1] Claude Code   claude CLI  (recommended — requires Node.js)"
    echo "    [2] Codex CLI     openai codex (requires Node.js)"
    echo "    [3] Ollama        local LLM server — no API key needed"
    echo "    [a] All of the above"
    echo "    [s] Skip  (default)"
    echo
    read -rp "  Selection [1/2/3/a/s]: " _rt
    _rt="${_rt,,}"
    [[ "$_rt" == "a" ]] && INSTALL_CLAUDE="yes" INSTALL_CODEX="yes" INSTALL_OLLAMA="yes"
    [[ "$_rt" == *1* ]] && INSTALL_CLAUDE="yes"
    [[ "$_rt" == *2* ]] && INSTALL_CODEX="yes"
    [[ "$_rt" == *3* ]] && INSTALL_OLLAMA="yes"
    echo
fi

step 5 "$TOTAL_STEPS" "AI runtimes"

if [[ "$NO_RUNTIMES" == "yes" || "$INSTALL_CLAUDE$INSTALL_CODEX$INSTALL_OLLAMA" == "nonono" ]]; then
    skip "none selected (--install-claude/codex/ollama to pre-select)"
else
    echo  # newline — per-item spinner lines follow

    # Node.js — required for Claude Code and Codex
    if [[ "$INSTALL_CLAUDE" == "yes" || "$INSTALL_CODEX" == "yes" ]]; then
        if ! command -v node >/dev/null 2>&1; then
            _progress_install "Node.js" \
                bash -c 'curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - \
                         && sudo apt-get install -y nodejs' \
            || { INSTALL_CLAUDE="no"; INSTALL_CODEX="no"; }
        else
            printf "      → %-18s " "Node.js"; cyan "already installed"
        fi
    fi

    if [[ "$INSTALL_CLAUDE" == "yes" ]]; then
        if command -v claude >/dev/null 2>&1; then
            printf "      → %-18s " "Claude Code"; cyan "already installed"
        else
            _progress_install "Claude Code" sudo npm install -g @anthropic-ai/claude-code
        fi
    fi

    if [[ "$INSTALL_CODEX" == "yes" ]]; then
        if command -v codex >/dev/null 2>&1; then
            printf "      → %-18s " "Codex CLI"; cyan "already installed"
        else
            _progress_install "Codex CLI" sudo npm install -g @openai/codex
        fi
    fi

    if [[ "$INSTALL_OLLAMA" == "yes" ]]; then
        if command -v ollama >/dev/null 2>&1; then
            printf "      → %-18s " "Ollama"; cyan "already installed"
        else
            _progress_install "Ollama" bash -c 'curl -fsSL https://ollama.com/install.sh | sh'
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 6 — baseline DB
# ---------------------------------------------------------------------------

if [[ "$BASELINE_MODE" != "none" ]]; then
    step 6 "$TOTAL_STEPS" "baseline DB ($BASELINE_MODE)"

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
                step 6 "$TOTAL_STEPS" "baseline DB (build)"   # re-print
                "$PY" -m mcp_baseline.build_baseline_db > /tmp/siftics_baseline.log 2>&1 \
                    && ok "$(du -h mcp_baseline/baseline.sqlite | cut -f1)" \
                    || die "" "local build failed (see /tmp/siftics_baseline.log)"
                ;;
        esac
    fi
fi

# ---------------------------------------------------------------------------
# Step 7 — forensic RAG index
# ---------------------------------------------------------------------------

CUR_STEP=6
[[ "$BASELINE_MODE" == "none" ]] && CUR_STEP=5

if [[ "$BUILD_RAG" == "yes" ]]; then
    CUR_STEP=$((CUR_STEP + 1))
    step "$CUR_STEP" "$TOTAL_STEPS" "forensic RAG index (Sigma + ATT&CK + LOLBAS + Atomic)"

    if [[ -s mcp_rag/index/records.jsonl ]]; then
        records=$(wc -l < mcp_rag/index/records.jsonl 2>/dev/null || echo "?")
        skip "already present ($records records)"
    else
        yel "(clones 4 repos from GitHub, ~10-30 min on first run)"
        "$PY" -m mcp_rag.build_index --output mcp_rag/index \
            > /tmp/siftics_rag.log 2>&1 \
            && ok "$(wc -l < mcp_rag/index/records.jsonl) records" \
            || warn "RAG index build failed — mcp_rag will return empty results
       (see /tmp/siftics_rag.log). Re-run with internet access to fix."
    fi
fi

# ---------------------------------------------------------------------------
# Step 8 — init case dir (optional)
# ---------------------------------------------------------------------------


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
# Final step — start UI (optional)
# ---------------------------------------------------------------------------

if [[ "$START_UI" == "yes" ]]; then
    CUR_STEP=$((CUR_STEP + 1))
    UI_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    UI_IP="${UI_IP:-127.0.0.1}"
    step "$CUR_STEP" "$TOTAL_STEPS" "starting siftics-ui at http://${UI_IP}:8080"

    if pgrep -f "siftics-ui run" >/dev/null; then
        skip "already running (pid $(pgrep -f 'siftics-ui run' | head -1))"
    else
        nohup .venv/bin/siftics-ui run \
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
else
    echo "  • Start the UI:       ./setup.sh   (or: .venv/bin/siftics-ui run &)"
fi
if [[ "$INIT_CASE" != "yes" ]]; then
    echo "  • Create a case:      see README QUICKSTART, or rerun with --init-case"
fi
echo "  • Bypass tests:       .venv/bin/python -m pytest tests/test_constraints.py -v"
echo "  • Start the agent:    claude  → /investigation-section-chief"
echo "  • Choose runtime:     http://${UI_IP}:8080/setup"
echo
echo "Docs: docs/QUICKSTART.md  ·  docs/architecture.md"
