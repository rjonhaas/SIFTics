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

  AI runtimes (optional — prompted interactively if none specified)
    --install-claude    Install Claude Code CLI (npm install -g @anthropic-ai/claude-code)
    --install-codex     Install OpenAI Codex CLI (npm install -g @openai/codex)
    --install-ollama    Install Ollama local LLM server (ollama.com/install.sh)
    --no-runtimes       Skip the runtime prompt and install nothing

  Web UI
    --start-ui          Launch siftics-ui on port 8080 after setup completes (default: ON)
                        (binds to 0.0.0.0 — reachable from host browser)
    --no-ui             Skip launching the UI

  Supply chain + system hardening
    --no-security-updates  Skip the unattended-upgrade pass (security-only
                           OS updates applied via apt before any pip work)
    --no-audit          Skip the pip-audit CVE scan after the venv is built

  Maintenance
    --kill-all          Stop siftics-ui and every mcp_* server, free port 8080,
                        and exit. Equivalent to ./scripts/kill_all.sh.

  Misc
    -q, --quiet         Suppress verbose pip output
    -h, --help          Show this help and exit

EXAMPLES
  # Express path — UI starts automatically, no flags needed:
  ./setup.sh

  # Full baseline + UI:
  ./setup.sh --full-baseline

  # Headless / CI (no UI):
  ./setup.sh --no-baseline --no-ui

  # Re-run after a partial install (safe, UI restarts too):
  ./setup.sh

  # Reset: stop the UI + MCP servers, free port 8080, then re-run:
  ./setup.sh --kill-all && ./setup.sh

FILES
  .venv/                     Python virtual environment
  mcp_baseline/baseline.sqlite  Rathbun known-good Windows baseline DB
  mcp_rag/index/             Forensic RAG index (Sigma + ATT&CK + LOLBAS + Atomic Red Team)
  /tmp/siftics-ui.log        Web UI stdout / stderr
  /tmp/siftics_*.log         Per-step log files for baseline build

SEE ALSO
  docs/QUICKSTART.md    30-second path for judges
  docs/architecture.md  Full architecture overview
  man siftics-setup     This page (after: sudo cp docs/man/siftics-setup.1 /usr/local/man/man1/)

EOF
}

# Flags can be combined: ./setup.sh --full-baseline --start-ui

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Flags + defaults
# ---------------------------------------------------------------------------

BASELINE_MODE="seed"        # seed | full | build | none
BUILD_RAG="yes"             # yes | no
# UI starts by default (main's UX choice — most operators want this).
# Pass --no-ui to skip when running headless / for CI.
START_UI="yes"
QUIET="no"
INSTALL_CLAUDE="no"
INSTALL_CODEX="no"
INSTALL_OLLAMA="no"
NO_RUNTIMES="no"
NO_SECURITY_UPDATES="no"
NO_AUDIT="no"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --full-baseline)   BASELINE_MODE="full";   shift ;;
        --build-baseline)  BASELINE_MODE="build";  shift ;;
        --no-baseline)     BASELINE_MODE="none";   shift ;;
        --no-rag)          BUILD_RAG="no";         shift ;;
        --start-ui)        START_UI="yes";         shift ;;
        --no-ui)           START_UI="no";          shift ;;
        --install-claude)  INSTALL_CLAUDE="yes";   shift ;;
        --install-codex)   INSTALL_CODEX="yes";    shift ;;
        --install-ollama)  INSTALL_OLLAMA="yes";   shift ;;
        --no-runtimes)     NO_RUNTIMES="yes";      shift ;;
        --no-security-updates) NO_SECURITY_UPDATES="yes"; shift ;;
        --no-audit)        NO_AUDIT="yes";         shift ;;
        -q|--quiet)        QUIET="yes";            shift ;;
        --kill-all)        KILL_ALL="yes";         shift ;;
        -h|--help)         usage; exit 0 ;;
        *) echo "unknown arg: $1 (use --help)" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# --kill-all short-circuits everything else: stop processes + free the port,
# then exit so the operator can re-run setup cleanly.
if [[ "${KILL_ALL:-no}" == "yes" ]]; then
    exec ./scripts/kill_all.sh
fi

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

# Detect any missing apt prereqs in one pass — historically users on a stock
# SIFT hit `python3-venv` missing and had to drop out, install, and re-run.
# We now auto-install the gap with one sudo apt-get instead of bailing.
declare -a MISSING=()
python3 -c "import venv, ensurepip" 2>/dev/null \
    || MISSING+=("python${PY_VER}-venv" "python3-pip" "python3-dev" "build-essential")
command -v curl >/dev/null \
    || MISSING+=("curl")

if (( ${#MISSING[@]} > 0 )); then
    yel "installing"
    echo
    echo "      → missing apt packages: ${MISSING[*]}"
    if ! command -v sudo >/dev/null; then
        die "" "sudo not available. Install manually:
       apt-get install -y ${MISSING[*]}"
    fi
    echo "      → running: sudo apt-get install -y ${MISSING[*]}"
    sudo apt-get update -qq 2>&1 | tail -1 || true
    if ! sudo apt-get install -y "${MISSING[@]}"; then
        die "" "apt-get install failed. Run manually:
       sudo apt-get install -y ${MISSING[*]}"
    fi
    # Re-verify the gap is closed before continuing.
    python3 -c "import venv, ensurepip" 2>/dev/null \
        || die "" "python3-venv still unavailable after apt install — check the apt output above."
    command -v curl >/dev/null \
        || die "" "curl still unavailable after apt install — check the apt output above."
    step 1 "$TOTAL_STEPS" "system prereqs (post-install re-check)"
fi

# Apply available security updates — stock SIFT (and most fresh Ubuntu) ships
# with a backlog of security advisories and prompts the user to install them
# on first login. Doing it here demonstrates "the toolchain is hardened
# before any forensic work starts" and removes the in-session prompt.
# Uses unattended-upgrade which Ubuntu already configures for security-only
# upgrades via /etc/apt/apt.conf.d/50unattended-upgrades. Skip with
# --no-security-updates if you need a reproducible build at a specific point.
if [[ "$NO_SECURITY_UPDATES" == "no" ]] && command -v sudo >/dev/null; then
    if ! dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
        echo "      → installing unattended-upgrades (for security-only updates)"
        sudo apt-get install -y -qq unattended-upgrades 2>&1 | tail -1 || true
    fi
    if command -v unattended-upgrade >/dev/null; then
        echo "      → applying security updates via unattended-upgrade"
        # --minimal-upgrade-steps keeps each transaction small so an interrupt
        # doesn't leave dpkg half-configured. Log is captured under
        # /var/log/unattended-upgrades/ for audit.
        sudo unattended-upgrade --minimal-upgrade-steps 2>&1 | tail -3 || true
        echo "      → security updates applied (log: /var/log/unattended-upgrades/)"
    fi
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

# Supply-chain CVE audit — scans the installed venv against the PyPA
# advisory database (no network for non-pip-installed packages; pip-audit
# does fetch the index DB once per run). Soft-fail by default: surfaces
# findings to stdout and warns, but does not abort the install. Skip with
# --no-audit. We do a one-shot install of pip-audit into the venv if it's
# missing — keeps the runtime requirement out of pyproject.toml.
if [[ "$NO_AUDIT" == "no" ]]; then
    step_audit_idx=$((3))   # cosmetic — keeps the existing step numbering stable
    printf "[%s/%s] %-58s " "$step_audit_idx.5" "$TOTAL_STEPS" "auditing deps for known CVEs (pip-audit)"
    if ! "$PY" -m pip_audit --version >/dev/null 2>&1; then
        "$PIP" install --quiet pip-audit >/dev/null 2>&1 || true
    fi
    if ! "$PY" -m pip_audit --version >/dev/null 2>&1; then
        warn "pip-audit unavailable — skipping CVE check"
    else
        AUDIT_OUT=$(mktemp)
        if "$PY" -m pip_audit --progress-spinner off > "$AUDIT_OUT" 2>&1; then
            ok "no known vulnerabilities"
        else
            warn "advisories found"
            echo "      ↓ pip-audit report ↓"
            sed 's/^/      /' "$AUDIT_OUT"
            echo "      ↑ end pip-audit report ↑"
            yel "      review the advisories above; re-run with --no-audit to bypass"
        fi
        rm -f "$AUDIT_OUT"
    fi
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
# Step 5b — Anthropic auth (only relevant when Claude Code is the chosen runtime)
#
# SIFTics shells out to `claude` for every agent turn, so the subprocess needs
# either (a) ANTHROPIC_API_KEY in env, or (b) an existing `claude login` OAuth
# session in ~/.claude/. We check in priority order:
#
#   1. ANTHROPIC_API_KEY already in env — nothing to do
#   2. ~/.config/siftics/.env exists with a key — source it
#   3. `claude login` OAuth credentials exist — nothing to do; claude handles it
#   4. None of the above — if interactive, prompt; else warn and continue
#
# The dotenv path is .gitignored (the whole .config/siftics/ tree is in
# .gitignore) and chmod 0600. We never write the key into agent.yaml — the
# runtime_config module is explicit that agent.yaml holds runtime selection
# metadata only, not secrets.
# ---------------------------------------------------------------------------

if [[ "$INSTALL_CLAUDE" == "yes" ]] || command -v claude >/dev/null 2>&1; then
    step "5b" "$TOTAL_STEPS" "Anthropic auth"

    SIFTICS_ENV_FILE="$HOME/.config/siftics/.env"

    # 1. Already in env?
    if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
        ok "ANTHROPIC_API_KEY already set in env (${ANTHROPIC_API_KEY:0:8}…)"

    # 2. Dotenv from a previous setup run?
    elif [[ -s "$SIFTICS_ENV_FILE" ]] && grep -q '^ANTHROPIC_API_KEY=' "$SIFTICS_ENV_FILE"; then
        set -a; . "$SIFTICS_ENV_FILE"; set +a
        ok "loaded ANTHROPIC_API_KEY from $SIFTICS_ENV_FILE"

    # 3. `claude login` OAuth credentials present?
    elif [[ -s "$HOME/.claude/.credentials.json" ]] || [[ -s "$HOME/.claude/credentials.json" ]]; then
        ok "claude login OAuth credentials present — using claude.ai subscription"

    # 4. Interactive prompt, else warn
    elif [[ -t 0 ]]; then
        echo
        cyan "   No Anthropic credentials found. Two ways to sign in:"
        echo "     [a] Paste an Anthropic API key now (from https://console.anthropic.com/settings/keys)"
        echo "     [b] Cancel this script (Ctrl+C), run 'claude login' to use your claude.ai subscription, then re-run setup.sh"
        echo "     [s] Skip — UI will start but agent calls will fail until you set ANTHROPIC_API_KEY"
        echo
        read -r -p "   Paste API key or [s] to skip: " _akey
        if [[ "$_akey" == "s" || "$_akey" == "S" || -z "$_akey" ]]; then
            warn "skipped — set ANTHROPIC_API_KEY in env before using the agent, or run 'claude login'"
        elif [[ "$_akey" != sk-ant-* ]]; then
            warn "that doesn't look like an Anthropic key (expected prefix 'sk-ant-'); not saved"
        else
            mkdir -p "$(dirname "$SIFTICS_ENV_FILE")"
            umask 077
            printf 'ANTHROPIC_API_KEY=%s\n' "$_akey" > "$SIFTICS_ENV_FILE"
            chmod 0600 "$SIFTICS_ENV_FILE"
            export ANTHROPIC_API_KEY="$_akey"
            ok "saved to $SIFTICS_ENV_FILE (chmod 0600) and exported to this shell"
            echo "       Future shells: 'set -a; . $SIFTICS_ENV_FILE; set +a' (or add that one line to ~/.bashrc)"
        fi
    else
        warn "no auth + non-interactive — UI will fail at first agent call.
       Re-run setup.sh interactively, or 'export ANTHROPIC_API_KEY=…' yourself, or 'claude login'"
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
# Cosmetic — SIFTics wallpaper on the SIFT VM desktop
#
# Pure quality-of-life: the demo video has the SIFTics logo behind every
# terminal scene, and operators on a fresh SIFT install see SIFT branding
# turn into SIFTics branding at the moment the agent is ready. Skipped
# cleanly on headless / WSL / no GUI / no XDG session.
# ---------------------------------------------------------------------------

set_siftics_wallpaper() {
    local src="${SCRIPT_DIR}/assets/FindEvilFightEvil.png"
    [[ -f "$src" ]] || return 0

    # Skip if headless / no display server attached
    if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
        return 0
    fi
    # Skip if gsettings isn't available (busybox / non-GTK environments)
    command -v gsettings >/dev/null 2>&1 || return 0

    mkdir -p "$HOME/Pictures" 2>/dev/null || return 0
    local dst="$HOME/Pictures/FindEvilFightEvil.png"
    cp "$src" "$dst" 2>/dev/null || return 0

    # SIFT 2026.04 OVA is Ubuntu MATE; WSL-SIFT is often GNOME; Mint hosts are
    # Cinnamon. Try the matching schema; fall through to best-effort if the
    # session reports something we don't recognise.
    local de="${XDG_CURRENT_DESKTOP:-}"
    case "${de,,}" in
        *mate*)
            gsettings set org.mate.background picture-filename "$dst"  2>/dev/null || true
            gsettings set org.mate.background picture-options  'zoom'  2>/dev/null || true
            ;;
        *cinnamon*)
            gsettings set org.cinnamon.desktop.background picture-uri     "file://$dst" 2>/dev/null || true
            gsettings set org.cinnamon.desktop.background picture-options 'zoom'        2>/dev/null || true
            ;;
        *gnome*|*ubuntu*|*unity*)
            gsettings set org.gnome.desktop.background picture-uri      "file://$dst" 2>/dev/null || true
            gsettings set org.gnome.desktop.background picture-uri-dark "file://$dst" 2>/dev/null || true
            gsettings set org.gnome.desktop.background picture-options  'zoom'        2>/dev/null || true
            gsettings set org.gnome.desktop.background primary-color    '#000000'     2>/dev/null || true
            ;;
        *)
            # Unknown DE - try MATE first (SIFT default), then Cinnamon, then
            # GNOME. Failures are silently absorbed; we never block setup over
            # a cosmetic.
            gsettings set org.mate.background picture-filename "$dst"    2>/dev/null \
                || gsettings set org.cinnamon.desktop.background picture-uri "file://$dst" 2>/dev/null \
                || gsettings set org.gnome.desktop.background picture-uri "file://$dst" 2>/dev/null \
                || true
            ;;
    esac
    return 0
}

# Fire the wallpaper set; output suppressed so the install-progress lines
# stay clean. Any failure is swallowed by the function itself.
set_siftics_wallpaper

# ---------------------------------------------------------------------------
# Cosmetic — disable screen blanking and screensaver on the analyst host
#
# A blank screen mid-demo or mid-investigation is the worst kind of
# interrupt. Set the session to never idle-blank, never lock, and never
# DPMS-off. Skipped cleanly on headless / no display.
#
# Reverting (if you want default blanking back): re-enable in the DE's
# Power / Screensaver settings, or `xset s default; xset +dpms`.
# ---------------------------------------------------------------------------

disable_screen_blanking() {
    # Skip if headless / no display server attached
    if [[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]; then
        return 0
    fi

    # X11 session controls — works on any DE with X. No-op on pure Wayland.
    if command -v xset >/dev/null 2>&1 && [[ -n "${DISPLAY:-}" ]]; then
        xset s off       2>/dev/null || true   # disable screensaver
        xset s noblank   2>/dev/null || true   # don't blank the video
        xset -dpms       2>/dev/null || true   # disable monitor power-off
    fi

    # gsettings (persistent across sessions)
    command -v gsettings >/dev/null 2>&1 || return 0
    local de="${XDG_CURRENT_DESKTOP:-}"
    case "${de,,}" in
        *mate*)
            gsettings set org.mate.session idle-delay 0                              2>/dev/null || true
            gsettings set org.mate.screensaver idle-activation-enabled false         2>/dev/null || true
            gsettings set org.mate.screensaver lock-enabled false                    2>/dev/null || true
            ;;
        *cinnamon*)
            gsettings set org.cinnamon.desktop.session idle-delay 0                  2>/dev/null || true
            gsettings set org.cinnamon.desktop.screensaver idle-activation-enabled false 2>/dev/null || true
            gsettings set org.cinnamon.desktop.screensaver lock-enabled false        2>/dev/null || true
            ;;
        *gnome*|*ubuntu*|*unity*)
            gsettings set org.gnome.desktop.session idle-delay 0                     2>/dev/null || true
            gsettings set org.gnome.desktop.screensaver idle-activation-enabled false 2>/dev/null || true
            gsettings set org.gnome.desktop.screensaver lock-enabled false           2>/dev/null || true
            ;;
        *)
            # Unknown DE — best-effort against the three schemas above.
            gsettings set org.mate.session idle-delay 0                  2>/dev/null \
                || gsettings set org.cinnamon.desktop.session idle-delay 0 2>/dev/null \
                || gsettings set org.gnome.desktop.session idle-delay 0    2>/dev/null \
                || true
            ;;
    esac
    return 0
}

disable_screen_blanking

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

        # Poll for port 8080 to actually accept connections. The old check was
        # `sleep 2 && kill -0 $PID`, which passed while siftics-ui was still
        # importing dependencies — the URL printed at the end of setup, the
        # user clicked it, the browser hit ERR_CONNECTION_REFUSED. Wait up to
        # 20 seconds and probe the real port; fail loud (with log content) if
        # we never reach a listening socket.
        UI_READY=0
        for _ in $(seq 1 20); do
            if curl -sf --max-time 1 -o /dev/null "http://127.0.0.1:8080/" 2>/dev/null; then
                UI_READY=1
                break
            fi
            if ! kill -0 "$UI_PID" 2>/dev/null; then
                # Process is gone before the port came up — die with the log.
                LOG_TAIL=$(tail -15 /tmp/siftics-ui.log 2>/dev/null | sed 's/^/       /')
                die "" "siftics-ui exited before opening port 8080. Log tail:
${LOG_TAIL}"
            fi
            sleep 1
        done
        if [[ "$UI_READY" -eq 0 ]]; then
            LOG_TAIL=$(tail -15 /tmp/siftics-ui.log 2>/dev/null | sed 's/^/       /')
            die "" "siftics-ui did not open port 8080 within 20s. Log tail:
${LOG_TAIL}"
        fi
        ok "pid $UI_PID"
    fi
fi

# ---------------------------------------------------------------------------
# Summary — single line, just the URL. Everything else moved to docs/.
# ---------------------------------------------------------------------------

if [[ "$START_UI" == "yes" ]]; then
    UI_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    UI_IP="${UI_IP:-127.0.0.1}"
    echo
    green "SIFTics is ready. Open this URL in your browser:"
    cyan  "    http://${UI_IP}:8080"
    echo
fi
