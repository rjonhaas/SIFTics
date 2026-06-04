#!/usr/bin/env bash
# kill_all.sh — stop all SIFTics processes for a clean restart
# Usage: ./kill_all.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; RESET='\033[0m'

killed=0

kill_pattern() {
    local label="$1" pattern="$2"
    local pids
    # exclude this script's own process tree ($$) and any claude/bash tool wrappers
    pids=$(pgrep -f "$pattern" 2>/dev/null | grep -vE "^($$|$PPID)$" | grep -v "kill_all" || true)
    if [[ -n "$pids" ]]; then
        echo -e "${RED}stopping${RESET} $label (pid $pids)"
        kill $pids 2>/dev/null || true
        killed=$((killed + 1))
    fi
}

kill_pattern "siftics-ui"       "siftics-ui run"
kill_pattern "mcp_baseline"     "mcp_baseline.server"
kill_pattern "mcp_broker"       "mcp_broker.server"
kill_pattern "mcp_case"         "mcp_case.server"
kill_pattern "mcp_cti"          "mcp_cti.server"
kill_pattern "mcp_ic_approval"  "mcp_ic_approval.server"
kill_pattern "mcp_rag"          "mcp_rag.server"

# Give processes a moment to exit cleanly
[[ $killed -gt 0 ]] && sleep 2

# Confirm port 8080 is free
if ss -tlnp 2>/dev/null | grep -q ':8080'; then
    echo -e "${RED}WARNING:${RESET} port 8080 still in use — check 'ss -tlnp | grep 8080'"
    exit 1
fi

if [[ $killed -eq 0 ]]; then
    echo "nothing was running"
else
    echo -e "${GREEN}all stopped${RESET} — port 8080 free, ready for ./setup.sh"
fi
