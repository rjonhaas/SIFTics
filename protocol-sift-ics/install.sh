#!/usr/bin/env bash
# Protocol SIFT ICS — bootstrap script for SANS SIFT Workstation
# Usage:  bash install.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Protocol SIFT ICS — installer                              ║"
echo "║  NIMS ICS-structured AI swarm for DFIR                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# ──────────────────────────────────────────────────────────────────
# Pre-flight checks
# ──────────────────────────────────────────────────────────────────

echo "[1/6] Pre-flight checks..."

if ! grep -q "SIFT" /etc/os-release 2>/dev/null && \
   ! command -v sift-cli >/dev/null 2>&1; then
  echo "  ⚠  This does not appear to be a SIFT Workstation."
  echo "     You can still install, but forensic tools may be missing."
  read -r -p "     Continue? [y/N] " resp
  [[ "$resp" == "y" || "$resp" == "Y" ]] || exit 1
fi

for cmd in node npm git findmnt sha256sum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "  ✗ Missing required command: $cmd"
    echo "     Install with: sudo apt install -y $cmd"
    exit 1
  fi
done

NODE_MAJOR=$(node -v | sed -e 's/^v//' -e 's/\..*//')
if (( NODE_MAJOR < 20 )); then
  echo "  ✗ Node.js 20+ required (found v$NODE_MAJOR)"
  exit 1
fi

echo "  ✓ Pre-flight OK"

# ──────────────────────────────────────────────────────────────────
# Directory setup
# ──────────────────────────────────────────────────────────────────

echo "[2/6] Setting up directories..."

EVIDENCE_MOUNT="${EVIDENCE_MOUNT:-/mnt/evidence}"
WORKING_DIR="${WORKING_DIR:-/working}"

sudo mkdir -p "$EVIDENCE_MOUNT"
sudo mkdir -p "$WORKING_DIR"
sudo chown "$USER":"$USER" "$WORKING_DIR"
chmod 755 "$WORKING_DIR"

echo "  ✓ Evidence mount: $EVIDENCE_MOUNT (ensure mounted ro,noatime,noexec,nodev)"
echo "  ✓ Working dir:    $WORKING_DIR"

# ──────────────────────────────────────────────────────────────────
# OpenClaw install
# ──────────────────────────────────────────────────────────────────

echo "[3/6] Installing OpenClaw..."

if ! command -v openclaw >/dev/null 2>&1; then
  npm install -g openclaw
  echo "  ✓ OpenClaw installed"
else
  echo "  ✓ OpenClaw already installed ($(openclaw --version 2>/dev/null || echo '?'))"
fi

# ──────────────────────────────────────────────────────────────────
# MCP server build
# ──────────────────────────────────────────────────────────────────

echo "[4/6] Building Protocol SIFT MCP server..."

cd "$REPO_ROOT/mcp-server"
npm install --silent
npm run build
echo "  ✓ MCP server built"

# ──────────────────────────────────────────────────────────────────
# Skill registration
# ──────────────────────────────────────────────────────────────────

echo "[5/6] Registering ICS skills with OpenClaw..."

OPENCLAW_CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-$HOME/.openclaw}"
mkdir -p "$OPENCLAW_CONFIG_DIR/skills"

# Symlink our skills directory into OpenClaw's skill discovery path
if [[ ! -L "$OPENCLAW_CONFIG_DIR/skills/protocol-sift-ics" ]]; then
  ln -s "$REPO_ROOT/skills" "$OPENCLAW_CONFIG_DIR/skills/protocol-sift-ics"
fi

cp "$REPO_ROOT/config/openclaw.json" "$OPENCLAW_CONFIG_DIR/openclaw.json.new"
echo "  ✓ Skills registered at $OPENCLAW_CONFIG_DIR/skills/protocol-sift-ics"
echo "  ✓ Config template copied to $OPENCLAW_CONFIG_DIR/openclaw.json.new"
echo "    → Review and rename to openclaw.json after setting ANTHROPIC_API_KEY"

# ──────────────────────────────────────────────────────────────────
# Sanity checks
# ──────────────────────────────────────────────────────────────────

echo "[6/6] Sanity checks..."

# Verify no skill other than tool-broker claims MCP invoke permission
OFFENDERS=$(grep -rln "invoke:" "$REPO_ROOT/skills" | \
  xargs -I{} sh -c 'grep -l "mcp_server" "{}" | grep -v "tool-broker"' || true)

if [[ -n "$OFFENDERS" ]]; then
  echo "  ✗ ARCHITECTURAL VIOLATION: the following skills claim MCP access:"
  echo "$OFFENDERS"
  echo "     Only logistics/tool-broker may invoke the MCP server."
  exit 1
fi

echo "  ✓ Only tool-broker has MCP invoke permission"

# Verify every SKILL.md has a description field (OpenClaw requires it)
for skill in $(find "$REPO_ROOT/skills" -name SKILL.md); do
  if ! grep -q "^description:" "$skill"; then
    echo "  ✗ Missing description in $skill"
    exit 1
  fi
done

echo "  ✓ All SKILL.md files have descriptions"

# ──────────────────────────────────────────────────────────────────
# Done
# ──────────────────────────────────────────────────────────────────

cat <<EOF

╔══════════════════════════════════════════════════════════════════╗
║  Install complete.                                              ║
║                                                                  ║
║  Next steps:                                                    ║
║    1. Set ANTHROPIC_API_KEY in $OPENCLAW_CONFIG_DIR/openclaw.json.new
║    2. Rename it to openclaw.json                                ║
║    3. Mount evidence read-only at $EVIDENCE_MOUNT               ║
║    4. Run: openclaw onboard                                     ║
║    5. Activate the IC with a directive:                         ║
║       openclaw invoke command-staff/incident-commander \\        ║
║         --input '{"incident_id":"INC-001", ...}'                ║
║                                                                  ║
║  Read ARCHITECTURE.md for trust boundaries.                     ║
║  Read skills/README.md for skill directory layout.              ║
╚══════════════════════════════════════════════════════════════════╝
EOF
