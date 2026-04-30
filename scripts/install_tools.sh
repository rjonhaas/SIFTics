#!/usr/bin/env bash
# install_tools.sh — Pre-flight dependency checker for the jackofallhacks
# triage framework. Checks required EZ Tools are present and offers to
# download any that are missing from Eric Zimmerman's official CDN.
#
# Run directly:   bash install_tools.sh
# Run silently:   bash install_tools.sh --check-only   (exits 1 if anything missing)
#
# Downloads target .NET 9 binaries from:
#   https://f001.backblazeb2.com/file/EricZimmermanTools/net9/<Tool>.zip
#
# All installs go to /opt/zimmermantools/ (requires sudo or root).

set -euo pipefail

INSTALL_DIR="/opt/zimmermantools"
CDN_BASE="https://download.ericzimmermanstools.com/net9"
CHECK_ONLY=false
[[ "${1:-}" == "--check-only" ]] && CHECK_ONLY=true

# ─── tool manifest ───────────────────────────────────────────────────────────
# Format: "display_name|dll_path|zip_filename"
# dll_path is relative to INSTALL_DIR

REQUIRED_TOOLS=(
    "MFTECmd      |MFTECmd.dll                        |MFTECmd.zip"
    "RECmd        |RECmd/RECmd.dll                    |RECmd.zip"
    "AmcacheParser|AmcacheParser.dll                  |AmcacheParser.zip"
    "AppCompatCache|AppCompatCacheParser.dll           |AppCompatCacheParser.zip"
    "SBECmd       |SBECmd.dll                         |SBECmd.zip"
    "EvtxECmd     |EvtxeCmd/EvtxECmd.dll              |EvtxECmd.zip"
    "LECmd        |LECmd.dll                          |LECmd.zip"
    "JLECmd       |JLECmd.dll                         |JLECmd.zip"
    "RBCmd        |RBCmd.dll                          |RBCmd.zip"
    "WxTCmd       |WxTCmd.dll                         |WxTCmd.zip"
    "PECmd        |PECmd.dll                          |PECmd.zip"
)

# ─── helpers ─────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { printf "  ${GREEN}[OK]${NC}      %s\n" "$*"; }
miss() { printf "  ${RED}[MISSING]${NC} %s\n" "$*"; }
info() { printf "  ${YELLOW}[INFO]${NC}    %s\n" "$*"; }

# ─── check phase ─────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════"
echo " EZ Tools Pre-Flight Check"
echo " Install dir : ${INSTALL_DIR}"
echo " Runtime     : .NET 9 (net9.0)"
echo " CDN         : ${CDN_BASE}"
echo "════════════════════════════════════════════════════"
echo ""

MISSING=()

for entry in "${REQUIRED_TOOLS[@]}"; do
    name=$(echo "${entry}" | cut -d'|' -f1 | tr -d ' ')
    dll=$(echo "${entry}"  | cut -d'|' -f2 | tr -d ' ')
    zip=$(echo "${entry}"  | cut -d'|' -f3 | tr -d ' ')

    if [[ -f "${INSTALL_DIR}/${dll}" ]]; then
        ok "${name} → ${INSTALL_DIR}/${dll}"
    else
        miss "${name} → ${INSTALL_DIR}/${dll}"
        MISSING+=("${entry}")
    fi
done

echo ""

if [[ ${#MISSING[@]} -eq 0 ]]; then
    echo "  All required tools are present. No action needed."
    echo ""
    exit 0
fi

echo "  ${#MISSING[@]} tool(s) missing."
echo ""

${CHECK_ONLY} && exit 1

# ─── install phase ───────────────────────────────────────────────────────────

echo "════════════════════════════════════════════════════"
echo " The following tools will be downloaded and installed:"
echo ""
for entry in "${MISSING[@]}"; do
    name=$(echo "${entry}" | cut -d'|' -f1 | tr -d ' ')
    zip=$(echo "${entry}"  | cut -d'|' -f3 | tr -d ' ')
    info "${name}  ←  ${CDN_BASE}/${zip}"
done
echo ""
echo " Install destination : ${INSTALL_DIR}"
echo " Requires            : sudo (will prompt if needed)"
echo "════════════════════════════════════════════════════"
echo ""
read -rp "  Proceed with installation? [y/N] " confirm
echo ""

if [[ "${confirm,,}" != "y" ]]; then
    echo "  Aborted. Re-run when ready or install manually:"
    for entry in "${MISSING[@]}"; do
        name=$(echo "${entry}" | cut -d'|' -f1 | tr -d ' ')
        zip=$(echo "${entry}"  | cut -d'|' -f3 | tr -d ' ')
        dll=$(echo "${entry}"  | cut -d'|' -f2 | tr -d ' ')
        dest_dir="${INSTALL_DIR}/$(dirname "${dll}")"
        echo ""
        echo "    # ${name}"
        echo "    curl -L '${CDN_BASE}/${zip}' -o /tmp/${zip}"
        echo "    sudo unzip -o /tmp/${zip} -d '${dest_dir}'"
    done
    echo ""
    exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

INSTALLED=0
FAILED=0

for entry in "${MISSING[@]}"; do
    name=$(echo "${entry}" | cut -d'|' -f1 | tr -d ' ')
    dll=$(echo "${entry}"  | cut -d'|' -f2 | tr -d ' ')
    zip=$(echo "${entry}"  | cut -d'|' -f3 | tr -d ' ')
    dest_dir="${INSTALL_DIR}/$(dirname "${dll}")"

    printf "  Installing %-16s ... " "${name}"

    if ! curl -fsSL "${CDN_BASE}/${zip}" -o "${TMP_DIR}/${zip}" 2>/dev/null; then
        echo "DOWNLOAD FAILED"
        (( FAILED++ )) || true
        continue
    fi

    sudo mkdir -p "${dest_dir}"
    if ! sudo unzip -o -q "${TMP_DIR}/${zip}" -d "${dest_dir}" 2>/dev/null; then
        echo "EXTRACT FAILED"
        (( FAILED++ )) || true
        continue
    fi

    if [[ -f "${INSTALL_DIR}/${dll}" ]]; then
        echo "OK"
        (( INSTALLED++ )) || true
    else
        echo "VERIFY FAILED (dll not found after extract)"
        (( FAILED++ )) || true
    fi
done

echo ""
echo "  Installed : ${INSTALLED}"
echo "  Failed    : ${FAILED}"
echo ""

if [[ ${FAILED} -gt 0 ]]; then
    echo "  One or more tools failed. Check network access to:"
    echo "    ${CDN_BASE}"
    exit 1
fi

echo "  Re-running check to confirm..."
echo ""
bash "$0" --check-only && echo "  All tools verified." || echo "  Some tools still missing — check output above."
echo ""
