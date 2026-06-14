#!/usr/bin/env bash
# Fetch a demo evidence bundle from the hunt_lab GitHub Releases page.
#
# Two halves of every case land in two different places, preserving the
# answer-key isolation rule (evidence and ground truth NEVER share a host
# the agent can reach):
#
#   Evidence     → ~/Desktop/cases/<case>/evidence/   (agent reads from here)
#   Ground truth → ~/dfir_answers/<case>/ground_truth.json   (human-only)
#
# The hunt_lab release attaches evidence_<uuid>.zip + ground_truth_<uuid>.json
# (matching UUIDs). We discover both via the GitHub REST API so we don't
# hard-code per-release URLs.
#
# Usage:
#   ./scripts/download_demo_case.sh                       # latest hunt_lab release
#   ./scripts/download_demo_case.sh --tag v1.0-rh-2026-06-06   # specific tag
#   ./scripts/download_demo_case.sh --name my_case        # custom local case dir
#   ./scripts/download_demo_case.sh --repo me/lab         # alternate source repo

set -euo pipefail

REPO_SLUG="${HUNT_LAB_REPO:-rjonhaas/hunt_lab}"
TAG="latest"
CASE_NAME=""
CASE_BASE="${SIFTICS_CASE_BASE:-$HOME/Desktop/cases}"
ANSWERS_BASE="${SIFTICS_ANSWERS_BASE:-$HOME/dfir_answers}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)   TAG="$2"; shift 2 ;;
        --name)  CASE_NAME="$2"; shift 2 ;;
        --repo)  REPO_SLUG="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1 (use --help)" >&2; exit 2 ;;
    esac
done

# Resolve the release metadata. /latest is special-cased by the GitHub API;
# named tags use /tags/<tag>.
if [[ "$TAG" == "latest" ]]; then
    META_URL="https://api.github.com/repos/$REPO_SLUG/releases/latest"
else
    META_URL="https://api.github.com/repos/$REPO_SLUG/releases/tags/$TAG"
fi

echo "[demo-case] resolving release: $REPO_SLUG @ $TAG"
META_JSON=$(curl -fsSL "$META_URL") || {
    echo "[demo-case] failed to fetch release metadata from $META_URL" >&2
    exit 1
}

# Parse the asset URLs + resolved tag name. python3 is already a hard
# SIFTics dep, so no jq required. JSON is passed via argv[1] so that the
# heredoc owns python's stdin (program source) without colliding with a
# here-string (the previous version had two stdin redirections fighting,
# and bash silently let the here-string win — python then tried to
# execute the JSON and tripped on the `false` literal).
PARSED=$(python3 - "$META_JSON" <<'PY'
import json, sys
r = json.loads(sys.argv[1])
tag = r.get("tag_name", "")
ev = gt = ""
for a in r.get("assets", []):
    n = a.get("name", "")
    if n.startswith("evidence_") and n.endswith(".zip"):
        ev = a.get("browser_download_url", "")
    elif n.startswith("ground_truth_") and n.endswith(".json"):
        gt = a.get("browser_download_url", "")
print(tag, ev, gt)
PY
)
read -r RESOLVED_TAG EVIDENCE_URL GROUND_TRUTH_URL <<<"$PARSED"

if [[ -z "$EVIDENCE_URL" ]]; then
    echo "[demo-case] no evidence_*.zip asset on release $RESOLVED_TAG" >&2
    exit 1
fi
if [[ -z "$GROUND_TRUTH_URL" ]]; then
    echo "[demo-case] no ground_truth_*.json asset on release $RESOLVED_TAG" >&2
    echo "[demo-case] continuing without ground truth (cannot self-grade)"  >&2
fi

# Local case dir name. Default to the release tag — readable, unique per cut.
[[ -n "$CASE_NAME" ]] || CASE_NAME="$RESOLVED_TAG"

CASE_DIR="$CASE_BASE/$CASE_NAME"
ANSWER_DIR="$ANSWERS_BASE/$CASE_NAME"
mkdir -p "$CASE_DIR" "$ANSWER_DIR"

# --- Evidence ---
EV_TMP="$(mktemp -t demo_case_evidence_XXXXXX.zip)"
trap 'rm -f "$EV_TMP"' EXIT
echo "[demo-case] downloading evidence: $(basename "$EVIDENCE_URL")"
curl -fL --progress-bar -o "$EV_TMP" "$EVIDENCE_URL"

EV_SHA=$(sha256sum "$EV_TMP" | awk '{print $1}')
EV_SIZE=$(du -h "$EV_TMP" | cut -f1)
echo "[demo-case] evidence sha256: $EV_SHA  ($EV_SIZE)"

# Extract into case dir. The hunt_lab bundle's top-level layout already
# contains an `evidence/` subdirectory; we extract verbatim so paths match
# the agent's expectations.
echo "[demo-case] extracting → $CASE_DIR"
unzip -q -o "$EV_TMP" -d "$CASE_DIR"

# --- Ground truth (off-case, on host only) ---
if [[ -n "$GROUND_TRUTH_URL" ]]; then
    GT_PATH="$ANSWER_DIR/ground_truth.json"
    echo "[demo-case] downloading ground truth → $GT_PATH"
    curl -fsSL -o "$GT_PATH" "$GROUND_TRUTH_URL"
    chmod 600 "$GT_PATH"  # answers are not for the agent
fi

cat <<EOF

[demo-case] done.
  Case ID            : $CASE_NAME
  Evidence (for agent): $CASE_DIR
  Ground truth (host) : ${GROUND_TRUTH_URL:+$ANSWER_DIR/ground_truth.json}${GROUND_TRUTH_URL:-(not in release)}

Open SIFTics → /new-case, point Case directory at:
  $CASE_DIR
The ground truth never goes on the same machine as the agent. Grade by hand.
EOF
