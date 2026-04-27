#!/usr/bin/env bash
# Bootstrap an incident response. Pre-flights, builds the IC directive,
# and dispatches it.
#
# Usage:  scripts/run-incident.sh [--incident-id INC-001] [--dry-run]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

INCIDENT_ID="INC-$(date -u +%Y%m%d-%H%M%S)"
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --incident-id) INCIDENT_ID="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    *)             echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

echo "=== Pre-flight ==="
PREFLIGHT_JSON=$(node "$REPO_ROOT/scripts/preflight.mjs" || true)
echo "$PREFLIGHT_JSON" | tee "$REPO_ROOT/.preflight-${INCIDENT_ID}.json" >/dev/null
OK=$(echo "$PREFLIGHT_JSON" | sed -n 's/.*"ok": *\(true\|false\).*/\1/p' | head -1)
if [[ "$OK" != "true" ]]; then
  echo "Pre-flight failed. Failures:"
  echo "$PREFLIGHT_JSON" | grep -B1 '"ok": false' | grep -E '"name"|"detail"' || true
  if [[ $DRY_RUN -eq 0 ]]; then
    echo
    echo "Refusing to dispatch to the IC. Run with --dry-run to print the directive anyway."
    exit 1
  fi
fi

echo
echo "=== IC directive ==="
DIRECTIVE_FILE="$REPO_ROOT/.directive-${INCIDENT_ID}.json"
node "$REPO_ROOT/scripts/build-directive.mjs" --incident-id "$INCIDENT_ID" > "$DIRECTIVE_FILE"
echo "Wrote $DIRECTIVE_FILE"
echo
head -20 "$DIRECTIVE_FILE"
echo "..."

if [[ $DRY_RUN -eq 1 ]]; then
  echo
  echo "(--dry-run: not dispatching)"
  exit 0
fi

echo
echo "=== Dispatch ==="
echo "Project's intended path is: openclaw invoke command-staff/incident-commander --input @$DIRECTIVE_FILE"
echo
echo "But the shipped config/openclaw.json does not validate against OpenClaw 2026.4.24's"
echo "schema (see DEPLOYMENT_NOTES.md). Until that is reconciled, the swarm cannot be"
echo "dispatched through OpenClaw. The directive has been written and is ready."
echo
echo "Next step (when ready): see DEPLOYMENT_NOTES.md → 'Wiring the orchestrator'."
exit 0
