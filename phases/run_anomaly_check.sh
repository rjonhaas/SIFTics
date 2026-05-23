#!/usr/bin/env bash
# Phase 18 wrapper — runs cross-artifact anomaly check.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"${REPO_ROOT}/.venv/bin/python" -m phases.anomaly_check "$@"
