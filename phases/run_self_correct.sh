#!/usr/bin/env bash
# Self-correction loop — re-runs upstream phases up to N iterations until
# Phase 18 reports zero HIGH-severity anomalies.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"${REPO_ROOT}/.venv/bin/python" -m phases.self_correct "$@"
