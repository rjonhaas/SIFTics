# SIFTics — Claude Code session context

## What this project is
SANS *Find Evil!* Hackathon submission (deadline **2026-06-15 23:45 EDT**).
Submission target: https://github.com/rjonhaas/SIFTics (branch `find-evil`).
Devpost: https://findevil.devpost.com

SIFTics is a custom-MCP-server IR agent for the SIFT Workstation. It wraps
Claude Code as an *Investigation Section Chief* under NIMS ICS doctrine, with
cryptographically-enforced Authority Gates (HMAC-signed IC approval required
before any active hunt fires).

## Current status (as of 2026-05-31)
All core features are built and passing. 14/14 constraint bypass tests green.
The repo is clean (no uncommitted changes).

### Completed work
- `siftics/` — core library: audit chain, case state, IC approval, cost tracker
- `siftics_ui/` — Flask+HTMX web UI (dashboard, gates, audit, chat, setup)
- `mcp_case/`, `mcp_ic_approval/`, `mcp_baseline/`, `mcp_rag/`, `mcp_broker/`, `mcp_cti/` — MCP servers
- `phases/` — 20 forensic phase scripts incl. Phase 18 anomaly checker + run_self_correct.sh
- `siftics/hypothesis_engine.py` — hypothesis scoring CLI
- `setup.sh` — idempotent one-shot installer (venv + deps + baseline + case + UI)
- `tests/test_constraints.py` — T1–T8 bypass harness (14 tests, all passing)
- `scripts/sync_to_sift.sh` — rsync + remote restart helper
- `scripts/bootstrap_sift_vm.sh` — full VM bootstrap script
- CI: `.github/workflows/build_baseline.yml` — builds full Rathbun SQLite on release
- `docs/accuracy_report.md` §3.3 + §6 — hallucination mitigation documented (RAG grounding,
  source_type field, v2 UI badge roadmap); README item #6 added
- `mcp_rag/`, `mcp_baseline/`, `mcp_cti/` — `source_type` audit events now written on every
  enrichment call (`rag_lookup` / `baseline_lookup` / `cti_lookup`); docs match implementation

### Last fix
`mcp_rag/server.py`, `mcp_baseline/server.py`, `mcp_cti/server.py` — these MCP servers were
completely invisible in `forensic_audit.jsonl`. Added `append_event` calls with `source_type:
"ai_enrichment"` (RAG) and `source_type: "deterministic"` (baseline + CTI) so the accuracy
report's §3.3 claim about the `source_type` field is now true rather than aspirational.

### Remaining / next tasks
- **SIFT VM sync** — rsync to 192.168.4.52 is the last unfinished task.
  VM was unreachable during last session. When it's up:
  ```
  SIFT_HOST=zeus@192.168.4.52 SIFT_RUN_TESTS=yes ./scripts/sync_to_sift.sh
  ```
- **Example run output** — `examples/run_2026-XX-XX/` placeholder needs a real
  `forensic_audit.jsonl` trace for Devpost item #10.
- **Demo video** — storyboard is in `docs/demo_video.md`; YouTube link TBD.
- **GitHub release** — tag `find-evil-v1`, trigger CI to publish baseline asset.

## Operator preferences
- **Always do a full stop/start cycle when restarting the UI.** Kill any running `siftics-ui` process first (`pkill -f "siftics-ui run"` or by PID), confirm port 8080 is free (`ss -tlnp | grep 8080`), then bring it back up with `./setup.sh --start-ui`. Never assume the existing process picked up new changes.

## How to pick up

```bash
cd /home/sansforensics/SIFTics
source .venv/bin/activate

# Verify everything still passes
.venv/bin/python -m pytest tests/test_constraints.py -v

# Kill everything, then bring back up
./scripts/kill_all.sh && ./setup.sh
# Browse: http://192.168.2.149:8080
```

## Key files for judges / graders
| What | Where |
|---|---|
| Devpost compliance map | `README.md` (top section) |
| Architecture | `docs/architecture.md` + `docs/architecture.png` |
| Constraint guardrails | `docs/constraint_implementation.md` |
| Accuracy report | `docs/accuracy_report.md` |
| Bypass test harness | `tests/test_constraints.py` |
| Quickstart (30 s) | `docs/QUICKSTART.md` |

## Local machine notes
- Working dir: `/home/zeus/Desktop/find_evil`
- Venv: `.venv/` (Python 3.12)
- Case dir: `~/Desktop/cases/`
- SIFT VM target: `192.168.4.52` (may need to be started)
- SSH now enabled on this machine (`sudo systemctl status ssh`)
