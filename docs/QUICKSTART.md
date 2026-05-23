# SIFTics Quickstart

Tested on a fresh **SANS SIFT 2026.04 OVA**, on **WSL-Ubuntu-22.04 + SIFT-server-mode**, and on **Linux Mint 22 hosts**. Per Rob T. Lee (Slack 2026-05-13) both SIFT-VM and WSL-SIFT are acceptable hackathon submission targets.

## 30-second path — from `git clone` to first finding

```bash
git clone https://github.com/rjonhaas/SIFTics.git
cd SIFTics
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# One-time seed of the demo baseline DB (~50 curated rows; full Rathbun
# corpus available via `scripts/build_baseline_db.sh --full`)
./scripts/build_baseline_db.sh --seed

# Initialise a case directory
export SIFTICS_CASE_DIR=~/cases/demo
sift-case-init \
    --case-dir "$SIFTICS_CASE_DIR" \
    --case-id  demo_2026_06 \
    --name     "Demo: Find Evil triage" \
    --ic-name  "$USER" \
    --itq-template ./templates/itq_questions.yaml
# (you will be prompted to set an IC passphrase — this derives the HMAC key)

# Run the UI
siftics-ui run --case-dir "$SIFTICS_CASE_DIR" &
# Browse: http://127.0.0.1:8080
```

You now have:

- A working case dir with header, hash-chained audit log, IC HMAC key, and the 35-question ITQ seeded.
- A baseline DB for known-good Windows-file / registry / service / scheduled-task lookups.
- The Flask UI at `localhost:8080` with `/dashboard`, `/gates`, `/audit`, `/chat`, `/setup`.

## Pick your agent runtime

Open `http://127.0.0.1:8080/setup` and choose one:

| Option | Best for | Cost |
|---|---|---|
| **Claude Code** *(primary — what Rob ranked best)* | Has `claude` CLI subscription installed | covered by subscription |
| **Anthropic API key** | In-browser chat panel; full control over models | per-token |
| **Ollama** *(fully local)* | Air-gapped / no-internet demo | $0 |
| OpenAI API key | Stub in v1 | per-token |
| Codex CLI | Stub in v1 | covered by subscription |

If you choose Anthropic API, paste your key in the wizard's password field. It's stored in the OS keychain (or a chmod-600 file as fallback) — never logged.

## Smoke test

```bash
# T1-T8 architectural bypass tests
python -m pytest tests/test_constraints.py -v
# expect: 14 passed in ~2s

# Hash-chained audit verify
.venv/bin/python -c "from siftics import audit; ok, errs = audit.verify_chain(); print('chain ok:', ok)"
```

## End-to-end demo case (Caldera mimikatz scenario)

If you have the sister `hunt_lab` repo set up, you can drive a real attack:

```bash
# Spin up the victim lab (Win11 + Sysmon + Elastic + Caldera + Sandcat)
git clone https://github.com/rjonhaas/hunt_lab && cd hunt_lab && bash setup.sh

# Fire the demo ability (in the Caldera UI at http://192.168.56.30:8888)
#   "Credential dumper (mimikatz variant)"

# Pull the resulting KAPE-style bundle into the SIFTics case
mkdir -p "$SIFTICS_CASE_DIR/evidence/win11"
# (copy EVTX dumps, MFT, registry hives into evidence/win11/)

# Drive the agent
cd ~/SIFTics
claude    # then type:  /investigation-section-chief
```

## Optional — full forensic-RAG knowledge corpus

The shipped repo includes the schema + builder; the actual 22 000-record index is fetched as a release asset (or built locally):

```bash
# Try the GitHub release first; falls back to local build
./scripts/download_rag_index.sh

# Or always build locally (~10–30 min, network-bound)
./scripts/download_rag_index.sh --build

# Better embeddings — optional but recommended:
pip install sentence-transformers
```

Without `sentence-transformers`, `mcp_rag` falls back to a deterministic hash-bag embedder (functional but lower-quality semantic search).

## Optional — full Rathbun baseline corpus

```bash
./scripts/build_baseline_db.sh --full
# Clones AndrewRathbun/VanillaWindowsReference + VanillaWindowsRegistryHives
# Disk: ~5 GB cached, ~200 MB DB. Time: 30+ min on first run.
```

## Optional — connect a real Velociraptor server

`mcp_broker` defaults to mock mode for demos. To wire it to a real server:

```bash
export SIFTICS_BROKER_MODE=real
export SIFTICS_BROKER_API_URL=https://velo.example.com:8000
export SIFTICS_BROKER_API_CERT=/path/to/client.pem
export SIFTICS_BROKER_API_KEY=/path/to/client.key
export SIFTICS_BROKER_CA_CERT=/path/to/server-ca.pem   # optional

# Restart the UI to pick up the new env
pkill -f 'siftics-ui run' || true
siftics-ui run --case-dir "$SIFTICS_CASE_DIR" &
```

Real-mode talks to the Velociraptor REST API (the same endpoint the WebUI uses). For deployments that only expose gRPC, swap in `pyvelociraptor` — the integration point is `mcp_broker.server._post()`.

## Optional — sync to a SIFT VM during development

If you develop on a host and test on a SIFT VM:

```bash
SIFT_HOST=user@192.168.4.52 ./scripts/sync_to_sift.sh
# Optional knobs:
#   SIFT_REMOTE_PATH=~/SIFTics        (default)
#   SIFT_RESTART_UI=no                (skip the post-sync UI restart)
#   SIFT_RUN_TESTS=yes                (run pytest on remote after sync)
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `SIFTICS_CASE_DIR is required` | Set the env var or pass `--case-dir`. |
| `flask --app siftics_ui.app` fails | Use `siftics-ui run` or `flask --app "siftics_ui.app:create_app" run`. |
| `mcp_rag forensic_rag_search` returns `index not found` | Run `./scripts/download_rag_index.sh` or `--build`. |
| `mcp_baseline.lookup_*` returns 0 matches always | DB not built. Run `./scripts/build_baseline_db.sh --seed`. |
| `evtx` import error in `fast_evtx_attack_filter` | `pip install evtx` (pyevtx-rs binding). |
| `sentence-transformers not found` | Optional; `mcp_rag` falls back to hash-bag. Install for higher precision. |
| `BudgetExceeded` raised mid-investigation | You hit `cost_budget_per_case_usd`. Adjust in `/setup` or in `~/.config/siftics/agent.yaml`. |
| `Agent context drift` on approval | Real case work happened between request and consume. Re-request approval. |
| WinRM-style errors with `claude` MCP | Claude Code's MCP wiring lives at `~/.claude/settings.json`. See [setup notes](../README.md#setup-on-sift-workstation). |

## Where everything lives

```
SIFTICS/
├── README.md                  # Devpost compliance map (judges start here)
├── docs/
│   ├── architecture.md        # this layered architecture
│   ├── accuracy_report.md     # measured accuracy + cost data
│   ├── constraint_implementation.md  # G1–G13 architectural guardrails
│   ├── compared_to_valhuntir.md      # honest criterion-by-criterion matrix
│   ├── datasets.md            # evidence sources + corpora
│   ├── demo_video.md          # 5-minute storyboard
│   └── QUICKSTART.md          # this file
├── tests/test_constraints.py  # T1–T8 — 14 passing
├── scripts/
│   ├── build_baseline_db.sh
│   ├── download_rag_index.sh
│   └── sync_to_sift.sh
└── (Python packages: siftics, siftics_ui, mcp_case, mcp_ic_approval,
   mcp_baseline, mcp_cti, mcp_rag, mcp_broker, phases, templates, skills)
```

Submission deadline: **2026-06-15 23:45 EDT**. Submit ≥ 24h early; verify the YouTube link in incognito before hitting submit.
