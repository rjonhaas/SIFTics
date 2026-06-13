# SIFTics Quickstart

Tested on a fresh **SANS SIFT 2026.04 OVA**, on **WSL-Ubuntu-22.04 + SIFT-server-mode**, and on **Linux Mint 22 hosts**. Per Rob T. Lee (Slack 2026-05-13) both SIFT-VM and WSL-SIFT are acceptable hackathon submission targets.

## Express path - one command

```bash
git clone -b find-evil https://github.com/rjonhaas/SIFTics.git
cd SIFTics
./setup.sh --init-case --start-ui
# Browse: http://127.0.0.1:8080
```

`./setup.sh` is idempotent (re-runnable) and narrates each step. Flags:

| Flag | Effect |
|---|---|
| (none) | venv + deps + seed baseline (default - fastest) |
| `--full-baseline` | …but fetch the ~100 MB full Rathbun DB from a GitHub Release (~30 s) |
| `--build-baseline` | …but build the full DB locally from sources (~30 min, ~5 GB cache) |
| `--no-baseline` | skip baseline step entirely |
| `--no-rag` | skip the forensic-RAG index build (Step 7) |
| `--init-case` | also create `~/cases/dry_run/` + Incident Commander (IC) HMAC key |
| `--start-ui` | also launch siftics-ui on `127.0.0.1:8080` |

The script:

- Checks Python 3.10+ is present
- Detects missing `python3.X-venv` and prints the exact `apt install` to run
- Skips steps that already completed (re-running after a partial install is safe)
- Times itself and reports total elapsed time
- Auto-generates the case ID as `YYYY-MM-DD-NN` (zero-padded daily sequence - first case today → `2026-06-11-01`, tenth → `2026-06-11-10`) under `~/Desktop/cases/`. The UI's `/new-case` page uses the same scheme. Override the base with `SIFTICS_CASE_BASE=/some/other/path`; supply a custom name to skip the auto-ID

## Manual path - the same 30 seconds, but explicit

Use this when you want to see what the script automates.

```bash
git clone -b find-evil https://github.com/rjonhaas/SIFTics.git
cd SIFTics
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Baseline DB - pick one:
#   (a) demo / quick-start    (~50 curated rows, instant)
./scripts/build_baseline_db.sh --seed
#   (b) full coverage         (~50-150 MB asset from latest GitHub release, ~30 s)
# ./scripts/download_baseline.sh
#   (c) build from scratch    (clones Rathbun, ~30 min, ~5 GB cache)
# ./scripts/build_baseline_db.sh --full

# Initialise a case directory
export SIFTICS_CASE_DIR=~/cases/demo
sift-case-init \
    --case-dir "$SIFTICS_CASE_DIR" \
    --case-id  demo_2026_06 \
    --name     "Demo: Find Evil triage" \
    --ic-name  "$USER" \
    --itq-template ./templates/itq_questions.yaml
# (you will be prompted to set an IC passphrase - this derives the HMAC key)

# Run the UI
siftics-ui run --case-dir "$SIFTICS_CASE_DIR" &
# Browse: http://127.0.0.1:8080
```

You now have:

- A working case dir with header, hash-chained audit log, IC HMAC key, and the 35-question Initial Triage Questionnaire (ITQ) seeded.
- A baseline DB for known-good Windows-file / registry / service / scheduled-task lookups.
- The Flask UI at `localhost:8080` with `/dashboard`, `/gates`, `/audit`, `/chat`, `/setup`, `/findings`, `/intel`, `/cases`, `/report`.

## Pick your agent runtime

Open `http://127.0.0.1:8080/setup`. Two umbrella radios drive the first-run choices:

- **Anthropic authentication** - *Claude.ai subscription (Pro / Max / Team)* uses the OAuth credentials produced by `claude login`; *Anthropic API key* takes a pasted key. The page detects existing OAuth credentials and existing env keys, so re-opening `/setup` mid-investigation shows you what's active right now.
- **Response posture** - *Standalone* keeps the agent's response tools working against a small sample environment (no infrastructure needed, judges' default); *Connected* talks to a real Velociraptor server via mTLS.

Switching either radio takes effect on the **next agent turn** - the save handler patches `os.environ` in the running Flask process, so no UI restart is needed - and writes a `runtime_auth_changed` / `response_posture_changed` event into the audit chain.

Additional runtime options (further down the page):

| Option | Best for | Cost |
|---|---|---|
| **Claude Code** *(primary - what Rob ranked best)* | Has `claude` CLI subscription installed | covered by subscription |
| **Anthropic API key** | In-browser chat panel; full control over models | per-token |
| **Ollama** *(fully local)* | Air-gapped / no-internet demo | $0 |
| OpenAI API key | Stub in v1 | per-token |
| Codex CLI | Stub in v1 | covered by subscription |

If you choose Anthropic API, paste your key in the wizard's password field. It's stored in the OS keychain (or a chmod-600 file as fallback) - never logged.

**One small UX note**: the ISC persona spells out NIMS-doctrine acronyms (Investigation Section Chief, Common Operating Picture, Affected Systems Register, Containment & Eradication Tracker, Initial Triage Questionnaire, Public Information Officer) on first use per response. This is deliberate - the cyber world has collided meanings for several of these (ISC → Internet Storm Center, ASR → Automatic Speech Recognition, CET → Central European Time, PIO → Programmed I/O), and the spell-out keeps briefings unambiguous when an analyst reads them out of context.

## Optional - external CTI integrations

The `/setup` page also accepts API keys for three optional CTI services that
enrich `mcp_cti` lookups:

| Service | What it adds | Free tier |
|---|---|---|
| **Shodan** | `lookup_shodan_ip()` - open ports, services, banners, CVEs for any IP | yes (1 query/sec) |
| **VirusTotal** | `lookup_virustotal()` - hash / URL / domain / IP reputation across 70+ AV engines | yes (4 queries/min) |
| **OpenSourceMalware** | `osm_lookup_indicator()` - STIX 2.1 indicator + relationship lookups | account required |

All three keys are stored in the OS keychain (libsecret on Linux, Keychain on
macOS, Credential Vault on Windows) via the Python `keyring` library. **Security
posture:**

- The raw key value is **never** written to `agent.yaml`, the audit log, or git
- MCP tools record only the storage location (`keyring:siftics_shodan`,
  `env:SIFTICS_SHODAN_API_KEY`, or `file:~/.config/siftics/shodan.key`) in
  `forensic_audit.jsonl` - never the value itself
- If the OS keychain is unavailable, the fallback is a `chmod 0600` file under
  `~/.config/siftics/` - owned by the analyst user, unreadable by anyone else
- Each integration degrades gracefully when its key is absent: the corresponding
  MCP tool returns an empty result and the agent records the absence as a gap
- Typing the literal string `CLEAR` (all caps) in any key field removes the
  stored credential entirely

Manual key configuration without the UI is still supported via env vars
(`SIFTICS_SHODAN_API_KEY`, `SIFTICS_VT_API_KEY`, `SIFTICS_OSM_API_KEY`) or by
running:

```python
from siftics import runtime_config as rc
cfg = rc.load_config()
rc.save_integration_key(cfg.integrations.shodan, "your-key-here", "shodan.key")
```

## Optional - response targets (Authority Gate destinations)

The `/setup` page also accepts connection profiles for the systems that
Authority Gates fire against. These are higher blast radius than CTI lookups
and are wired separately:

| Target | Authority Gate | Use case |
|---|---|---|
| **Velociraptor** | `execute_hunt_package`, host isolation in `containment_action` | Fleet hunts, network quarantine, live collection |
| **Elastic SIEM** | `publish_intel` destination | Push generated STIX/YARA/Sigma IOCs to a threat-intel index |
| **Microsoft Entra ID** | identity actions in `containment_action` | Revoke session tokens, force password reset, disable user accounts |

**Universal output: the action checklist.** When you call `containment_action`,
the agent always produces a structured action checklist. Configured targets
upgrade each checklist item from "manual action required" to "executable" - 
they never the inverse. A SIFTics deployment with zero targets configured
still produces useful output: a step-by-step plan the IC executes by hand.

**Security model for response targets:**

- Non-secret fields (URLs, cert file paths, tenant IDs, app client IDs) live
  in `agent.yaml` - they are configuration, not credentials
- Secret fields (Elastic API key, Entra app client secret, Velociraptor client
  key file) follow the same keyring-first pattern as the CTI vault
- Velociraptor cert files (`client.pem`, `client.key`, `ca.pem`) should be
  `chmod 0600` in `~/.config/siftics/velociraptor/`
- Entra ID ships in **stub mode by default** - `containment_action` approval
  logs the intent to the audit chain but does NOT call Graph API until you
  explicitly toggle LIVE mode in `/setup`. This is deliberate: real Graph
  calls lock users out of their work; the stub mode lets you exercise the
  full gate workflow without risk

Each target degrades gracefully when not configured. The Authority Gate still
fires, the audit chain still records the IC's decision, and the action
checklist still lists the steps with the manual command/UI path documented.

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

## Optional - full forensic-RAG knowledge corpus

`setup.sh` **automatically builds the RAG index on first run (Step 7)**. It checks whether `mcp_rag/index/` is already present; if not, it builds from GitHub sources (~10–30 min, network-bound). If the build fails, setup warns but does not abort. Pass `--no-rag` to skip Step 7 entirely.

The index contains 6,337 records (Sigma 3,132 · ATT&CK 1,164 · Atomic Red Team 1,804 · LOLBAS 237).

If you need to rebuild manually after setup:

```bash
# Rebuild locally (~10–30 min, network-bound)
./scripts/download_rag_index.sh --build

# Better embeddings - optional but recommended:
pip install sentence-transformers
```

Without `sentence-transformers`, `mcp_rag` falls back to a deterministic hash-bag embedder (functional but lower-quality semantic search).

## Optional - full Rathbun baseline corpus

Two paths:

**Fastest** - fetch the prebuilt SQLite from the latest GitHub Release:
```bash
./scripts/download_baseline.sh
# ~30 seconds; ~50-150 MB compressed download
```

**From scratch** - clone Rathbun's repos and rebuild locally:
```bash
./scripts/build_baseline_db.sh --full
# Clones AndrewRathbun/VanillaWindowsReference + VanillaWindowsRegistryHives
# Disk: ~5 GB cached, ~100 MB DB. Time: 30+ min on first run.
```

The Release-asset path is what we use in CI (`.github/workflows/build_baseline.yml`)
and what we recommend for judges who want full coverage in seconds rather than
minutes.

## Optional - connect a real Velociraptor server

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

Real-mode talks to the Velociraptor REST API (the same endpoint the WebUI uses). For deployments that only expose gRPC, swap in `pyvelociraptor` - the integration point is `mcp_broker.server._post()`.

## Optional - sync to a SIFT VM during development

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
├── tests/test_constraints.py  # T1–T8 - 14 passing
├── scripts/
│   ├── build_baseline_db.sh
│   ├── download_rag_index.sh
│   └── sync_to_sift.sh
└── (Python packages: siftics [incl. completeness_rules.py], siftics_ui,
   mcp_case, mcp_ic_approval, mcp_baseline, mcp_cti, mcp_rag, mcp_broker,
   mcp_intel, phases, templates, skills [investigation-section-chief,
   triage-methodology, hypothesis-engine, windows-artifacts,
   linux-server-artifacts, malware-triage, timeline-reconstruction,
   anti-forensics-detection, case-completeness-review, reporting-conventions,
   macos-artifacts, iot-ot-artifacts, daedalus])
```

Submission deadline: **2026-06-15 23:45 EDT**. Submit ≥ 24h early; verify the YouTube link in incognito before hitting submit.
