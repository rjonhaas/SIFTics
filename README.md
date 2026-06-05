# SIFTics — SANS *Find Evil!* Hackathon Submission

> **Tagline:** Valhuntir answers *"what happened here?"* — SIFTics answers *"what happened here, where else is it, and is it still happening?"*

**Architectural pattern (per [hackathon rules](https://findevil.devpost.com)):** **Custom MCP Server** — Rob T. Lee's #2 approach, *"the most sound architecture in the evaluation."*

**Platform:** SANS SIFT Workstation + Claude Code (or any other approved agentic framework that speaks MCP).

**License:** [MIT](LICENSE) (Devpost-detectable, repo root).

---

## Devpost compliance map — every required deliverable, with locations

> *Per Rob T. Lee's Slack guidance: "Do not make it hard for the judges to see where the components are. Make it SUPER EASY TO FIND THEM."*

| # | Devpost requirement | Location in this repo |
|---|---|---|
| 1 | **URL to code repository** | [https://github.com/rjonhaas/SIFTics](https://github.com/rjonhaas/SIFTics) *(public, this repo)* |
| 2 | **Open-source license (MIT or Apache 2.0)** | [`LICENSE`](LICENSE) *(repo root, MIT)* |
| 3 | **README with setup instructions** | This file — see [Setup](#setup-on-sift-workstation) below |
| 4 | **Live deployment URL OR local setup instructions** | Local — [Quickstart](#quickstart-30-seconds-from-clone-to-first-finding) below |
| 5 | **Text description (features and functionality)** | [Project Description](#project-description) below |
| 6 | **Demo video (≤ 5 min, live terminal, audio narration)** | [`docs/demo_video.md`](docs/demo_video.md) — YouTube link + storyboard |
| 7 | **Architecture Diagram** | [`docs/architecture.md`](docs/architecture.md) + [`docs/architecture.png`](docs/architecture.png) — trust boundaries colour-coded (red = architectural, yellow = prompt-based) |
| 8 | **Evidence Dataset Documentation** | [`docs/datasets.md`](docs/datasets.md) — DEF CON DFIR CTF + CyberDefenders Case 166 + hunt_lab generated case |
| 9 | **Accuracy Report** | [`docs/accuracy_report.md`](docs/accuracy_report.md) — measured FP/FN, hallucinations, integrity, T1–T8 bypass test results |
| 10 | **Agent Execution Logs** | [`examples/run_2026-XX-XX/forensic_audit.jsonl`](examples/) — hash-chained, end-to-end trace from finding → tool execution |

> **Judges**: every required item above has a direct link. If anything is missing or unclear, please open a GitHub issue and we will respond within 24 hours.

---

## Project description

SIFTics turns the SIFT Workstation into a **machine-speed incident response agent** that:

1. **Closes the speed gap** between attackers operating at 7-minute breakout times and human responders. The HOT execution layer produces candidate findings in seconds, generates a Velociraptor hunt package, surfaces it to the Incident Commander for cryptographically-signed approval, and fires it across the enterprise within tens of seconds.
2. **Operates under NIMS Incident Command System doctrine.** The Claude Code agent functions as the *Investigation Section Chief* (tactical autonomy); the human analyst is the *Incident Commander* (strategic authority). Authority Gates between them are **architecturally enforced** via HMAC-signed approval objects, not by prompt instructions.
3. **Maintains a tamper-evident audit chain.** Every tool execution, every IC decision, and every action result is logged as a hash-chained JSONL row; the chain is verifiable end-to-end with `audit_verify.sh`.
4. **Self-corrects under doctrine.** Phase-18 anomaly detection scans for cross-artifact contradictions and re-runs upstream phases up to three iterations until the contradiction count decreases.
5. **Drives Velociraptor as an active hunt controller** (not just a parser). Findings become typed `HuntPackage` objects; approved packages execute as enterprise-wide hunts; results feed back into the COP.
6. **Grounds AI enrichment in retrieved evidence, not model memory.** Every MITRE technique alignment, LOLBAS context note, and Sigma rule explanation is backed by a record retrieved from the embedded `mcp_rag` forensic index — not generated from training-time knowledge alone. Deterministic lookups (baseline hash checks, IOC exact-match) are typed separately from LLM enrichment in `forensic_audit.jsonl`, so analysts know exactly what to verify. See [`docs/accuracy_report.md §3`](docs/accuracy_report.md) for the full hallucination accounting.

### How SIFTics maps to the six judging criteria

| Criterion (equal weight; criterion 1 is tiebreaker) | Where to see it |
|---|---|
| 1. Autonomous Execution Quality | `phases/run_self_correct.sh` + `mcp_broker/hypothesis_score.py` + Authority Gate flow in demo video at t=2:00–3:00 |
| 2. IR Accuracy | [`docs/accuracy_report.md`](docs/accuracy_report.md) — measured against public ground truth |
| 3. Breadth and Depth | 20 phase scripts across Windows / Linux / memory / network / email / cross-machine attack-path — see [`phases/`](phases/) |
| 4. Constraint Implementation | [`docs/constraint_implementation.md`](docs/constraint_implementation.md) — architectural (red) vs prompt-based (yellow) guardrails; T1–T8 bypass test results in [`tests/test_constraints.py`](tests/test_constraints.py) |
| 5. Audit Trail Quality | `siftics/audit.py` — hash-chained `forensic_audit.jsonl` + `audit_verify.sh` |
| 6. Usability and Documentation | This README + `docs/QUICKSTART.md` + the SIFTics web UI at `localhost:8080` — dashboard improvements: transcript persists across page reloads (sessionStorage), block-level markdown rendering (tables/lists/headings), separate message bubbles per agent turn; dedicated `/findings`, `/intel`, `/cases`, and `/report` pages |

---

## Quickstart — 30 seconds from clone to first finding

Tested on a fresh **SANS SIFT Workstation 2026.04.22** OVA and on **WSL-Ubuntu-22.04 with SIFT server-mode** (per Rob T. Lee's Slack guidance, both are acceptable submission targets).

### Express path — one command

```bash
git clone -b find-evil https://github.com/rjonhaas/SIFTics.git
cd SIFTics
./setup.sh --init-case --start-ui
# Then open http://127.0.0.1:8080 in a browser
```

`setup.sh` is idempotent and narrates each step. Common variants:

```bash
./setup.sh                              # venv + deps + seed baseline only
./setup.sh --full-baseline              # ...but fetch the full ~100 MB DB from a Release
./setup.sh --build-baseline             # ...but build the full DB locally (~30 min)
./setup.sh --init-case --start-ui       # full express: case dir + UI on 127.0.0.1:8080
./setup.sh --no-rag                     # skip the RAG index build (Step 7)
./setup.sh --help                       # all flags
```

**Step 7 (RAG index):** `setup.sh` now automatically checks for `mcp_rag/index/` and builds the forensic-RAG index from GitHub sources if it is absent. Pass `--no-rag` to skip this step. If the build fails the script warns but does not abort.

If `setup.sh` fails on a missing system package, it prints the exact `apt install` command and exits cleanly.

### Manual path — for understanding what's happening

```bash
# 1. Clone and install
git clone -b find-evil https://github.com/rjonhaas/SIFTics.git
cd SIFTics
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# 2. Baseline DB — pick one:
./scripts/build_baseline_db.sh --seed    # demo: ~50 curated rows, instant
# ./scripts/download_baseline.sh         # full ~100 MB Rathbun corpus from Release, ~30 s
# ./scripts/build_baseline_db.sh --full  # full build from sources, ~30 min, ~5 GB cache

# 3. Initialise a case directory
export SIFTICS_CASE_DIR=~/cases/demo_2026_05_22
sift-case-init \
  --case-dir "$SIFTICS_CASE_DIR" \
  --case-id demo_2026_05_22 \
  --name "Demo: Find Evil! triage" \
  --ic-name "$(whoami)" \
  --itq-template ./templates/itq_questions.yaml
# (you will be prompted for an IC passphrase — this derives the HMAC key)

# 4. Start the SIFTics web UI
siftics-ui run --case-dir "$SIFTICS_CASE_DIR" &
# Now open http://127.0.0.1:8080 in a browser

# 5. Drop some evidence in and start the agent
mkdir -p "$SIFTICS_CASE_DIR/evidence/win11"
# (copy KAPE bundle / disk image / EVTX dump into evidence/win11/)
claude  # launches Claude Code in the SIFTics MCP context
> /investigation-section-chief
```

The agent will read the seeded ITQ, walk the questionnaire by picking the right phase scripts, write findings into the ASR / CET registers, and propose Authority Gates when scope expansion or active actions become appropriate.

A 5-minute demo of this exact sequence runs in [`docs/demo_video.md`](docs/demo_video.md).

---

## Setup on SIFT Workstation

### Prerequisites

- SIFT Workstation 2026.04 or newer (full OVA *or* WSL server-mode install — both supported)
- Python 3.10+
- ~4 GB free RAM, ~10 GB free disk for the bundled knowledge index
- Claude Code (or any other Custom-MCP-capable agentic framework — `claude` CLI tested)

### Install

```bash
# Recommended: pipx for an isolated, repeatable install
pipx install --editable .

# Fetch the prebuilt forensic-RAG index (one-time, ~200 MB)
./scripts/download_rag_index.sh
```

### Repo layout

```
.
├── LICENSE                          MIT — Devpost item #2
├── README.md                        this file — Devpost items #3, #5
├── pyproject.toml                   install metadata
├── requirements.txt
├── siftics/                         core library (case state, audit, IC approval)
│   ├── audit.py                     hash-chained JSONL log + verification
│   ├── case_state.py                COP / ASR / CET / ITQ data layer
│   ├── ic_approval.py               HMAC-SHA256 IC Authority Gate primitives
│   └── cli.py                       sift-case-init, sift-approve
├── siftics_ui/                      Flask + vanilla JS web UI (localhost:8080)
│   ├── app.py
│   ├── labels.yaml                  dual-label config (generic / cimtk)
│   ├── static/vendor/siftics.js     vanilla JS client (replaces HTMX)
│   └── templates/                   Jinja templates (dashboard, gates, audit,
│                                     findings, intel, cases, report)
├── mcp_broker/                      Velociraptor MCP — 10 typed functions
├── mcp_case/                        Case-state MCP server (asr_append, itq_answer,
│                                     finding_record, etc.) — writes findings.jsonl
├── mcp_rag/                         Embedded forensic RAG (sqlite-vec, 6,337 records)
├── mcp_cti/                         OSM STIX + abuse.ch IOC lookups
├── mcp_baseline/                    Rathbun known-good baseline lookup
├── mcp_ic_approval/                 Cryptographic Authority Gate MCP server
├── mcp_intel/                       STIX 2.1 / YARA / Sigma IOC generation — writes intel.jsonl
├── phases/                          20 forensic phase scripts (existing SIFTics)
│   ├── run_ntfs.sh
│   ├── run_registry.sh
│   ├── run_eventlogs.sh
│   ├── run_zircolite.sh             *new* — Sigma-rule application over EVTX
│   ├── run_anomaly_check.sh         Phase 18
│   ├── run_self_correct.sh
│   └── …
├── skills/                          NIMS ICS skill files (agent guidance) — 11 files
│   ├── investigation-section-chief.md
│   ├── triage-methodology.md
│   ├── hypothesis-engine.md
│   ├── windows-artifacts.md
│   ├── linux-server-artifacts.md
│   ├── malware-triage.md
│   ├── timeline-reconstruction.md
│   ├── anti-forensics-detection.md
│   ├── reporting-conventions.md
│   ├── macos-artifacts.md           mac_apt plugin map, Unified Log, APFS, persistence triage
│   ├── iot-ot-artifacts.md          firmware (binwalk), industrial protocol PCAPs, SCADA DBs
│   └── daedalus.md                  tool finder/implementer for unknown artifacts; 6-step workflow
├── tests/
│   └── test_constraints.py          T1–T8 bypass harness — Devpost criterion #4
├── templates/
│   └── itq_questions.yaml           Initial Triage Questionnaire seed
├── docs/
│   ├── architecture.md              architecture overview — Devpost item #7
│   ├── architecture.png             diagram with red/yellow trust boundaries
│   ├── constraint_implementation.md architectural vs prompt-based guardrails
│   ├── datasets.md                  evidence sources — Devpost item #8
│   ├── accuracy_report.md           measured accuracy — Devpost item #9
│   ├── demo_video.md                YouTube link + storyboard — Devpost item #6
│   ├── compared_to_valhuntir.md     honest criterion-by-criterion matrix
│   └── QUICKSTART.md                30-second path for judges
└── examples/
    └── run_2026-XX-XX/              full case run — Devpost item #10
        ├── forensic_audit.jsonl
        ├── findings.jsonl           evidence chain traceability (finding_record)
        ├── intel.jsonl              STIX/YARA/Sigma IOC output (mcp_intel)
        ├── findings/
        └── hunt_packages/
```

---

## How the architectural guardrails work

The single most important architectural property of SIFTics is **the agent cannot bypass Authority Gates because the MCP functions that would let it bypass simply do not exist on its tool surface.**

There are **four gated actions** that require a cryptographically signed `ICApproval` before they execute: `execute_hunt_package` (deploy Velociraptor hunt), `containment_action` (network isolation), `evidence_acquisition` (live collection), and `publish_intel` (push IOCs to a Threat Intelligence Platform). Each gate is distinct — an approval for one is rejected at all others.

Specifically:

- `execute_hunt_package(package, approval)` requires a cryptographically signed `ICApproval` object.
- There is no `execute_hunt_package_unapproved()` function.
- The Python type system enforces the requirement (`approval: ICApproval` is a required positional argument).
- The function body re-verifies the HMAC signature, the agent context hash, and the double-spend check before doing any work.
- The IC's HMAC key lives in `$CASE/ic_key.hmac` (mode 0600, owner = analyst); the MCP server process runs as a different user that can read only `$CASE/ic_verifier.hmac` (mode 0640) — and in v2 these would be Ed25519 public/private separation.

Run the bypass test harness to verify:

```bash
python -m pytest tests/test_constraints.py -v
```

T8a–g specifically test the IC approval boundary. T1–T7 test the other architectural guardrails (read-only mounts, namespace-guarded Velociraptor uploads, prompt-injection sanitiser, etc.). All eight must pass for the submission to claim the *architectural* (not just prompt-based) guardrail badge in criterion #4.

---

## Evidence integrity approach

SIFTics treats evidence integrity as **architectural**, not prompt-based:

1. **Read-only mounts.** `verify_readonly_mounts.sh` runs pre-flight on every case start and fails closed if any evidence mount is writable. The MCP server refuses to start if this check fails.
2. **No `eval`-style MCP functions.** The agent cannot pass arbitrary code to be executed; every parser is a pre-committed, version-pinned function on the MCP surface.
3. **Hash-chained audit.** Every read, every tool invocation, and every IC decision is appended to `forensic_audit.jsonl` with `SHA-256(prev_line_hash || canonical(event))`. `audit_verify.sh` recomputes the chain end-to-end.
4. **Single-use approvals.** An `ICApproval` object can be consumed exactly once — the atomic `O_EXCL` create of `approvals/consumed/<request_id>.json` enforces double-spend prevention.

If you find a path to spoliation that this design misses, please open a security issue — we explicitly test for them in T1–T8 and want to know about anything we missed. Honest failure modes are documented in [`docs/accuracy_report.md §6`](docs/accuracy_report.md).

---

## Credits and framework lineage

- **NIMS Incident Command System** — for the Common Operating Picture, Section Chief / Incident Commander roles, and Authority Gate concept.
- **NIST SP 800-61 Rev 2** — for the Containment, Eradication, Recovery framing in the CET register.
- **FEMA ICS Form 209** — for the affected-systems register column model.
- **SANS LDR553** (Steve Armstrong-Godwin / AG Cyber) — UI structure inspired by the CIMTK toolkit. *Pending explicit permission to use branded names; currently shipped with generic IR-doctrine labels (`labels.yaml: active_label_set: generic`).*
- **AndrewRathbun / VanillaWindowsReference + VanillaWindowsRegistryHives** — Windows known-good baseline corpus used by `mcp_baseline`.
- **wagga40 / Zircolite** — Sigma rule application over EVTX in `phases/run_zircolite.sh`.
- **OpenSourceMalware.com** — STIX threat-intel feed integrated via `mcp_cti`.
- **abuse.ch** (URLhaus, MalwareBazaar, ThreatFox) — multi-source IOC enrichment in `mcp_cti`.
- **MITRE ATT&CK, LOLBAS, Atomic Red Team, SigmaHQ** — knowledge corpus indexed into `mcp_rag` for semantic alignment.
- **Velociraptor team** — the EDR platform that makes the detect-hunt loop possible.

---

## Contact

For questions during judging:

- GitHub issues: [https://github.com/rjonhaas/SIFTics/issues](https://github.com/rjonhaas/SIFTics/issues) (preferred — we monitor 24/7 during the judging window)
- Email: rjonhaas@example.com *(replace with submission contact)*

For everyone else interested in DFIR + AI:

- Hackathon: [findevil.devpost.com](https://findevil.devpost.com)
- Slack: Protocol SIFT workspace
- Hunt_lab (the victim network we used to generate test cases): [https://github.com/rjonhaas/hunt_lab](https://github.com/rjonhaas/hunt_lab)
