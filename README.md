# SIFTics

DFIR triage workflow for the SANS SIFT Workstation. Claude Code orchestrates analysis; shell scripts extract and parse artifacts; skill files guide tool execution and reporting.

---

## Workflow Overview

```
Step 0  — Case setup: create CLAUDE.md at the case root
Step 1  — Extract evidence (KAPE ZIPs, memory images, PCAPs, cloud logs)
Step 2  — Open the case directory in Claude Code and invoke
          /investigation-section-chief. The agent (NIMS ICS Investigation Section
          Chief — your "Intel Section") reads the triage-methodology skill,
          decides which phase scripts apply, and sequences them. You (the human
          analyst) are the Incident Commander; the agent reports to you.
Step 3  — ISC invokes domain skills as findings dictate (memory-analysis,
          network-analysis, yara-hunting, etc.) and writes the
          Common Operating Picture (COP) at every operational period boundary.
          Authority-gated decisions (scope expansion, chain-of-custody issues,
          case closure) are surfaced in the COP for IC review without blocking
          analysis.
Step 4  — ISC drafts the investigation-report at recommended closure;
          IC reviews and approves before delivery.
Step 5  — (optional) Run Phase 16 CVE attribution; regenerate report.
Step 6  — (optional) Generate HTML deliverable:
          python3 scripts/gen_html_package.py /cases/<case_name>
```

There is no `run_all.sh` anymore. The agent **is** the orchestrator. For deterministic
re-execution (benchmark scenarios), invoke each `run_*.sh` script directly in numerical
order from the [Phase Catalog](skills/triage-methodology/SKILL.md#phase-catalog) — the
phase scripts' self-skip guards make this idempotent.

---

## Step 0 — Case CLAUDE.md (Do This First)

Before running any scripts or analysis, create a `CLAUDE.md` at the case root. This file is loaded automatically by Claude Code when you open the case directory and grounds every analysis decision in the facts you know going in.

```bash
cp "${SIFTICS_HOME:-/home/sansforensics/SIFTics}/templates/case_claude.md" /cases/<case_name>/CLAUDE.md
```

Then open it and fill in what you know:

| Section | What to capture |
|---------|----------------|
| **Case Identification** | Case name, type, analyst, case root path |
| **Attack Window** | Earliest compromise and latest known activity (UTC) with confidence level |
| **Machines in Scope** | Hostname, role, evidence path, collection type for each machine |
| **Known IOCs** | Any IPs, domains, hashes, accounts, or file paths known before analysis |
| **Investigator Context** | What the client reported, suspected threat actor, containment already done |
| **Evidence Inventory** | Source, type, path, capture timestamp, SHA256 for each evidence file |

**You do not need to know everything.** Partial information is better than nothing. Leave unknowns blank — Claude will fill gaps through analysis and update the COP accordingly.

The attack window is the most critical field. Even a rough estimate ("sometime in the week of 2025-03-03") anchors temporal analysis and prevents Claude from treating every artifact as equally relevant.

---

## Triage Scripts (`scripts/`)

Each script accepts the case root as a positional argument. Each is independently
runnable, idempotent, and self-skipping (re-running on a fully-analyzed case is a no-op).
Each sources `audit_log.sh` automatically and writes hash-chained entries to
`<case_root>/analysis/forensic_audit.jsonl`.

The agent invokes these via the [`triage-methodology`](skills/triage-methodology/SKILL.md)
skill, which encodes the sequencing logic, break conditions, and skip rules. Manual
invocation is also supported:

```bash
# Run a single phase
bash scripts/run_ntfs.sh /cases/<case_name>

# Run a sequence by hand (deterministic re-execution / benchmark mode)
# Order: Layer 1 foundation (NTFS, Registry, EventLogs, Artifacts, Execution, Memory, PCAP) →
#        Layer 2 domain analysis (Hunting, CredAccess, AntiForensics, Browser, Ransomware,
#        WebServer, Email, Linux) → Layer 3 consolidation (IOC, C2 Beacon) →
#        Layer 4 synthesis (Attack Path, Anomaly Check) → optional self-correction
for s in run_ntfs run_registry run_eventlogs run_artifacts run_execution \
         run_memory run_pcap \
         run_hunting run_credaccess run_antiforensics run_browser run_ransomware \
         run_webserver run_email run_linux \
         run_ioc_extract run_c2_beacon \
         run_attack_path run_anomaly_check; do
    bash "scripts/${s}.sh" /cases/<case_name>
done

# Optional: self-correct on detected anomalies (max 3 iterations)
bash scripts/run_self_correct.sh /cases/<case_name>

# Optional: push findings as Velociraptor hunts to the rest of the fleet
SIFTICS_MCP_MOCK=1 \
bash scripts/run_detect_hunt_loop.sh /cases/<case_name>
```

### Core Windows Triage (Phases 1–13)

Output lands in `<case_root>/analysis/<MACHINE>/<Category>/`.

| Script | Phase | What it does |
|--------|-------|-------------|
| `run_ntfs.sh` | 1 | MFT, Boot, LogFile, USN Journal |
| `run_registry.sh` | 2 | System/user hives, Amcache, ShimCache, ShellBags, RegBack |
| `run_eventlogs.sh` | 3 | All EVTX (EvtxECmd + Maps) |
| `run_artifacts.sh` | 4 | LNK, Jump Lists, Recycle Bin, Windows Timeline, Prefetch |
| `run_execution.sh` | 5 | IIS logs, HTTPERR, PowerShell history, Scheduled Tasks |
| `run_hunting.sh` | 6 | PrivEsc / Lateral Movement hunting over EVTX CSVs |
| `run_credaccess.sh` | 7 | DCSync, LSASS, Kerberoasting, WMI, timestomping |
| `run_antiforensics.sh` | 8 | Log clearing, VSS deletion, Defender tampering |
| `run_ioc_extract.sh` | 9 | IOC extraction (IPs/URLs/hashes/paths) across all CSVs |
| `run_c2_beacon.sh` | 10 | C2 beacon detection via IIS log interval analysis |
| `run_browser.sh` | 11 | Zone.Identifier/MotW, Chrome/Edge/Firefox/IE history |
| `run_ransomware.sh` | 12 | Ransom notes, suspicious extensions, archive staging |
| `run_webserver.sh` | 13 | IIS injection detection, LOLBIN downloads, webshell inventory |

### Extended / Specialist Phases (14–17)

| Script | Phase | What it does |
|--------|-------|-------------|
| `run_email.sh` | 14 | PST/OST/mbox parsing via readpst; message and attachment extraction |
| `run_linux.sh` | 15 | Linux partition analysis (ext4 via losetup); auth logs, bash history, cron, SSH keys |
| `run_cve_attribution.sh` | 16 | CVE attribution — reads completed report + COP, invokes Claude CLI, writes `analysis/cve_attribution.md` |
| `run_attack_path.sh` | 17 | Cross-machine attack path graph from lateral movement events; outputs CSV + Markdown + Mermaid |

### Synthesis & Self-Correction (Phases 18–20)

| Script | Phase | What it does |
|--------|-------|-------------|
| `run_anomaly_check.sh` | 18 | Cross-artifact contradiction scanner — Shimcache-MFT mismatch, EVTX gap during attack window, USN jumps, memory-vs-disk IP cross-ref, etc. Output `analysis/anomalies.csv` feeds the self-correction loop. |
| `run_memory.sh` | 19 | Volatility 3 autonomous triage — psscan/pstree/cmdline/netscan/svcscan/malfind (with dump) + YARA over malfind dumps + memory_anomalies.csv synthesis (orphan PPID, wrong-parent svchost/lsass, RWX VAD without backing) |
| `run_pcap.sh` | 20 | tshark + (optional) Zeek autonomous triage — top talkers, DNS triple (queries/NXDOMAIN/DGA-suspicious), HTTP, TLS SNI, per-dst-IP beacon scoring (denylist + IOC aware), pcap_anomalies.csv synthesis |
| `run_self_correct.sh` | — | Reads HIGH-severity anomalies, picks corrective action per category, re-runs the upstream phase, re-checks anomalies, verifies the count decreased. Hard cap of 3 iterations. Per-iteration log to `analysis/self_correction.jsonl`. |
| `run_detect_hunt_loop.sh` | — | End-to-end SIFTics → Velociraptor detect-hunt loop. Pulls offline collection from primary victim → SIFTics analysis → `findings_to_hunt.py` derives Velociraptor hunt artifacts → MCP broker pushes hunts → results ingested back into the case for cross-host correlation. Mock mode (`SIFTICS_MCP_MOCK=1`) for demo without a real Velociraptor server. |

### Utility Scripts

| Script | What it does |
|--------|-------------|
| `run_mftecmd.sh` | Standalone MFT parser — parses `$MFT`, `$Boot`, `$LogFile`, `$J` for every machine under the case root |
| `daedalus_fingerprint.sh` | Artifact discovery — probes mounted evidence for all known artifact classes; outputs a run-plan manifest |
| `findings_to_hunt.py` | Converts SIFTics analysis output (`ioc_master.csv`, `anomalies.csv`, memory/PCAP anomalies, attack path) into Velociraptor hunt artifact YAML. Used by `run_detect_hunt_loop.sh`. |
| `hypothesis_score.py` | CLI for the Hypothesis Engine — `add`, `signal`, `score`, `report`, `retire`. Mechanically computes confidence from signal weights (no LLM-estimated scores). Append-only JSONL ledger at `analysis/hypotheses.jsonl`. |
| `test_constraints.py` | Bypass test harness — runs T1–T7 against architectural and prompt-based guardrails. Output: `reports/bypass_test_report.md` + `bypass_test_results.json`. The Constraint Implementation evidence for the Accuracy Report. |
| `audit_log.sh` | Sourced by every phase script — provides hash-chained JSONL logging via `audit_log_entry()` and `log_cmd()`. Append-only `analysis/forensic_audit.jsonl`. |
| `audit_verify.sh` | Recomputes the SHA-256 chain over `forensic_audit.jsonl` to detect tampering. Exit 0 = chain intact. |
| `audit_query.sh` | Search the audit log by tool, machine, or keyword. |
| `verify_readonly_mounts.sh` | Pre-flight: parses `/proc/mounts`, halts if any evidence path is mounted `rw`. |
| `sanitize_for_llm.py` | Prompt-injection defense — 22 regex patterns; writes paired sanitized/unsanitized CSVs. Original is never modified. |
| `score_benchmark.py` | Accuracy benchmark scorer — evaluates SIFTics output against ground-truth manifests (DEF CON 2019, SpottedInTheWild). |
| `report_to_html.py` | Converts `reports/investigation_report.md` to a standalone dark-theme HTML report with sidebar TOC |
| `gen_html_package.py` | Produces a customer-ready ZIP: CISO dashboard, full report, analyst evidence hub, sortable CSV tables |
| `parse_apache_log.py` | Parses Apache combined/common access log format |
| `parse_bash_history.py` | Categorises bash history entries with IOC extraction |
| `parse_email.py` | Phase 14 email artifact parser (called by `run_email.sh`) |
| `install_tools.sh` | Pre-flight dependency checker; verifies required EZ Tools are present |

---

## Skills (`skills/`)

Domain skill files that Claude Code reads to guide tool execution. Invoke via the investigation-section-chief skill at the start of every case.

> **Roles (NIMS ICS):** You — the human analyst — are the **Incident Commander (IC)**.
> The agent runs as the **Investigation Section Chief (ISC)**, the role NIMS defines for
> the section that conducts the investigation under the IC's authority. The ISC has
> tactical autonomy inside its section but surfaces authority-gated decisions in the COP
> for the IC's review. See `investigation-section-chief/SKILL.md` for the full
> Authority Gates table.

| Skill | Domain |
|-------|--------|
| `investigation-section-chief` | The agent's NIMS ICS role — investigation lifecycle, COP, finding taxonomy, Authority Gates. Invoke first. |
| `triage-methodology` | Phase sequencing & decision engine — invoked by ISC at Period 1 (replaces `run_all.sh`) |
| `daedalus` | Adaptive artifact discovery and handler generation |
| `windows-artifacts` | EZ Tools, Event Logs, Registry |
| `memory-analysis` | Volatility 3, Memory Baseliner |
| `linux-host` | Auth logs, bash history, cron, SUID |
| `edr-telemetry` | Velociraptor, CrowdStrike, SentinelOne, MDE |
| `network-analysis` | PCAP, Zeek, tshark |
| `malware-analysis` | Static analysis, capa, strings |
| `yara-hunting` | YARA rules, IOC sweeps |
| `cloud-forensics` | AWS GuardDuty, CloudTrail, S3 |
| `macos-triage` | Unified Log, FSEvents, Quarantine DB |
| `plaso-timeline` | Cross-source super-timeline |
| `sleuthkit` | File system triage, MFT recovery, file carving |
| `investigation-report` | Final report generation — drafted by ISC at case closure; IC reviews and approves before delivery |
| `hypothesis-engine` | Working-theory ledger; signal scoring at each operational period (replaces "anchoring on first plausible explanation") |
| `cve-attribution` | Intel ICS Phase 16 — CVE attribution from completed report |

---

## MCP Broker (`mcp_broker/`)

Typed-function MCP gateway between the SIFTics agent and external services.
Built initially to drive the SIFTics → Velociraptor detect-hunt loop; designed
to add more wrapped services over time (REMnux, ELK, Jira, etc.) without
expanding the agent's surface area.

```
mcp_broker/
├── server.py            ← MCP protocol server (stdio); registers 10 typed Velociraptor functions
├── tools/
│   └── velociraptor.py  ← list_clients / pull_offline_collection / upload_artifact /
│                          create_hunt / start_hunt / get_hunt_status /
│                          get_hunt_results / wait_for_hunt / list_artifacts / get_client
├── audit.py             ← per-call JSONL log with sensitive-arg redaction + latency
├── config.py            ← YAML config loader; falls back to mock mode if no config
├── auth.py              ← Velociraptor API client cert/key bundle loader (mTLS)
└── README.md            ← install + configure + run + extending guide
```

**Architectural posture:** the agent calls a fixed catalog of typed functions — no shell
exec, no raw VQL passthrough. All agent input flows through `_safe_str()` rejecting
VQL-reserved characters. Custom artifact uploads must start with `SIFTICS_` or `Custom.`
to prevent overwriting Velociraptor built-ins. Sensitive auth material is held server-side
and never enters the agent's context window. Every MCP call is logged to
`mcp_broker/audit.jsonl` with redacted args, result summary, and latency.

**Mock mode:** set `SIFTICS_MCP_MOCK=1` to run the broker against canned responses without
a real Velociraptor server. Used for development, demos, and CI.

See `mcp_broker/README.md` for install/configure/run details, and
`docs/architecture.md` for the detect-hunt loop architecture diagram.

---

## Try It Out (judges, this section is for you)

This section is the reproducibility and Try-It-Out instructions required by the
hackathon submission rules. It assumes you have a fresh SANS SIFT Workstation
and Claude Code installed.

### 1. Install SIFTics

```bash
git clone https://github.com/rjonhaas/SIFTics.git ~/SIFTics
export SIFTICS_HOME=~/SIFTics

# Symlink skills into Claude Code's skill directory
mkdir -p ~/.claude/skills
for skill in ~/SIFTics/skills/*/; do
    ln -sf "$skill" ~/.claude/skills/$(basename "$skill")
done

# Verify dependencies
bash ~/SIFTics/scripts/install_tools.sh --check-only
```

### 2. Verify the architectural guardrails (no evidence required)

```bash
python3 ~/SIFTics/scripts/test_constraints.py
# Reads: nothing (uses temp dir)
# Writes: ~/SIFTics/reports/bypass_test_report.md + bypass_test_results.json
# Tests T1–T7 architectural / prompt-based boundaries
```

Expected outcome: T2 BLOCKED, T3 DETECTED (4/4), T4 DETECTED, T5 VERIFIED-PRESENT,
T6 DETECTED, T7 FULL-COVERAGE. T1 ALLOWED-OS-level (intentional — see report).

### 3. Run the accuracy benchmark against public CTF evidence

If you want to verify SIFTics' accuracy against documented ground truth, the repo
ships two benchmark manifests for public CTF cases:

| Case | Public source | Ground-truth checks |
|---|---|---|
| DEF CON 2019 DFIR CTF | DFA 2019 (publicly downloadable) | 21 checks across 10 phases |
| CyberDefenders Case 166 (SpottedInTheWild) | cyberdefenders.org | 16 checks across 7 phases |

Download the evidence to `/cases/<case_name>/`, then:

```bash
# Drive the pipeline (skill-driven, agent-orchestrated):
#   Open the case directory in Claude Code and invoke /investigation-section-chief.
#   The agent reads triage-methodology and runs phases 1-17 + 19 + 20 as evidence dictates.

# Or — for deterministic re-execution against the benchmark, drive manually:
for s in run_ntfs run_registry run_eventlogs run_artifacts run_execution \
         run_hunting run_credaccess run_antiforensics run_browser run_ransomware \
         run_webserver run_email run_linux run_ioc_extract run_c2_beacon \
         run_attack_path run_anomaly_check run_memory run_pcap; do
    bash ~/SIFTics/scripts/${s}.sh /cases/defcon2019_dfir
done

# Score against ground truth
python3 ~/SIFTics/scripts/score_benchmark.py \
    --case-dir /cases/defcon2019_dfir \
    --ground-truth ~/SIFTics/benchmark/ground_truth/defcon2019.json
```

Expected outcome: 21/21 (100% recall) on DEF CON 2019, 16/16 (100% recall) on
SpottedInTheWild. Phases 18/19/20 are new and not yet in the benchmark manifests
(scoring infrastructure is the same; ground truth needs to be added).

### 4. Demonstrate the self-correction loop

The killer-demo sequence the hackathon prompt requires (at least one self-correction
in the demo video). After the pipeline has run on a case with anti-forensic
indicators (DEF CON 2019 has VSS deletion + log clearing, ideal):

```bash
# Phase 18 detects contradictions across artifacts
bash ~/SIFTics/scripts/run_anomaly_check.sh /cases/defcon2019_dfir

# Self-correction loop reads anomalies.csv, picks first HIGH, re-runs
# the upstream phase, re-checks anomalies, iterates (max 3)
bash ~/SIFTics/scripts/run_self_correct.sh /cases/defcon2019_dfir

# Read the iteration trace
cat /cases/defcon2019_dfir/analysis/self_correction.jsonl
cat /cases/defcon2019_dfir/analysis/self_correction_report.md
```

Each iteration is recorded with timestamp, target anomaly, corrective action,
HIGH-anomaly count delta, and success/no-change/worse outcome.

### 5. Inspect the audit trail

Every command run by every phase script is hash-chained:

```bash
# Verify the chain has no breaks
bash ~/SIFTics/scripts/audit_verify.sh /cases/defcon2019_dfir/analysis/forensic_audit.jsonl

# Search by tool, machine, or keyword
bash ~/SIFTics/scripts/audit_query.sh \
    --tool MFTECmd /cases/defcon2019_dfir/analysis/forensic_audit.jsonl
```

Any finding in the COP or report can be traced back to the exact command that
produced it — meets the hackathon's Audit Trail Quality criterion.

### 6. Demonstrate the detect → hunt loop (SIFTics + Velociraptor via MCP)

After SIFTics has produced findings on a primary victim, push those findings
across the fleet as Velociraptor hunts and ingest the cross-host results.

**Setup the broker (one-time):**

```bash
cd ~/SIFTics
python3 -m venv mcp_broker/.venv
mcp_broker/.venv/bin/pip install -r mcp_broker/requirements.txt
cp mcp_broker/config/config.example.yaml mcp_broker/config/config.yaml
# edit config.yaml to point at your Velociraptor server + api_client.yaml
```

**Run the loop (real Velociraptor):**

```bash
PRIMARY_CLIENT_ID=C.1234abcd \
HUNT_TIMEOUT_S=300 \
bash ~/SIFTics/scripts/run_detect_hunt_loop.sh /cases/<case_name>
```

**Run the loop (mock mode — no Velociraptor server needed):**

```bash
SIFTICS_MCP_MOCK=1 \
bash ~/SIFTics/scripts/run_detect_hunt_loop.sh /cases/<case_name>
```

What happens (7 steps, all audited):

1. Discover the primary victim's offline-collection zip in `<case>/incoming/`
   (or pull from Velociraptor if `PRIMARY_CLIENT_ID` set)
2. SIFTics analyzes (deterministic phase loop or agent-driven via ISC)
3. `findings_to_hunt.py` converts `ioc_master.csv` + `anomalies.csv` +
   memory/PCAP anomalies into Velociraptor artifact YAML files
4. MCP broker uploads each artifact, creates a hunt, starts it
5. Polls until each hunt completes (bounded by `HUNT_TIMEOUT_S`)
6. Ingests hunt results back into `<case>/analysis/cross_host_findings.csv`
7. Surfaces any new affected hosts as scope-expansion candidates per the ISC
   Authority Gates rules

The MCP broker exposes 10 typed functions only — no shell exec, no raw VQL.
See `mcp_broker/README.md` for the full architectural posture.

### 7. Read the architecture diagram

See [`docs/architecture.md`](docs/architecture.md) for the full Mermaid diagram
showing IC/ISC roles, phase scripts, evidence sources, output pipeline, and the
explicit architectural-vs-prompt-based guardrail classification.

---

## Phase 16 — CVE Attribution

After the investigation report is complete, run Phase 16 to attribute exploitation patterns to known CVEs:

```bash
bash scripts/run_cve_attribution.sh /cases/<case_name>
```

The script reads `reports/investigation_report.md` and `analysis/cop.md`, calls the `claude` CLI with a focused CVE attribution prompt, and writes `analysis/cve_attribution.md`. Then re-run the investigation-report skill to integrate the output as Section 3B of the report.

**Requirements:** `claude` CLI in PATH (or set `CLAUDE_BIN=/path/to/claude`). Override the model with `CVE_MODEL=<model-id>`.

---

## HTML Deliverables

### Analyst report

Converts the markdown investigation report to a standalone HTML file with a dark theme and sidebar TOC:

```bash
python3 scripts/report_to_html.py /cases/<case_name>
# Output: reports/investigation_report.html
```

### Customer package

Produces a self-contained ZIP suitable for client delivery. No server required — customer unzips and opens `index.html`:

```bash
python3 scripts/gen_html_package.py /cases/<case_name>
# Output: reports/<case_name>_package.zip
```

The package contains:
- `index.html` — CISO executive dashboard (severity, findings, timeline, actions)
- `report.html` — Full rendered investigation report
- `analyst.html` — Analyst evidence hub (phase-ordered investigation journey)
- `csv/*.html` — Individual CSV artifact tables (sortable, searchable, paginated)

---

## Templates (`templates/`)

| File | Purpose |
|------|---------|
| `case_claude.md` | Case CLAUDE.md template — copy to case root and fill in at Step 0 |
