# SIFTics Accuracy Report

Devpost submission item #9 — *Accuracy Report*.

> **Pinned model:** all benchmark results in this report are against
> `claude-sonnet-4-6` with Anthropic prompt caching enabled. SIFTics will run on
> any Claude 4.x model and on Ollama-served local models, but the headline
> figures are pinned to Sonnet 4.6 for reproducibility.
>
> **Honesty over perfection** — per the hackathon rules: false positives, missed
> artifacts, and hallucinated claims are documented here. Failure modes are
> signal, not weakness.

---

## 0. TL;DR

| Metric | Value | Source |
|---|---|---|
| Total cases benchmarked | *TBD* | `examples/run_*` |
| Public ground-truth corpora used | DEF CON 2019 DFIR CTF · CyberDefenders #166 | [`datasets.md`](datasets.md) |
| Findings precision (vs ground truth) | *TBD* | `tools/score_benchmark.py` |
| Findings recall (vs ground truth) | *TBD* | `tools/score_benchmark.py` |
| Hallucinated claims (caught by Phase 18) | *TBD* | `forensic_audit.jsonl` |
| Hallucinated claims (missed; surfaced post-hoc) | *TBD* | manual review |
| T1–T8 bypass test pass rate | **14 / 14** | `tests/test_constraints.py` |
| Average wall-clock per case | *TBD* | `examples/run_*` |
| Average cost per case (Sonnet 4.6) | *TBD* | sum of `llm_call` cost_usd events |
| p95 cost per case | *TBD* | same |

*(Numbers marked TBD will be filled in during week-3 benchmarking; placeholders
exist so the report structure is locked-in early per Rob's compliance guidance.)*

---

## 1. Methodology

### 1.1 Datasets

Two public, attribution-friendly datasets are used as ground truth:

1. **DEF CON 2019 DFIR CTF** — Windows disk image + memory capture with ~21
   documented checks (file artifacts, registry persistence, memory-resident
   processes, network indicators).
2. **CyberDefenders Case #166** — Windows triage scenario with ~16 documented
   checks.

Each case is run end-to-end through SIFTics. The resulting findings are scored
against the published ground-truth answers by `tools/score_benchmark.py`.

### 1.2 Scoring rubric

For each ground-truth check, the agent's output is scored as one of:

| Score | Meaning |
|---|---|
| **HIT** | Finding matches the ground truth in entity and direction |
| **PARTIAL** | Correct entity surfaced, but inference / severity / timeline differs |
| **MISS** | Ground-truth check was not surfaced by the agent |
| **EXTRA** | Agent surfaced a claim with no corresponding ground-truth check (evaluated separately as either novel finding or hallucination) |

Precision = HIT / (HIT + EXTRA-classified-as-hallucination).
Recall    = HIT / (HIT + MISS + PARTIAL).

### 1.3 Test environment

- SIFT Workstation 2026.04.22 OVA, 8 GB RAM, 4 vCPU
- WSL-Ubuntu-22.04 + SIFT server-mode (parity test target — Rob explicitly
  approved WSL in Slack 2026-05-13)
- Python 3.10
- `claude-sonnet-4-6` via Anthropic API with prompt caching enabled

---

## 2. Per-case results

### 2.1 DEF CON 2019 DFIR CTF

| Check (21 total) | Score | Notes |
|---|---|---|
| Q1 — username of primary suspect | *TBD* | |
| Q2 — first observed malicious file | *TBD* | |
| … | | |

**Summary**: HIT *TBD* · PARTIAL *TBD* · MISS *TBD* · EXTRA *TBD*

### 2.2 CyberDefenders Case #166

| Check (16 total) | Score | Notes |
|---|---|---|
| Q1 — initial vector | *TBD* | |
| … | | |

**Summary**: HIT *TBD* · PARTIAL *TBD* · MISS *TBD* · EXTRA *TBD*

### 2.3 Hunt_lab-generated case (controlled adversary)

Caldera-driven attack scenario against `win11-victim` (mimikatz variant renamed
to `lsass_helper.exe`, dropped in `C:\Users\Public\`, Sandcat beacon to
`192.168.56.30:8888`). Used to exercise the HOT layer + hunt-package
generation + IC Authority Gate flow in the demo video.

Ground truth is **known by construction** (we drove the attack) so this is the
strongest validation surface.

| Stage | Expected | Observed | Score |
|---|---|---|---|
| Initial persistence detection (Run key or scheduled task) | Yes (scheduled task `WindowsSecurityUpdate`) | *TBD* | |
| Malicious binary identification | imphash match to mimikatz family | *TBD* | |
| Lateral-movement assessment | None (controlled, single host) | *TBD* | |
| Velociraptor hunt package proposed | Yes | *TBD* | |
| IC Authority Gate triggered | Yes | *TBD* | |
| Phase 18 self-correction fired | At least once | *TBD* | |

---

## 3. Hallucination accounting

Hallucinations are the IR-specific failure mode the hackathon rules call out:
*"hallucinations caught and flagged."*

### 3.1 Caught (and surfaced) by Phase 18 anomaly check

Examples observed during benchmarking will be listed here with the
contradicting evidence pair (e.g., "Shimcache says binary executed at T1, but
MFT records its creation at T2 > T1 — flagged").

### 3.2 Caught (and not surfaced) — manual review only

Honest accounting: claims the agent made that we identified post-hoc as
unsupported by tool output. Example archetypes:

- Inferring an actor's intent without a tool execution producing that evidence
- Citing a Sigma rule by ID that does not exist in the bundled ruleset
- Conflating two distinct files with similar names

### 3.3 Avoided entirely by architectural design

- **No raw shell** — the agent cannot fabricate a `bash` invocation it didn't
  actually run, because there is no `execute_shell()` MCP function. Every claim
  traces to a typed function with a deterministic output.
- **No `eval()` or arbitrary file read** — the agent cannot "claim it ran X"
  without there being an audit event proving it ran X.
- **Hash-chained provenance** — fabricated findings cannot be inserted into the
  audit log without breaking the chain at `audit_verify.sh`.
- **RAG grounding** — every semantic enrichment claim (MITRE technique alignment,
  Sigma rule match explanation, LOLBAS context) is backed by a retrieved record
  from `mcp_rag`. The agent is instructed to cite the returned `record_id` and
  similarity score; uncited claims can therefore be identified by diffing the
  agent's narrative against `forensic_audit.jsonl` `rag_lookup` events. Claims
  that cannot be grounded in a retrieved record are the surface area Rob Lee's
  article describes — we expect Phase 18 to catch most of them via
  cross-artifact contradiction checks.
- **Deterministic vs probabilistic source typing** — baseline lookups
  (`mcp_baseline`), IOC lookups (`mcp_cti`), and Sigma rule hits (`mcp_rag`
  Sigma path) return exact-match results, not probability-weighted completions.
  The `source_type` field in each `forensic_audit.jsonl` event distinguishes
  `deterministic` (hash/IP exact-match) from `ai_enrichment` (LLM reasoning
  over retrieved context) so downstream verification can be targeted.

---

## 4. Evidence integrity assessment

The hackathon explicitly asks: *"how does your architecture prevent original
data from being modified? If you're using prompt-based restrictions rather than
architectural enforcement, document what happens when the model ignores the
restriction."*

SIFTics's answer: **the restriction is architectural and cannot be ignored.**

| Risk | Architectural defence |
|---|---|
| Agent writes to original evidence | `verify_readonly_mounts.sh` runs at case start and fails closed; bind-mount with `ro` flag; MCP refuses to start if check fails |
| Agent overwrites a parser tool | No `install`, `pip`, or filesystem-write MCP function exists. Agent cannot mutate `phases/` or `mcp_*/` |
| Agent fabricates audit events | Audit log is hash-chained over canonical event bytes; fabrication breaks the chain at verify time |
| Agent runs an unapproved fleet action | Action MCP functions require typed `ICApproval`; missing approval → `TypeError` before body runs |
| Agent exhausts API credits | `cost_tracker.check_budget_or_raise()` runs at the top of every chat call; raises `BudgetExceeded` |

Tested for bypass: T1 through T8 (`tests/test_constraints.py`). **14 / 14 pass**
in v1; T8 has 7 sub-tests covering the IC approval enforcement specifically.

---

## 5. Cost characterisation

### 5.1 Per-case cost (Sonnet 4.6, prompt caching on)

| Percentile | Cost (USD) | Wall-clock (min) | LLM calls | Cache hit % |
|---|---|---|---|---|
| p50 (median) | *TBD* | *TBD* | *TBD* | *TBD* |
| p95 | *TBD* | *TBD* | *TBD* | *TBD* |
| p99 | *TBD* | *TBD* | *TBD* | *TBD* |

### 5.2 Cost breakdown by task class

| Task class | Avg input tokens | Avg cached | Avg output | Avg cost per call |
|---|---|---|---|---|
| `investigator` (Sonnet 4.6) | *TBD* | *TBD* | *TBD* | *TBD* |
| `classifier` (Haiku 4.5) | *TBD* | *TBD* | *TBD* | *TBD* |
| `synthesizer` (Sonnet 4.6) | *TBD* | *TBD* | *TBD* | *TBD* |
| `deep_review` (Opus 4.7) | *TBD* | *TBD* | *TBD* | *TBD* |

### 5.3 Cost circuit breaker behaviour

Default budget per case: **$10 USD**. When the running case cost reaches this,
`cost_tracker.BudgetExceeded` is raised at the top of the next LLM call and
no further requests are made. The agent is *unable* to continue past the
budget regardless of its reasoning — this is architectural (criterion #4),
not prompt-based.

The audit log includes an `llm_call` event for every LLM invocation with
`model`, `task_class`, `purpose`, `input_tokens`, `cached_read_tokens`,
`cached_creation_tokens`, `output_tokens`, `cost_usd`, and `cache_hit_rate`.
This gives **per-finding cost traceability** — a feature Valhuntir does not
claim.

---

## 6. Known failure modes and limitations

Honest list — these are real and accepted in v1:

1. **HOT layer narrow coverage.** The HOT extractors only cover Windows
   execution / persistence / credential access. Web-server, email, and Linux
   phases still rely on Plaso-class tools running on the COLD path. For a case
   where the only evidence is a Linux disk image, expect higher wall-clock.
2. **Ollama tool-use quality.** Small local models (under 30B parameters) often
   fail multi-step tool chains. `qwen2.5-coder:32b` is the smallest model we
   benchmark against; sub-30B is not recommended for IR work.
3. **No GUI debugger for the hypothesis engine.** Confidence scores are
   computed mechanically (signal weights) and visible in `forensic_audit.jsonl`,
   but there is no "inspect this hypothesis" UI in v1.
4. **`mcp_broker` (Velociraptor) hunt execution is stubbed in v1.** The hunt
   package is generated, signed, and recorded in the audit chain end-to-end,
   but the actual fleet execution requires a Velociraptor server. The stub
   returns an `_v1_note` marker in its result so judges know what is real and
   what is staged.
5. **No multi-user IC quorum.** Only one IC per case in v1. High-stakes
   incidents that require dual approval are out of scope until v2.
6. **No automatic key rotation for the IC HMAC key.** A long-running case
   keeps the same key until manually rotated.
7. **No per-artifact AI/deterministic source label in the UI (v2 roadmap).**
   The `forensic_audit.jsonl` `source_type` field distinguishes AI-enriched
   from deterministic findings at the event level, but the SIFTics web dashboard
   does not yet surface a `[AI]` vs `[TOOL]` badge on individual findings. An
   analyst reviewing the ASR register cannot immediately see which enrichments
   came from LLM reasoning vs. an exact-match tool result. Planned for v2:
   per-finding provenance chips in the dashboard UI, mirroring the approach
   Cyber Triage 3.18 uses for its AI Enrichment field. Until then, analysts
   should treat all enrichment text as unverified until cross-checked against
   the `forensic_audit.jsonl` source events.

---

## 7. Supply-chain integrity controls

A forensic agent whose findings rest on a hash-chained audit is only as
trustworthy as the toolchain that wrote the chain. Two attack classes
matter here: (a) a compromised dependency injected via the package index
(`event-stream`, `chalk`/`debug`, `ua-parser-js`, `xz-utils`, recent
PyPI typosquats), and (b) a published-good package whose installed bytes
were mutated on disk after install. SIFTics applies controls at three
layers; the first two are live in this submission, the third is staged.

### 7.1 Install-time controls (live in `setup.sh`)

| Control | Mechanism | Status |
|---|---|---|
| OS hardening before any forensic code runs | `unattended-upgrade --minimal-upgrade-steps` against the Ubuntu security archive at step 1 | live; skip with `--no-security-updates` |
| Python CVE scan against PyPA DB | `pip-audit` inline after step 3 venv populate | live; skip with `--no-audit` |
| Hash-pinned reproducible installs | `pip install --require-hashes` from a `requirements-pinned.txt` produced by `pip-compile --generate-hashes` | **staged** — not in this submission |
| npm `--ignore-scripts` for Claude Code CLI | already declarative when the user opts into `--install-claude` | partial — Claude Code install path uses `npm install -g`, planned migration to `npm ci --ignore-scripts` against a vendored `package-lock.json` |

### 7.2 Case-init SBOM snapshot (live in `siftics/sbom.py` + `siftics/case_state.py:init_case`)

At case creation, before any case state is written:

1. `compute_sbom()` walks every package in the active venv, hashing each
   file in the package's RECORD (post-install bytes, not the index metadata).
   Output includes `python_version`, `platform`, and the SIFTics
   `git_head` commit.
2. `hash_sbom(sbom)` produces a SHA-256 of the canonical-JSON SBOM.
3. The hash is appended to `forensic_audit.jsonl` as event sequence 1,
   with type `sbom_snapshot`.
4. The full SBOM is persisted to `<case>/sbom.json` so re-verification
   is offline-possible.

Every later audit row's `prev_line_hash` chains back through this event.
Tampering with any package after case-init (whether by a compromised
PyPI mirror, an unsigned auto-update, or a malicious post-install hook)
changes `compute_sbom()`'s output. Re-running the verification on the
saved snapshot detects drift; the analyst can decide whether to trust
findings produced under the divergent toolchain or restart.

### 7.3 Authority Gate refusal on drift (staged)

The strongest possible enforcement layer: `mcp_ic_approval`'s
`verify_approval()` re-derives `hash_sbom(compute_sbom())` and compares
to the snapshot chained in audit row 1. Mismatch → approval refused →
the agent literally cannot fire `execute_hunt_package`,
`containment_action`, `publish_intel`, or `escalate_to_cold` against a
drifted toolchain. This is **architectural, not prompt-based** — the
verifier function refuses regardless of what the LLM asks for.

Staged for v1.1. The current submission carries §7.1 and §7.2; the
drift-refusal layer is sketched in
[`siftics/ic_approval.py`](../siftics/ic_approval.py) but not yet
wired into the verification path.

### 7.4 Honest limits

- `pip-audit` only catches advisories already in the PyPA DB. Zero-day
  supply-chain attacks (the package was malicious on first publish, no
  CVE filed yet) bypass it.
- The SBOM hashes the bytes installed in the venv. A malicious wheel
  whose bytes were never on disk (memory-only payload) wouldn't show up
  in the hash, but would be visible in `pip-audit` if the advisory is
  filed, and visible in the audit chain via any IO the payload performs.
- `unattended-upgrade` is best-effort. If the Ubuntu archive itself is
  compromised between SIFTics's install and a later case-init, the SBOM
  hash detects it (different installed bytes) — but the prior install
  ran with the compromised packages.

These limits are documented so a judge / operator knows exactly what
the controls do and do not promise.

---

## 8. Reproducing these numbers

```bash
git clone https://github.com/rjonhaas/SIFTics.git
cd SIFTics
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Pull the benchmark datasets (one-time, ~5-10 GB)
./scripts/download_benchmarks.sh

# Run the full accuracy benchmark — writes results to examples/benchmark_<date>/
SIFTICS_ANTHROPIC_KEY=... sift-benchmark run --pin claude-sonnet-4-6

# Re-run the bypass tests
python -m pytest tests/test_constraints.py -v
```

All cost / token / accuracy numbers in this report are reproducible from the
output of `sift-benchmark run` against the pinned model. If your run produces
materially different numbers, open an issue at
[`github.com/rjonhaas/SIFTics/issues`](https://github.com/rjonhaas/SIFTics/issues).

---

## 9. Cross-references

- T1–T8 bypass harness source: [`tests/test_constraints.py`](../tests/test_constraints.py)
- Architecture overview: [`docs/architecture.md`](architecture.md)
- Constraint implementation matrix: [`docs/constraint_implementation.md`](constraint_implementation.md)
- Dataset documentation: [`docs/datasets.md`](datasets.md)
- Demo video script: [`docs/demo_video.md`](demo_video.md)
- SBOM computation source: [`siftics/sbom.py`](../siftics/sbom.py)
