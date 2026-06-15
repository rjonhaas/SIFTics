# SIFTics Accuracy Report

Devpost submission item #9 - *Accuracy Report*.

> **Pinned model:** all benchmark results in this report are against
> `claude-sonnet-4-6` with Anthropic prompt caching enabled. SIFTics will run on
> any Claude 4.x model and on Ollama-served local models, but the headline
> figures are pinned to Sonnet 4.6 for reproducibility.
>
> **Honesty over perfection** - per the hackathon rules: false positives, missed
> artifacts, and hallucinated claims are documented here. Failure modes are
> signal, not weakness.

---

## 0. TL;DR

| Metric | Value | Source |
|---|---|---|
| Total cases benchmarked | **4 public + 1 controlled OT run** | CFReDS, Nitroba, webserver, DFIR Madness Szechuan, hunt_lab OT - see §2 |
| Public ground-truth corpora used | NIST CFReDS Data Leakage Case · Digital Corpora Nitroba Harassment Scenario · Ali Hadi Web Server Compromise Case | [`datasets.md`](datasets.md) |
| Latest Szechuan exact-hit recall | **15 / 29 = 51.7%** | `examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/score_card.md` |
| Latest Szechuan hit-or-partial coverage | **22 / 29 = 75.9%** | same |
| Latest Szechuan uncorrected FP / hallucinations | **0** | same |
| Latest Szechuan corrected FP | **1** | F-017 superseded F-011 |
| Constraint regression test pass rate | **17 / 17** | `tests/test_constraints.py` on SIFT VM, 2026-06-14 |
| Packaged Szechuan wall-clock | **84 min** | `score_card.md` operator timing |
| Packaged Szechuan cost (Sonnet 4.6) | **$6.944945** | `forensic_audit.jsonl` `llm_call` event |
| Cost percentile status | Not enough completed packaged runs for p95/p99 | one fully packaged current run |

The newest Szechuan run is intentionally reported in two layers: raw agent output
contained one false positive (F-011 OneDrive exfiltration), and the agent
corrected it with F-017 before the run ended. The final Common Operating Picture
was operator-reviewed so ASR-2 no longer repeats the corrected claim. This is
the "honesty over perfection" behavior the judging rubric explicitly rewards.

---

## 1. Methodology

### 1.1 Datasets

Three public, attribution-friendly datasets are used as ground truth:

1. **NIST CFReDS Data Leakage Case** - Windows disk image with 43 documented
   Initial Triage Questions (ITQ); NIST-curated ground truth.
2. **Digital Corpora Nitroba University Harassment Scenario** - multi-host
   network evidence (pcaps, logs) with documented attribution ground truth,
   including the perpetrator's Gmail address recovered from HTTP cookies.
3. **Ali Hadi Web Server Compromise Case** - Linux web server disk image with
   a documented multi-stage attack chain (exploit → webshell → persistence).

Each case is run end-to-end through SIFTics. The resulting findings are scored
against the published ground-truth answers by `tools/score_benchmark.py`.

### 1.2a Domain knowledge skills

Domain knowledge skill files now guide the agent during analysis (up from 3 at
initial submission): `windows-artifacts`, `linux-server-artifacts`,
`malware-triage`, `timeline-reconstruction`, `anti-forensics-detection`,
`reporting-conventions` (added to ISC skill set), plus the original
`investigation-section-chief`, `triage-methodology`, and `hypothesis-engine`.
These skills constrain how the agent reasons over evidence and formats findings,
reducing hallucination surface area on unfamiliar artifact types.

Two recent additions specifically target the FP and FN classes surfaced by the
first grading-run datapoint (see [`datasets.md` §6.1](datasets.md)):

- **`anti-forensics-detection.md` timestomping scope expansion** (commit
  `adc94a1`) - the Timestomping section now names three scopes the agent must
  check (implant binaries, user-data files in attacker-accessed directories,
  log files), and a closer rule that "no timestomping observed" without scope
  coverage reads as incomplete. Closes the Beth_Secret.txt timestomp
  false-positive class.
- **`case-completeness-review.md`** - pre-close completeness critic skill. The
  ISC persona's operating loop now has a step 9: call `case_completeness_check()`
  before any final briefing, motivation set, or ASR row marked as safe
  transition; address every HIGH gap, document every MEDIUM gap. Backed by the
  `siftics/completeness_rules.py` rule engine (see §3.4 below).

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
- WSL-Ubuntu-22.04 + SIFT server-mode (parity test target - Rob explicitly
  approved WSL in Slack 2026-05-13)
- Python 3.10
- `claude-sonnet-4-6` via Anthropic API with prompt caching enabled

---

## 2. Per-case results

### 2.1 NIST CFReDS Data Leakage Case

All 43 Initial Triage Questions answered. 26 distinct findings recorded in
`findings.jsonl` with full evidence chains. Verdict: **prosecution-ready**.

| Category | Result |
|---|---|
| ITQ completion | **43 / 43** |
| Distinct findings | 26 |
| MITRE ATT&CK TTPs correctly identified | 5 / 6 |
| Verdict produced | Prosecution-ready |

The one missed TTP was a secondary persistence mechanism; it has since been
addressed in the `windows-artifacts` and `anti-forensics-detection` skill
files.

### 2.2 Digital Corpora Nitroba University Harassment Scenario

Current rerun date: **2026-06-14** on the SIFT Workstation VM.

Case directories:

- Initial buggy run: `~/Desktop/cases/nitroba_2026-06-14`
- Fixed rerun: `~/Desktop/cases/nitroba_fixed_2026-06-14_214620`

Evidence handling: the real artifact
`/mnt/hgfs/long_storage/dfir_datasets/nitroba.pcap` was copied into
`~/Desktop/cases/nitroba_fixed_2026-06-14_214620/evidence/nitroba.pcap`.
The evidence file was **56,180,821 bytes** with **0 symlinks**. The VM did not
receive answer-key JSON/JSONL files.

Exhibit verification recorded by the agent:

- SHA-256:
  `2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb`
- SHA-1: `65656392412add15f93f8585197a8998aaeb50a1`
- MD5: `9981827f11968773ff815e39f5458ec8`
- Capture window: 2008-07-22 01:51:07 UTC to 06:13:47 UTC
- Packet count: 94,410

The initial run exposed a product bug: `sift-case-init --no-key` without an
explicit `--itq-template` failed to seed `grid.jsonl`. The agent still found and
persisted several correct Nitroba facts, but ITQ completion was impossible in
that case directory. The fix in `siftics/case_state.py` now seeds the bundled
ITQ template by default; the fixed rerun created 43 grid rows and recorded the
`itq_seeded` audit event.

Fixed-run durable outputs at stop time:

| Output | Count |
|---|---:|
| `findings.jsonl` | 6 |
| `suit.jsonl` / ASR rows | 4 |
| `grid.jsonl` total ITQs | 43 |
| Completed ITQs | 6 |
| Briefings | 1 |

Accuracy checks from the fixed rerun:

| Ground-truth / benchmark check | Persisted SIFTics output | Score |
|---|---|---|
| Real PCAP used, not answer JSON/JSONL | `F-001` hashes and capture metadata from `capinfos`, `sha256sum`, `sha1sum` | Hit |
| Victim email identified | `F-004` and `F-005`: `lilytuckrige@yahoo.com` | Hit |
| Harassment delivery mechanism | `F-004`: POST to `www.sendanonymousemail.net/send.php`, server confirmed message sent | Hit |
| Harassment body recovered | `F-004`: "Your class stinks" message body recovered from TCP stream 1631 | Hit |
| Second threatening message recovered | `F-005`: POST to `www.willselfdestruct.com/secure/submit`, subject "you can't find us" | Hit |
| Perpetrator identity token | `F-006`: `jcoachj@gmail.com` authenticated from `192.168.15.4` at 06:00:56 UTC | Hit |
| Pre-message intent signal | `F-006`: Google search for `sending anonymous mail` from `192.168.15.4` at 05:58:01 UTC | Hit |
| Source host | `ASR-3`: `192.168.15.4` marked as primary harassment source | Hit |
| Adjacent-host/null-hypothesis handling | `ASR-4`: `192.168.1.64` documented as adjacent/co-located, not confirmed as harassment source | Hit after operator method correction |
| Full ITQ completion | 6 / 43 answered before stop | Miss for full completion |

Important caveat: the clean fixed run initially anchored on noisy identity
tokens from `192.168.1.64`. A method-only operator message redirected it to
enumerate all HTTP POST bodies across the full PCAP. After that correction, it
persisted the core harassment and attribution facts. The report therefore
scores the final durable case output as accurate, but does **not** claim this
clean rerun was fully unaided.

Scoring split:

| Metric | Result |
|---|---|
| Core artifact-recovery recall after method correction | **8 / 8** |
| Core COP-persisted recall after method correction | **8 / 8** |
| ITQ completion in fixed rerun | **6 / 43** |
| Hallucinated COP findings in reviewed core harassment findings | **0** |
| Product failure observed | Initial case init did not seed ITQs; clean fixed run over-focused on adjacent-host identity tokens until redirected |

Corrective action from this run:

- `siftics.case_state.init_case()` now seeds the bundled
  `siftics/templates/itq_questions.yaml` when no explicit template is supplied.
- A regression test verifies default ITQ seeding and passed on the SIFT VM.
- The UI operating contract now tells the agent to establish the COP first and
  persist artifact-backed facts immediately.

### 2.3 Ali Hadi Web Server Compromise Case

Full attack chain recovered. One gap in persistence detection was identified
post-run and has been corrected in the `linux-server-artifacts` skill.

| Stage | Result |
|---|---|
| Initial exploit vector | Found |
| Webshell deployment | Found |
| Post-exploitation activity | Found |
| Persistence mechanism | Missed in initial run; now covered by updated skill |

**Summary**: Attack chain found end-to-end. Persistence gap exposed a real
blind spot in Linux server artifact coverage - documented here per the
"honesty over perfection" principle, and corrected in `linux-server-artifacts.md`.

### 2.4 Hunt_lab-generated case (controlled adversary)

Caldera-driven attack scenario against `win11-victim` (mimikatz variant renamed
to `lsass_helper.exe`, dropped in `C:\Users\Public\`, Sandcat beacon to
`192.168.56.30:8888`). Used to exercise the HOT layer + hunt-package
generation + Incident Commander (IC) Authority Gate flow in the demo video.

Ground truth is **known by construction** because the attack was driven by the
project team. For the current Stage One package this case is treated as a
functional demo surface, not as a headline scored accuracy run; the packaged
accuracy evidence is the Szechuan run in §2.6.

| Stage | Expected | Observed | Score |
|---|---|---|---|
| Initial persistence detection (Run key or scheduled task) | Yes (scheduled task `WindowsSecurityUpdate`) | Demo-path validation only; not packaged as scored run | Not scored |
| Malicious binary identification | imphash match to mimikatz family | Demo-path validation only; not packaged as scored run | Not scored |
| Lateral-movement assessment | None (controlled, single host) | Demo-path validation only; not packaged as scored run | Not scored |
| Velociraptor hunt package proposed | Yes | Demo-path validation only; not packaged as scored run | Not scored |
| IC Authority Gate triggered | Yes | Demo-path validation only; not packaged as scored run | Not scored |
| Phase 18 self-correction fired | At least once | Demo-path validation only; not packaged as scored run | Not scored |

### 2.5 Hunt_lab OT-SSH-Brute-WaterPlant-2026

Run date: **2026-06-14** on the SIFT Workstation VM.

Case directory: `~/Desktop/cases/ot_brute_2026-06-14`.

Evidence handling: real artifacts were copied into
`~/Desktop/cases/ot_brute_2026-06-14/evidence` from the host USB-backed dataset.
The case evidence directory was **506M** and contained **0 symlinks**. The VM did
not receive answer-key JSON/JSONL files.

Post-run scoring used the host-side authored answer key only after the SIFTics
run. The agent and VM were evaluated against real artifacts:
`ot_hmi/auth.log`, `ot_hmi/water_treatment.conf`,
`ot_hmi/water_treatment.conf.pre_tamper`, Windows Prefetch, EVTX, `$MFT`, and
the copied Windows-side `water_treatment_dump.conf`.

| Ground-truth check | Real-artifact verification | Agent transcript | Persisted COP finding | Score |
|---|---|---|---|---|
| Windows pivot host | Prefetch parsed from `SSHD.EXE-D972B7DB.pf`: SSHD ran at 2026-06-13 18:28:09, 18:37:23, 18:43:33 UTC | Identified `192.168.56.20` / `win11_victim` as pivot | No `findings.jsonl` written | Partial |
| OT brute force target/account | `auth.log` has 8 `Failed password for operator from 192.168.56.20` events | Correctly described brute force against `operator` | No `findings.jsonl` written | Partial |
| Successful OT authentication | `auth.log` has 3 `Accepted password for operator from 192.168.56.20` events | Correctly described successful compromise | No `findings.jsonl` written | Partial |
| Config dump | `win11_victim/water_treatment_dump.conf` present; sha256 `92aaac62fdfa4d52f3e8273a564a9cff890da9bb322b26901cf8efdec7b61f5f` | Recognized config-dump artifact family | No `findings.jsonl` written | Partial |
| Setpoint tamper | `free_chlorine_target_ppm` changed `1.20` -> `0.40`; pre hash `97a7809a5ae84dd6ca0c34cd30399ccbde16eff9e4b93811643f981de940cf79`, post hash `d497c40ae0cac48916ebe488d57ce08b9731cd8e28e4a310da67a8533662ecb9` | Correctly surfaced tamper and hashes | No `findings.jsonl` written | Partial |

Scoring split:

| Metric | Result |
|---|---|
| Artifact-recognition recall | **5 / 5 partial-or-better** |
| COP-persisted recall | **0 / 5** |
| COP-persisted precision | Not scored; no findings persisted |
| Authority Gate surfaced for OT safety containment | **0 / 1** before fix |
| Hallucinated COP findings | **0** |
| Product failure observed | Agent continued artifact exploration and chat narration instead of calling `finding_record()` / `itq_answer()`; no IC-visible gate/hard-stop was produced for water-treatment setpoint tamper |

Corrective action from this run:

- The UI agent prompt now injects a SIFTics operating contract on both
  `/api/agent/start` and `/api/agent/message`.
- The contract names the exact MCP tools the agent must use:
  `mcp__siftics_case__case_get_header`,
  `mcp__siftics_case__itq_unanswered`, `mcp__siftics_case__asr_open`,
  `mcp__siftics_case__finding_record`, `mcp__siftics_case__itq_answer`, and
  `mcp__siftics_case__briefing_post`.
- The contract explicitly says case JSON/JSONL files are state/audit output,
  not forensic evidence, and that artifact-backed claims must be persisted
  immediately rather than narrated only in chat.
- OT/ICS process tamper now explicitly requires the Safety Officer +
  Authority Gate path. For water-treatment HMI isolation this is expected to
  hard-stop on personnel safety, but the hard-stop is now recorded as an
  IC-visible blocked gate rather than disappearing.

### 2.6 DFIR Madness - Stolen Szechuan Sauce

Run date: **2026-06-14 to 2026-06-15** on the SIFT Workstation VM.

Case directory: `/cases/szechuan_sauce_2026-06-14`.

Packaged run artifacts:
`examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/`.

Evidence handling: the VM case contained the five real evidence artifacts in
`evidence/`:

- `DC01-E01.zip`
- `DC01-memory.zip`
- `DESKTOP-E01.zip`
- `DESKTOP-SDN1RPT-memory.zip`
- `case001-pcap.zip`

The answer key stayed in a host-only scoring directory and was used only after
the run for scoring. It was not copied into the SIFT VM.

Durable outputs:

| Output | Count |
|---|---:|
| `findings.jsonl` | 18 |
| Current ASR rows | 2 |
| ASR writes | 3 |
| `grid.jsonl` inquiry checks | 43 |
| Resolved inquiry checks | 7 |
| Briefings | 2 |
| Draft IOCs | 4 |
| Pending Authority Gates | 1 |
| Hash-chained audit events | 61 |

Audit-chain verification on the copied run: **PASS**.

Scoring against the public DFIR Madness answer key:

| Metric | Result |
|---|---:|
| Answer-key checks reviewed | 29 |
| Hits | 15 |
| Partials | 7 |
| Misses | 7 |
| Corrected false positives | 1 |
| Uncorrected false positives in final COP | 0 |
| Uncorrected hallucinations in reviewed findings | 0 |
| Exact-hit recall | 51.7% |
| Hit-or-partial coverage | 75.9% |

Key hits:

- External RDP and payload delivery from `194.61.24.102` (F-001, F-002, F-004).
- `coreupdater.exe` persistence and hash on the compromised Windows hosts
  (F-005, F-006, F-007).
- C2 to `203.78.103.109:443` from both hosts (F-012, F-018).
- DC01 to DESKTOP lateral RDP at `2020-09-19 02:35:54 UTC` (F-010).
- DCSync / KRBTGT credential compromise (F-003, ITQ-050/051).
- Sensitive DC file access and compromised/backdoor account inventory
  (F-014, F-015, F-016).
- Active attacker state at acquisition from DESKTOP memory (F-018).

Corrected false positive:

- F-011 initially interpreted a 36 MB OneDrive transfer as exfiltration.
- F-017 corrected that claim using directional PCAP analysis: DESKTOP sent only
  0.003 MB to OneDrive; 36.268 MB flowed inbound to DESKTOP.
- ASR-2 was updated by `operator-review` at audit seq 61 so the final Common
  Operating Picture no longer repeats the corrected exfiltration claim.

Miss themes:

1. The agent did not fully recover the answer-key sequence around
   `Secret_Beth.txt`, `Beth_Secret.txt`, `secret.zip`, `loot.zip`, and the
   timestomped Beth file.
2. The agent did not recover domain passwords from the hashes.
3. The agent did not fully characterize the victim timezone/local-time mismatch.
4. The agent found service persistence but did not complete all registry
   persistence details before the run stopped.

The score card contains the three-claim trace judges are instructed to run:

- F-002 payload delivery via `tshark` HTTP extraction.
- F-010 lateral RDP via `tshark -z conv,tcp`.
- F-017 OneDrive exfil correction via directional byte counts.

See:
[`examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/score_card.md`](../examples/szechuan_sauce/runs/2026-06-14-szechuan_sauce_2026-06-14/score_card.md).

---

## 3. Hallucination accounting

Hallucinations are the IR-specific failure mode the hackathon rules call out:
*"hallucinations caught and flagged."*

### 3.1 Caught (and surfaced) by Phase 18 anomaly check

Examples observed during benchmarking will be listed here with the
contradicting evidence pair (e.g., "Shimcache says binary executed at T1, but
MFT records its creation at T2 > T1 - flagged").

### 3.2 Caught (and not surfaced) - manual review only

Honest accounting: claims the agent made that we identified post-hoc as
unsupported by tool output. Example archetypes:

- Inferring an actor's intent without a tool execution producing that evidence
- Citing a Sigma rule by ID that does not exist in the bundled ruleset
- Conflating two distinct files with similar names

### 3.3 Avoided entirely by architectural design

- **No raw shell** - the agent cannot fabricate a `bash` invocation it didn't
  actually run, because there is no `execute_shell()` MCP function. Every claim
  traces to a typed function with a deterministic output.
- **No `eval()` or arbitrary file read** - the agent cannot "claim it ran X"
  without there being an audit event proving it ran X.
- **Hash-chained provenance** - fabricated findings cannot be inserted into the
  audit log without breaking the chain at `audit_verify.sh`.
- **RAG-bounded enrichment** - evidence artifacts establish case facts; `mcp_rag`
  does not. RAG is used only to explain and classify facts already supported by
  artifact output: MITRE technique alignment, Sigma rule rationale, LOLBAS
  context, and Atomic Red Team references. The agent is instructed to cite the
  returned `record_id` and similarity score for those enrichment claims; uncited
  enrichments can therefore be identified by diffing the agent's narrative
  against `forensic_audit.jsonl` `rag_lookup` events.
- **Baseline-bounded suspicion** - `mcp_baseline` is deterministic comparison
  against known-good Windows reference data. A miss or path anomaly is a review
  candidate, not proof of compromise; it becomes a finding only when correlated
  with case evidence such as execution, persistence, network traffic, or memory.
- **Deterministic vs probabilistic source typing** - baseline lookups
  (`mcp_baseline`) and IOC lookups (`mcp_cti`) return exact-match results, not
  probability-weighted completions. RAG lookups are typed as enrichment, not
  deterministic proof.
  The `source_type` field in each `forensic_audit.jsonl` event distinguishes
  `deterministic` (hash/IP exact-match) from `ai_enrichment` (LLM reasoning
  over retrieved context) so downstream verification can be targeted.

### 3.4 Pre-close completeness critic - the architectural answer to the FN class

False negatives (ground-truth checks the agent never surfaced) are the dominant
error class in the first grading-run datapoint (13 FN out of 36 graded claims;
see [`datasets.md` §6.1](datasets.md)). The architectural mitigation shipped
this cycle:

- **`siftics/completeness_rules.py`** - pure-Python rule engine, seven rules
  each a typed function over a `CaseState` dataclass (suit.jsonl + findings.jsonl
  + grid.jsonl + briefings/). Initial v1 ruleset:
 - `antiforensics_scope_data_files` (HIGH) - covers the Beth_Secret.txt
    timestomp false-positive class
 - `antiforensics_scope_log_files` (MEDIUM)
 - `registry_persistence_when_service_persistence` (HIGH)
 - `browser_history_when_remote_entry_vector` (MEDIUM)
 - `timezone_registry_read_for_windows` (MEDIUM)
 - `cti_lookup_for_external_ips` (MEDIUM)
 - `credential_dump_on_dc_compromise` (HIGH)
- **`mcp_case.case_completeness_check()`** - typed MCP tool the agent calls
  before any final briefing or motivation lock-in. Returns gaps ordered
  HIGH → MEDIUM → LOW. Writes a `case_completeness_check_run` audit event.
- **`mcp_case.case_set_motivation(text)`** - typed lock-in for the
  attacker-motive narrative. Rejects placeholder strings (<25 chars, "TBD",
  "Unknown", etc.) and writes a `case_motivation_set` audit event.
- **`skills/case-completeness-review.md`** - the prompt-side obligation that
  forces the agent to call the check before closing. Every HIGH gap must be
  addressed; every MEDIUM gap must be documented.

The rule engine itself is structural (pure Python, deterministic over typed
state); the agent's *obligation to call it* is prompt-based (P14 in
[`constraint_implementation.md`](constraint_implementation.md)). Together they
turn "did the agent forget to look at X?" from a tacit reviewer concern into a
typed, auditable check.

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

### 5.1 Packaged-run cost (Sonnet 4.6, prompt caching on)

The current repository contains one fully packaged, judge-ready accuracy run
with token/cost telemetry: DFIR Madness Stolen Szechuan Sauce. Percentiles are
not reported from a single datapoint.

| Run | Cost (USD) | Wall-clock (min) | LLM calls | Output tokens |
|---|---|---|---|---|
| `szechuan_sauce_2026-06-14` | `$6.944945` | 84 | 1 recorded audit event | 9,602 |

### 5.2 Cost breakdown by task class

| Task class | Input tokens | Cached read | Cached creation | Output tokens | Cost per call |
|---|---:|---:|---:|---:|---:|
| `investigator` (`claude-sonnet-4-6`) | 563 | 28,556,178 | 809,725 | 9,602 | `$6.944945` |

No packaged Stage One run used separate `classifier`, `synthesizer`, or
`deep_review` task-class calls, so those rows are intentionally omitted instead
of reported as speculative estimates.

### 5.3 Cost circuit breaker behaviour

Default budget per case: **$10 USD**. When the running case cost reaches this,
`cost_tracker.BudgetExceeded` is raised at the top of the next LLM call and
no further requests are made. The agent is *unable* to continue past the
budget regardless of its reasoning - this is architectural (criterion #4),
not prompt-based.

The audit log includes an `llm_call` event for every LLM invocation with
`model`, `task_class`, `purpose`, `input_tokens`, `cached_read_tokens`,
`cached_creation_tokens`, `output_tokens`, `cost_usd`, and `cache_hit_rate`.
This gives **per-finding cost traceability** - a feature Valhuntir does not
claim.

---

## 6. Known failure modes and limitations

Honest list - these are real and accepted in v1:

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
   analyst reviewing the Affected Systems Register (ASR) cannot immediately see which enrichments
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
| Hash-pinned reproducible installs | `pip install --require-hashes` from a `requirements-pinned.txt` produced by `pip-compile --generate-hashes` | **staged** - not in this submission |
| npm `--ignore-scripts` for Claude Code CLI | already declarative when the user opts into `--install-claude` | partial - Claude Code install path uses `npm install -g`, planned migration to `npm ci --ignore-scripts` against a vendored `package-lock.json` |

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
drifted toolchain. This is **architectural, not prompt-based** - the
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
  hash detects it (different installed bytes) - but the prior install
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

# Run the full accuracy benchmark - writes results to examples/benchmark_<date>/
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
