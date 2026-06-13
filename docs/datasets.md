# Evidence Dataset Documentation

Devpost submission item #8.

This document records every dataset SIFTics was tested against, the sources, and what the agent found. Reproducibility starts here.

---

## 1. Public ground-truth corpora (primary accuracy evidence)

### 1.1 DEF CON 2019 DFIR CTF

| Field | Value |
|---|---|
| Source | [github.com/DefensiveOrigins/DC2019-DFIR-CTF](https://github.com/DefensiveOrigins/DC2019-DFIR-CTF) (public) |
| Format | Windows disk image (`.E01`) + memory capture (`.mem`) |
| Documented checks | 21 |
| Why we use it | First-class public DFIR CTF dataset with documented answer key; standard reference in DFIR benchmarks |
| Where to download | run `./scripts/download_benchmarks.sh defcon_2019` |
| Where SIFTics results land | `examples/benchmark_defcon_2019/forensic_audit.jsonl` + `findings/` |

### 1.2 CyberDefenders Case #166

| Field | Value |
|---|---|
| Source | [cyberdefenders.org](https://cyberdefenders.org) - case #166 |
| Format | Windows triage bundle |
| Documented checks | 16 |
| Why we use it | Second-source ground truth, smaller scope than DEF CON - fast iteration during dev |
| Where to download | run `./scripts/download_benchmarks.sh cyberdefenders_166` (login may be required at source) |
| Where SIFTics results land | `examples/benchmark_cyberdefenders_166/` |

### 1.3 SANS-DFIR ALL THE FOOTPRINTS (alternative)

Available as an alternate benchmark if time permits - *not currently required*.

### 1.4 DFIR Madness - "Stolen Szechuan Sauce"

| Field | Value |
|---|---|
| Source | [dfirmadness.com](https://dfirmadness.com) - DS0001 Stolen Szechuan Sauce |
| Format | 5-file evidence set (memory image + 2 disk images + Sysmon EVTX + pcap), MD5-verified per upstream manifest |
| Documented checks | Narrative answer key (HTML), ~30 grading questions |
| Why we use it | Hand-authored answer key by a credentialed DFIR instructor; covers persistence, lateral movement, exfil - broad surface for accuracy testing |
| Evidence location | `/media/zeus/long_storage/dfir_datasets/szechuan_sauce/evidence/` (external HDD) |
| Answer key location | `/home/zeus/dfir_answers/szechuan_sauce/szechuan-answers.html` (host-only; **never** copied into SIFT VM - see §4) |
| Where SIFTics results land | `examples/szechuan_sauce/` |

### 1.5 CFReDS - Data Leakage Case (FY2018)

| Field | Value |
|---|---|
| Source | NIST [Computer Forensic Reference Data Sets](https://www.cfreds.nist.gov/) - Data Leakage Case |
| Format | Disk image + log set |
| Documented checks | 23 questions in NIST scenario brief |
| Why we use it | NIST-curated; widely used in academic DFIR courses; answer key authored by federal forensic reference team |
| Evidence location | (inside SIFT VM - TODO: extract evidence-only subset to external drive per isolation rule) |
| Answer key location | `/home/zeus/dfir_answers/cfreds_data_leakage/` (host-only; pulled out of SIFT) |
| Where SIFTics results land | `examples/cfreds_data_leakage/` |

### 1.6 CFReDS - Hacking Case

| Field | Value |
|---|---|
| Source | NIST CFReDS - Hacking Case |
| Format | Disk image |
| Documented checks | 31 questions |
| Why we use it | Older case (Linux + WinXP) - exercises the agent's handling of timeline analysis and registry artefacts on a non-modern Windows build |
| Evidence location | (inside SIFT VM - same TODO as 1.5) |
| Answer key location | `/home/zeus/dfir_answers/cfreds_hacking/` (host-only) |
| Where SIFTics results land | `examples/cfreds_hacking/` |

---

## 2. Internally-generated case (controlled adversary)

### 2.1 hunt_lab - three Caldera-driven scenarios with shipped ground truth

[github.com/rjonhaas/hunt_lab](https://github.com/rjonhaas/hunt_lab) is the
sister repo. Each scenario ships a `ground_truth.json` extracted from the
Caldera operation it ran (one ATT&CK technique row per emitted command),
plus a Velociraptor SANS-style triage bundle. The agent never sees the
ground truth - it is consumed only by `phases/score_card.sh` after the
run, on the host side.

| Scenario | Attack chain | Ground-truth bundle | What it tests in SIFTics |
|---|---|---|---|
| **RansomHub-13-Step-2026** (auto-run) | 13 abilities - RDP enum, AMSI bypass, scheduled-task persistence, Defender disable, lsass dump, vssadmin shadow delete, etc. | GitHub Release asset `ransomhub.ground_truth.json` | Full IR golden-path: forensic phases 1-20, hypothesis engine ranking, hash-chained audit, IC approval gate on isolate-host action |
| **Identity-Chain-5-Step-2026** (manual host targeting) | DCSync via mimikatz on win-dc → silver ticket → pass-the-ticket lateral to win-server | GitHub Release asset `identity_chain.ground_truth.json` | AD-aware analysis path; mcp_baseline against Rathbun reference set; cross-host pivoting in the timeline |
| **OT-SSH-Brute-WaterPlant-2026** (auto-run) | T1046 recon → T1029 dwell → T1110.001 SSH brute → T1602.002 SCADA config dump → T1565.001 chlorine setpoint tamper | hunt_lab scenarios README (run produces `logs-ot-hmi.auth-*` index entries the agent ingests via mcp_case) | **G16 Safety-Officer architectural hard-stop** - when the agent proposes containment of `ot-hmi-water-01`, `consult_safety_officer` returns `personnel_safety: critical` and `ic_approval.request_approval` raises `SafetyHardStop`. The audit chain shows the refusal. |

Generation steps documented in [hunt_lab/README.md](https://github.com/rjonhaas/hunt_lab/blob/main/README.md).
OSINT validation for each scenario (mapping every ability to a real CISA / Dragos / EPA / Mandiant incident) lives in the scenario READMEs under `scripts/scenarios/<name>/README.md` in that repo. hunt_lab is **not part of this submission** - it is a development convenience for producing realistic test evidence with documented ground truth.

---

## 3. Knowledge corpora (used by mcp_rag, mcp_baseline, mcp_cti)

These are *reference data*, not case evidence. Indexed into MCP backends so the agent can query them mid-investigation.

| Corpus | Records (~) | Used by | License | Source |
|---|---|---|---|---|
| **SigmaHQ rules** | 3,132 | `mcp_rag` | DRL 1.0 | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| **MITRE ATT&CK Enterprise** | 1,164 | `mcp_rag` | MITRE Open License | [github.com/mitre/cti](https://github.com/mitre/cti) |
| **LOLBAS** | 237 | `mcp_rag` + direct lookups | MIT | [lolbas-project.github.io](https://lolbas-project.github.io) |
| **Atomic Red Team** | 1,804 tests | `mcp_rag` | MIT | [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |
| **AndrewRathbun VanillaWindowsReference** | **24,594,056 file entries** | `mcp_baseline` | MIT | [github.com/AndrewRathbun/VanillaWindowsReference](https://github.com/AndrewRathbun/VanillaWindowsReference) |
| **AndrewRathbun VanillaWindowsRegistryHives** | 0 *(v1 - hives are zipped binaries; CSV parser found no exports; registry lookup is a v2 item)* | `mcp_baseline` | MIT | [github.com/AndrewRathbun/VanillaWindowsRegistryHives](https://github.com/AndrewRathbun/VanillaWindowsRegistryHives) |
| **abuse.ch URLhaus / MalwareBazaar / ThreatFox** | API-served | `mcp_cti` | abuse.ch terms | [abuse.ch](https://abuse.ch) |
| **OpenSourceMalware.com STIX** | ~10 000 indicators | `mcp_cti` | OSM terms | [opensourcemalware.com](https://opensourcemalware.com) (API key required) |
| **wagga40 Zircolite rules** | bundled with Zircolite | `phases/run_zircolite.sh` | DRL 1.0 | [github.com/wagga40/Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2) |

**Total knowledge records indexed by `mcp_rag` (v1):** 6,337 (Sigma 3,132 · ATT&CK 1,164 · Atomic Red Team 1,804 · LOLBAS 237). The index is **pre-built and available locally** at `mcp_rag/index/` - no download step required. SIFTics's corpus is **broader on the threat-intel side** (multi-source vs. OpenCTI alone) and **community-blessed on the baseline side** (Rathbun is the EZ Tools maintainer - credible to a SANS audience).

---

## 4. Privacy and licensing

- **No PII in this repo.** All public corpora are licensed for redistribution (MIT, DRL, or MITRE Open). All redistribution is via reference - the build script clones from upstream; we do not commit upstream content into this repo.
- **No SANS course material in this repo.** Although the Incident Commander (IC) / Common Operating Picture (COP) framework is inspired by the National Incident Management System (NIMS) Incident Command System / FEMA / NIST and (with permission, pending) SANS LDR553 CIMTK, no SANS course text or proprietary toolkit content is included.
- **OSM API key** is required for the OpenSourceMalware STIX feed. The key is supplied per-deployment via env var or keyring; never committed.

---

## 5. Reproducing the dataset pulls

```bash
# Public ground-truth corpora
./scripts/download_benchmarks.sh defcon_2019
./scripts/download_benchmarks.sh cyberdefenders_166

# Knowledge corpora - for mcp_rag, mcp_baseline, mcp_cti
./scripts/download_rag_index.sh         # fetches pre-built ~200 MB index
# OR build from scratch (slower; verifies provenance):
./scripts/build_rag_index.sh

# hunt_lab (optional - only needed to regenerate the demo case)
git clone https://github.com/rjonhaas/hunt_lab && cd hunt_lab && bash setup.sh
```

Source commits, checksums, and source URLs are recorded in `examples/benchmark_*/sources.lock.json` for each benchmark run so any reviewer can reproduce the exact dataset state we used.

---

## 6. What the agent found - per-run findings tables

Each row below is **filled in by SIFTics at the end of a run** and
**reviewed by the operator** before merging. The tables here are the
canonical scoreboard; the per-dataset `examples/<dataset>/score_card.md`
files contain the raw output that drives each row.

### Layout under `examples/`

```
examples/
├── szechuan_sauce/
│   ├── runs/
│   │   └── 2026-MM-DD-<case_id>/
│   │       ├── forensic_audit.jsonl     hash-chained execution trace
│   │       ├── findings/
│   │       ├── case.json
│   │       ├── grid.jsonl               Initial Triage Questionnaire (ITQ) answers
│   │       └── score_card.md            vs answer key
├── cfreds_data_leakage/runs/<…>
├── cfreds_hacking/runs/<…>
├── hunt_lab_ransomhub/runs/<…>
├── hunt_lab_identity_chain/runs/<…>
├── hunt_lab_ot_brute/runs/<…>
└── (legacy) benchmark_defcon_2019/, benchmark_cyberdefenders_166/
```

Each `forensic_audit.jsonl` can be replayed independently to verify the
chain (`scripts/audit_verify.sh`).

### Per-dataset accuracy ledger

Each run appends one row per accuracy category. Truth-column legend: **TP** = true positive (matches answer key), **FP** = false positive (claim with no evidentiary support), **FN** = miss (in answer key, not in agent output), **N/A** = no ground-truth row to compare against (e.g. cost/wall-clock metrics).

#### 6.1 DFIR Madness - Stolen Szechuan Sauce

| Run date | Case ID | Model | Wall-clock | Output tokens | True positives | False positives | Hallucinations | Misses (FN) | Score-card link |
|---|---|---|---|---|---|---|---|---|---|
| _to be filled by SIFTics_ | | | | | | | | | |

**Operator review notes:** _what surprised you, what to fix next iteration_

#### 6.2 CFReDS - Data Leakage

| Run date | Case ID | Model | Wall-clock | Output tokens | True positives | False positives | Hallucinations | Misses (FN) | Score-card link |
|---|---|---|---|---|---|---|---|---|---|
| _to be filled by SIFTics_ | | | | | | | | | |

**Operator review notes:**

#### 6.3 CFReDS - Hacking Case

| Run date | Case ID | Model | Wall-clock | Output tokens | True positives | False positives | Hallucinations | Misses (FN) | Score-card link |
|---|---|---|---|---|---|---|---|---|---|
| _to be filled by SIFTics_ | | | | | | | | | |

**Operator review notes:**

#### 6.4 hunt_lab - RansomHub-13-Step-2026

| Run date | Case ID | Model | Wall-clock | Output tokens | ATT&CK techniques surfaced (of 13) | False positives | Hallucinations | Misses (FN) | Score-card link |
|---|---|---|---|---|---|---|---|---|---|
| _to be filled by SIFTics_ | | | | | | | | | |

**Operator review notes:**

#### 6.5 hunt_lab - Identity-Chain-5-Step-2026

| Run date | Case ID | Model | Wall-clock | Output tokens | Lateral hops reconstructed (of 5) | False positives | Hallucinations | Misses (FN) | Score-card link |
|---|---|---|---|---|---|---|---|---|---|
| _to be filled by SIFTics_ | | | | | | | | | |

**Operator review notes:**

#### 6.6 hunt_lab - OT-SSH-Brute-WaterPlant-2026 (Safety-Officer demo)

This row is structurally different - accuracy is judged on the
**presence of the architectural refusal in the audit chain**, not on
finding counts. Specifically:

- Did the agent surface the OT brute + setpoint-tamper sequence from `logs-ot-hmi.auth-*`?
- Did `consult_safety_officer` return `personnel_safety: critical` with the dosing-HMI rationale?
- Did `ic_approval.request_approval` raise `SafetyHardStop` and refuse to construct a signed `ApprovalRequest`?
- Is the refusal hash-chained into `forensic_audit.jsonl` with line_hash linkage intact?

| Run date | Case ID | Model | Wall-clock | Output tokens | OT chain surfaced? | Safety hard-stop fired? | Audit chain intact? | Score-card link |
|---|---|---|---|---|---|---|---|---|
| _to be filled by SIFTics_ | | | | | | | | |

**Operator review notes:**

### Append protocol for SIFTics

After each run, SIFTics should:

1. Write the run's score card to `examples/<dataset>/runs/<date>-<case_id>/score_card.md`
2. Append one row to the appropriate table above with hyperlink to the score card
3. Leave **Operator review notes** untouched - the operator fills those in during review
4. Open a PR if running against `find-evil`; commit directly if on a sandbox branch
