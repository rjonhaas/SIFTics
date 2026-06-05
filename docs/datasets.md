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
| Source | [cyberdefenders.org](https://cyberdefenders.org) — case #166 |
| Format | Windows triage bundle |
| Documented checks | 16 |
| Why we use it | Second-source ground truth, smaller scope than DEF CON — fast iteration during dev |
| Where to download | run `./scripts/download_benchmarks.sh cyberdefenders_166` (login may be required at source) |
| Where SIFTics results land | `examples/benchmark_cyberdefenders_166/` |

### 1.3 SANS-DFIR ALL THE FOOTPRINTS (alternative)

Available as an alternate benchmark if time permits — *not currently required*.

---

## 2. Internally-generated case (controlled adversary)

### 2.1 hunt_lab — Caldera-driven mimikatz scenario

| Field | Value |
|---|---|
| Source | [github.com/rjonhaas/hunt_lab](https://github.com/rjonhaas/hunt_lab) (sister repo) |
| Format | live Windows 11 victim VM (192.168.56.20) with Sysmon + Elastic Agent + Sandcat |
| Attack | Caldera abilities: persistence via scheduled task `WindowsSecurityUpdate`; mimikatz variant renamed to `lsass_helper.exe` in `C:\Users\Public\`; Sandcat beacon to 192.168.56.30:8888 |
| Why we use it | **Ground truth is known by construction** — we drove the attack ourselves, so every TTP is documented |
| Where SIFTics results land | `examples/run_2026-XX-XX/` (referenced in the demo video) |

Generation steps documented in [hunt_lab/README.md](https://github.com/rjonhaas/hunt_lab/blob/main/README.md). hunt_lab is **not part of the submission** — it is a development convenience for producing realistic test evidence.

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
| **AndrewRathbun VanillaWindowsRegistryHives** | 0 *(v1 — hives are zipped binaries; CSV parser found no exports; registry lookup is a v2 item)* | `mcp_baseline` | MIT | [github.com/AndrewRathbun/VanillaWindowsRegistryHives](https://github.com/AndrewRathbun/VanillaWindowsRegistryHives) |
| **abuse.ch URLhaus / MalwareBazaar / ThreatFox** | API-served | `mcp_cti` | abuse.ch terms | [abuse.ch](https://abuse.ch) |
| **OpenSourceMalware.com STIX** | ~10 000 indicators | `mcp_cti` | OSM terms | [opensourcemalware.com](https://opensourcemalware.com) (API key required) |
| **wagga40 Zircolite rules** | bundled with Zircolite | `phases/run_zircolite.sh` | DRL 1.0 | [github.com/wagga40/Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2) |

**Total knowledge records indexed by `mcp_rag` (v1):** 6,337 (Sigma 3,132 · ATT&CK 1,164 · Atomic Red Team 1,804 · LOLBAS 237). The index is **pre-built and available locally** at `mcp_rag/index/` — no download step required. SIFTics's corpus is **broader on the threat-intel side** (multi-source vs. OpenCTI alone) and **community-blessed on the baseline side** (Rathbun is the EZ Tools maintainer — credible to a SANS audience).

---

## 4. Privacy and licensing

- **No PII in this repo.** All public corpora are licensed for redistribution (MIT, DRL, or MITRE Open). All redistribution is via reference — the build script clones from upstream; we do not commit upstream content into this repo.
- **No SANS course material in this repo.** Although the IC/COP framework is inspired by NIMS ICS / FEMA / NIST and (with permission, pending) SANS LDR553 CIMTK, no SANS course text or proprietary toolkit content is included.
- **OSM API key** is required for the OpenSourceMalware STIX feed. The key is supplied per-deployment via env var or keyring; never committed.

---

## 5. Reproducing the dataset pulls

```bash
# Public ground-truth corpora
./scripts/download_benchmarks.sh defcon_2019
./scripts/download_benchmarks.sh cyberdefenders_166

# Knowledge corpora — for mcp_rag, mcp_baseline, mcp_cti
./scripts/download_rag_index.sh         # fetches pre-built ~200 MB index
# OR build from scratch (slower; verifies provenance):
./scripts/build_rag_index.sh

# hunt_lab (optional — only needed to regenerate the demo case)
git clone https://github.com/rjonhaas/hunt_lab && cd hunt_lab && bash setup.sh
```

Source commits, checksums, and source URLs are recorded in `examples/benchmark_*/sources.lock.json` for each benchmark run so any reviewer can reproduce the exact dataset state we used.

---

## 6. What the agent found — sample outputs

Sample findings from each benchmark live under `examples/benchmark_*/findings/`:

```
examples/
├── benchmark_defcon_2019/
│   ├── forensic_audit.jsonl         hash-chained execution trace
│   ├── findings/
│   │   ├── phase_1_ntfs.md
│   │   ├── phase_2_registry.md
│   │   ├── …
│   ├── hunt_packages/
│   ├── briefings/
│   ├── case.json
│   ├── grid.jsonl                   ITQ answers
│   └── score_card.md                vs ground truth
├── benchmark_cyberdefenders_166/
│   └── (same layout)
└── run_2026-XX-XX/                  hunt_lab Caldera case
    └── (same layout)
```

Each `forensic_audit.jsonl` can be replayed independently to verify the chain (`audit_verify.sh`).
