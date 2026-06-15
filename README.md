# SIFTics

> **Find Evil. Fight Evil.**

**License:** [MIT](LICENSE)

---

## What SIFTics is

SIFTics turns the SIFT Workstation into an agentic DFIR analyst. Claude Code drives the analysis loop as the Investigation Section Chief; you sit as Incident Commander, and every active response (fleet hunt, host isolation, account disable) requires your HMAC-signed approval before it fires. The guardrails are **architectural**, not prompted: typed MCP functions, schema-layer Safety Officer hard-stops, hash-chained audit. It runs standalone against any evidence bundle on a SIFT VM - no external infrastructure required - and the same agent wires up to Velociraptor and an EDR / TIP for live response when you point it at one.

---

## Quickstart

Tested on a fresh **SANS SIFT Workstation 2026.04.22** OVA and on **WSL-Ubuntu-22.04 with SIFT server-mode**.

```bash
git clone https://github.com/rjonhaas/SIFTics.git
cd SIFTics
./setup.sh
# Then open http://127.0.0.1:8080 in a browser; create your case via the new-case page
```

`setup.sh` is idempotent and narrates each step. Cases are created through the UI's new-case page, which mints a `YYYY-MM-DD-NN` ID under `~/Desktop/cases/` and accepts a free-form IC briefing for the agent.

**Demo evidence (optional):** pull a known-answer Caldera bundle from the [hunt_lab Releases](https://github.com/rjonhaas/hunt_lab/releases):

```bash
./scripts/download_demo_case.sh
```

Drops evidence into `~/Desktop/cases/<release-tag>/`. The ground-truth JSON lands separately at `~/dfir_answers/<release-tag>/` (chmod 600) — never on the same machine as the agent, per the answer-key isolation rule.

Hardware tiers, manual install path, individual flags, and `agent.yaml` configuration: [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

---

## Deep dives

| Topic | Doc |
|---|---|
| Architecture, MCP servers, three-layer framing, trust boundaries, NIMS Command Staff doctrine | [`docs/architecture.md`](docs/architecture.md) |
| Architectural vs prompt-based guardrails, bypass test results | [`docs/constraint_implementation.md`](docs/constraint_implementation.md) |
| What SIFTics was tested against and what it found | [`docs/datasets.md`](docs/datasets.md) |
| False positives, misses, hallucinations - honest self-assessment | [`docs/accuracy_report.md`](docs/accuracy_report.md) |
| Setup detail, hardware tiers, manual install path | [`docs/QUICKSTART.md`](docs/QUICKSTART.md) |
| Demo video storyboard | [`docs/demo_video.md`](docs/demo_video.md) |
| Demo video word-for-word script | [`docs/demo_video_script_v2.md`](docs/demo_video_script_v2.md) |

---

## Credits and framework lineage

- **NIMS Incident Command System** - for the Common Operating Picture, Section Chief / Incident Commander roles, and Authority Gate concept.
- **NIST SP 800-61 Rev 2** - for the Containment, Eradication, Recovery framing in the CET register.
- **FEMA ICS Form 209** - for the affected-systems register column model.
- **SANS LDR553** (Steve Armstrong-Godwin / AG Cyber) - UI structure inspired by the CIMTK toolkit. *Pending explicit permission to use branded names; currently shipped with generic IR-doctrine labels (`labels.yaml: active_label_set: generic`).*
- **AndrewRathbun / VanillaWindowsReference + VanillaWindowsRegistryHives** - Windows known-good baseline corpus used by `mcp_baseline` for deterministic comparison. Baseline misses are review candidates, not standalone proof of compromise.
- **wagga40 / Zircolite** - Sigma rule application over EVTX in `phases/run_zircolite.sh`.
- **OpenSourceMalware.com** - STIX threat-intel feed integrated via `mcp_cti`.
- **abuse.ch** (URLhaus, MalwareBazaar, ThreatFox) - multi-source IOC enrichment in `mcp_cti`.
- **MITRE ATT&CK, LOLBAS, Atomic Red Team, SigmaHQ** - knowledge corpus indexed into `mcp_rag` for explanatory enrichment of evidence-backed findings, not as ground truth.
- **Velociraptor team** - the EDR platform that makes the detect-hunt loop possible.

---

## Contact

- GitHub issues: [https://github.com/rjonhaas/SIFTics/issues](https://github.com/rjonhaas/SIFTics/issues)

---

## Hackathon

This project is the SIFTics entry to the [SANS Find Evil! 2026 hackathon](https://findevil.devpost.com). Required deliverables, their locations, and how SIFTics maps to the six judging criteria are in [`docs/hackathon_submission.md`](docs/hackathon_submission.md).
