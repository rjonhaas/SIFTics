# SIFTics

> **Find Evil. Fight Evil.**

Agentic Digital Forensics and Incident Response for the SANS SIFT Workstation. Claude Code (or any other approved agentic framework that speaks MCP) drives the analysis loop; the human Incident Commander authorises every active response with cryptographically-enforced gates.

**License:** [MIT](LICENSE)

---

## What SIFTics is

> **The asymmetry SIFTics targets:** detection has been operating at AI-speed for years; response is still human-speed because **authority cannot be delegated to a model**. SIFTics is the bridge - it lets a human Incident Commander (IC) authorise active response at the speed an AI can propose it, with cryptographically-enforced gates so the IC never loses control of *what* gets executed.

SIFTics is structured in three deliberately-separated layers. Layer 1 stands on its own; Layers 2 and 3 show what the same agent looks like when wired to a real SOC.

| Layer | What it is | What lives here |
|---|---|---|
| **1. SIFTics agent** | The standalone agentic DFIR analyst. National Incident Management System (NIMS) Incident Command framework, HMAC-signed Authority Gates, hash-chained audit, Safety / Legal Officer architectural guardrails. Runs against any evidence bundle on the SIFT Workstation; **no external infrastructure required**. | this repo - `siftics/`, `mcp_*/`, `siftics_ui/`, `phases/`, `skills/` |
| **2. Integration contract** | A typed MCP tool surface that any environment can plug into - Velociraptor, an EDR, a TIP, an Entra ID tenant. The agent doesn't know or care which vendor is on the other side; the contract is identical. | `mcp_broker/`, `mcp_containment/`, `mcp_intel/` - each with a `_MODE = mock \| real` flag |
| **3. Reference deployment** | A live Caldera + Velociraptor + ELK + Active-Directory environment that shows the agent **fighting back at AI-speed** against real adversary emulation. **Not a dependency** of Layer 1; it demonstrates what Layer 2 enables. | sister repo: [github.com/rjonhaas/hunt_lab](https://github.com/rjonhaas/hunt_lab) |

**Two ways to run it:**

- **Standalone** - clone, run `./setup.sh` on a SIFT VM, point it at any evidence bundle. The MCP broker returns generic enterprise placeholders so there is nothing external to configure.
- **Connected** - configure response targets at `/setup`, switch the MCP broker to `real` mode, point it at a Velociraptor server. Any Velociraptor server speaking the same API works.

Layer 1 is the core: a working agent that needs no external infrastructure. Layers 2 and 3 demonstrate the same agent authorising live response, and architecturally refusing to authorise the *wrong* response (see the OT Safety Officer hard-stop in the demo).

**Architectural pattern:** Custom MCP Server. The agent reaches every tool, evidence source, and response target through a typed, schema-validated, audit-logged interface.

---

## Quickstart

Tested on a fresh **SANS SIFT Workstation 2026.04.22** OVA and on **WSL-Ubuntu-22.04 with SIFT server-mode**.

```bash
git clone -b find-evil https://github.com/rjonhaas/SIFTics.git
cd SIFTics
./setup.sh --init-case --start-ui
# Then open http://127.0.0.1:8080 in a browser
```

`setup.sh` is idempotent and narrates each step. Case IDs auto-generate as `YYYY-MM-DD-NN` under `~/Desktop/cases/`. Custom names still work via `--case-id`.

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
| Demo video word-for-word script | [`docs/demo_video_script.md`](docs/demo_video_script.md) |

---

## Credits and framework lineage

- **NIMS Incident Command System** - for the Common Operating Picture, Section Chief / Incident Commander roles, and Authority Gate concept.
- **NIST SP 800-61 Rev 2** - for the Containment, Eradication, Recovery framing in the CET register.
- **FEMA ICS Form 209** - for the affected-systems register column model.
- **SANS LDR553** (Steve Armstrong-Godwin / AG Cyber) - UI structure inspired by the CIMTK toolkit. *Pending explicit permission to use branded names; currently shipped with generic IR-doctrine labels (`labels.yaml: active_label_set: generic`).*
- **AndrewRathbun / VanillaWindowsReference + VanillaWindowsRegistryHives** - Windows known-good baseline corpus used by `mcp_baseline`.
- **wagga40 / Zircolite** - Sigma rule application over EVTX in `phases/run_zircolite.sh`.
- **OpenSourceMalware.com** - STIX threat-intel feed integrated via `mcp_cti`.
- **abuse.ch** (URLhaus, MalwareBazaar, ThreatFox) - multi-source IOC enrichment in `mcp_cti`.
- **MITRE ATT&CK, LOLBAS, Atomic Red Team, SigmaHQ** - knowledge corpus indexed into `mcp_rag` for semantic alignment.
- **Velociraptor team** - the EDR platform that makes the detect-hunt loop possible.

---

## Contact

- GitHub issues: [https://github.com/rjonhaas/SIFTics/issues](https://github.com/rjonhaas/SIFTics/issues)

---

## Hackathon

This project is the SIFTics entry to the [SANS Find Evil! 2026 hackathon](https://findevil.devpost.com). Required deliverables, their locations, and how SIFTics maps to the six judging criteria are in [`docs/hackathon_submission.md`](docs/hackathon_submission.md).
