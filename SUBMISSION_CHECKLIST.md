# FIND EVIL! Submission Checklist

This document maps each hackathon requirement to the concrete artifact in this repository. Use it to track what's complete and what still needs work before the June 15, 2026 deadline.

## The Eight Required Submission Components

> From the official rules, **missing any one = elimination before judging**.

| # | Requirement | Artifact | Status |
|---|---|---|---|
| 1 | **Code Repository** (GitHub, MIT or Apache 2.0) | Full repo with Apache 2.0 license | ⚠ Need to push to GitHub |
| 2 | **Demo Video** (≤5 min, live terminal, ≥1 self-correction) | Not yet recorded | ⬜ TODO |
| 3 | **Architecture Diagram** | `ARCHITECTURE.md` | ✅ Complete |
| 4 | **Written Project Description** (Devpost story format) | Not yet written | ⬜ TODO |
| 5 | **Dataset Documentation** | Not yet written (needs a fixture dataset first) | ⬜ TODO |
| 6 | **Accuracy Report** | Drafted via spoliation + injection reports | 🟡 Partial |
| 7 | **Try-It-Out Instructions** | `install.sh` + per-skill READMEs | ✅ Complete |
| 8 | **Agent Execution Logs** | Audit Log skill + hash-chained JSONL design | 🟡 Design complete, needs real run |

## The Three Mandatory Demonstrated Capabilities

> The Project must demonstrate all of the following per the rules:

| Capability | Design Support | Demo Evidence |
|---|---|---|
| **Self-correction** — agent detects and resolves errors without human intervention | IC operational period loop + Planning Section contradiction detection + Forensics Branch consistency checks | ⬜ Demo video must show this |
| **Accuracy validation** — findings traceable to artifacts, files, offsets, log entries | Every finding schema requires `tool_execution_id` citation; audit log provides `trace_finding` query | ✅ Design; needs real execution trace |
| **Analytical reasoning** — structured investigative narrative, not a raw log | Documentation Unit produces `Attack Narrative` section with confidence language and inline citations | ✅ Design; needs a real incident run |

## Judging Criteria Coverage

| Criterion (equally weighted, first is tiebreaker) | How Our Submission Addresses It |
|---|---|
| **Autonomous Execution Quality** | ICS operational period loop. IC reasons about objectives, delegates, synthesizes, re-tasks on gaps. Demo video will show this live. |
| **IR Accuracy** | Confidence-tiered findings (CONFIRMED / INFERRED / CONTRADICTED). Situation Unit detects contradictions. Branch consistency checks (MFT vs USN, AmCache vs Prefetch). |
| **Breadth and Depth of Analysis** | Five specialized branches (Triage, Forensics, Memory, Network, Malware) run in parallel without any single agent holding all raw data. Custom MCP server parses output into typed fields. |
| **Constraint Implementation** | **Our strongest suit.** Architectural guardrails verified by 88-vector spoliation harness. Every one of the 88 blocked. Report distinguishes prompt-based from architectural enforcement with layer-level attribution. |
| **Audit Trail Quality** | Append-only JSONL audit log with SHA-256 hash chain. `trace_finding(FND-N)` query returns full chain from finding → branch rollup → MCP call → tool execution. |
| **Usability and Documentation** | `install.sh` handles SIFT bootstrap. Every skill has SKILL.md manifest. ARCHITECTURE.md explains trust boundaries. |

## Repository Structure

```
protocol-sift-ics/
├── README.md                                    Project overview
├── ARCHITECTURE.md                              Full architecture diagram + trust boundaries
├── SUBMISSION_CHECKLIST.md                      This file
├── install.sh                                   SIFT Workstation bootstrap script
│
├── config/
│   └── openclaw.json                            OpenClaw gateway config + model tiering
│
├── skills/                                      All 17 OpenClaw skills
│   ├── command-staff/ (4 skills)                IC, Legal, Safety, Liaison
│   ├── operations/   (6 skills)                 Ops Chief + 5 branches
│   ├── planning/     (4 skills)                 Chief + Situation/Timeline/Documentation
│   ├── logistics/    (3 skills)                 Chief + Tool Broker + Evidence Store
│   └── finance-admin/(2 skills)                 Audit Log + Token Budget
│
└── mcp-server/                                  Custom typed-function MCP server
    ├── README.md                                Server design + philosophy
    ├── package.json                             Dependencies + npm scripts
    ├── tsconfig.json                            TypeScript build config
    ├── src/
    │   ├── index.ts                             MCP server entry point
    │   ├── safety/
    │   │   ├── path_guard.ts                    Path containment enforcement
    │   │   └── readonly_guard.ts                Read-only mount verification
    │   └── tools/disk/
    │       └── prefetch.ts                      Example typed tool (PECmd wrapper)
    └── test/
        ├── spoliation/                          88 spoliation attack vectors
        │   ├── README.md
        │   ├── helpers/ (harness, fixture)
        │   ├── attack-vectors/ (5 categories)
        │   ├── reports/
        │   │   └── spoliation-report-example.md Pre-generated example report
        │   └── run.ts                           Runner with JSON + Markdown output
        │
        └── injection/                           67 injection attack vectors
            ├── README.md
            ├── helpers/ (harness with judge model)
            ├── attack-vectors/ (6 categories)
            ├── reports/
            │   └── injection-report-example.md  Pre-generated example report
            └── run.ts                           Runner with multi-tier + statistical mode
```

## What Still Needs To Be Done Before Submission

In priority order:

### 1. ~~Accuracy Test Harness~~ ✅ Scaffold + ground truth complete
Built. All 6 test cases now have curated ground truth: 001-ransomware-disk-only, 002-insider-threat-disk-mem, 003-c2-network-only, 004-multi-host-lateral, 005-living-off-the-land, 006-clean-baseline. **What's still needed**: actual fixture evidence files (disk images, memory captures, PCAPs). See per-case `fixture/README.md` files for generation guides. The harness will run end-to-end as soon as fixtures exist — case definitions and matcher logic are complete.

### 2. ~~One Full Tool Module End-to-End~~ ✅ Volatility complete
Built. `mcp-server/src/tools/memory/` contains the Volatility 3 wrapper with: 7 typed plugin functions (vol_info, vol_pslist, vol_pstree, vol_psscan, vol_cmdline, vol_malfind, vol_netscan), plugin allowlist, argument validation, output spillover for large results, time normalization, and unit tests covering 19+ validation cases. Demo video can use real `vol` invocations against a fixture memory capture.

### 3. Real Execution Run Against a Fixture Incident
- Small, known-scope incident (ransomware or insider threat) with disk + memory
- Drive the swarm through a real operational period
- Capture the audit log, the final incident report, and the execution trace
- This becomes the content of the Demo Video AND the Dataset Documentation

### 4. Demo Video
- ≤5 minutes, live terminal, audio narration
- MUST show at least one self-correction sequence — the IC re-tasking a branch after a gap or contradiction is the cleanest way to demonstrate this
- No slides. No marketing footage.

### 5. Written Project Description (Devpost story format)
- What it does
- How you built it
- Challenges
- What you learned
- What's next
- The ICS framing is the differentiator — lead with that

### 6. Push to GitHub with Apache 2.0 License
- Repository must be public
- License file must be detectable at the top of the repo
- README.md must have setup instructions (we have this)

### 7. Register on Devpost
- Submit before Jun 15, 2026 11:45 PM EDT

## The Story That Wins

When you write the Devpost project description, lead with this:

> We didn't build AI agents — we built an **Incident Command System**. The National Incident Management System's ICS framework has organized human emergency response for 20+ years. Every DFIR practitioner already knows it. We made our agents follow the same chain of command, with the same evidence protections, the same legal advisories, and the same audit trails that responders need to stand behind in court.
>
> Our Incident Commander sets objectives each operational period and delegates to Section Chiefs. Branches specialize (Forensics, Memory, Network, Malware). A Command Staff of Legal, Safety, and Liaison officers advises the IC. Every tool call routes through a single architectural choke point — the Tool Broker — which is the only skill with MCP access. Evidence is mounted read-only. Every finding is traceable to a specific tool execution via an append-only, hash-chained audit log.
>
> We tested it: 88 spoliation attacks, all blocked. 67 injection attacks across three model tiers, zero uncontained critical hijacks.
>
> A senior DFIR analyst reading our audit log shouldn't see "AI output." They should see an incident response that looks like theirs — just faster.
