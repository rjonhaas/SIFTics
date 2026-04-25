# Protocol SIFT ICS — OpenClaw Skills Structure

An autonomous DFIR agent swarm built on OpenClaw, structured as a NIMS Incident Command System (ICS). Every DFIR practitioner already knows ICS — this swarm makes AI follow the same chain of command, with the same evidence protections, the same legal advisories, and the same audit trails that responders need to stand behind in court.

## Directory Layout

```
protocol-sift-ics/
├── skills/
│   ├── command-staff/        # Advisors reporting directly to IC
│   │   ├── incident-commander/
│   │   ├── legal-counsel/
│   │   ├── safety-officer/
│   │   └── liaison-officer/
│   ├── operations/           # Tactical DFIR work
│   │   ├── ops-chief/
│   │   ├── triage-branch/
│   │   ├── forensics-branch/
│   │   ├── memory-branch/
│   │   ├── network-branch/
│   │   └── malware-branch/
│   ├── planning/             # Situational awareness + documentation
│   │   ├── planning-chief/
│   │   ├── situation-unit/   # Shared COP — the swarm's memory
│   │   ├── timeline-unit/
│   │   └── documentation-unit/
│   ├── logistics/            # Tool routing + evidence integrity
│   │   ├── logistics-chief/
│   │   ├── tool-broker/      # ONLY skill with MCP write access
│   │   └── evidence-store/
│   └── finance-admin/        # Audit trail + cost tracking
│       ├── audit-log/
│       └── token-budget/
├── mcp-server/               # Custom MCP server wrapping SIFT tools
└── config/
    └── openclaw.json         # Model routing + provider config
```

## Architectural Guarantees

1. **Unity of Command** — Each skill reports to exactly one superior skill
2. **Evidence Integrity is Architectural, Not Prompted** — Only `logistics/tool-broker` can invoke the MCP server. All other skills submit structured requests to it. Branch agents cannot directly execute commands.
3. **Read-Only COP** — `planning/situation-unit` owns the shared state. All other skills read from it; only Situation Unit writes to it (with audit-log mirroring).
4. **Legal Privilege Isolation** — `command-staff/legal-counsel` writes to a separate privileged log that is not merged with the general incident log.
5. **Full Audit Trail** — `finance-admin/audit-log` receives a copy of every inter-skill message and every MCP tool call with timestamps.

## How OpenClaw Loads This

OpenClaw discovers skills by scanning the skills directory. Each SKILL.md is a manifest declaring:
- **Triggers**: when this skill should activate
- **Inputs**: what structured data it expects
- **Outputs**: what structured data it produces
- **Permissions**: what other skills / tools it may invoke

The top-level IC skill is the entry point. All other skills are invoked through the chain of command.

## Model Tiering

| Tier | Skills | Model |
|---|---|---|
| Command (strategic) | IC, Legal Counsel | Claude Opus 4.7 |
| Section Chiefs | Ops Chief, Planning Chief | Claude Sonnet 4.6 |
| Branch / Specialist | Forensics, Memory, Network, Malware | Claude Sonnet 4.6 |
| Support / Fast | Triage, Tool Broker, Audit Log | Claude Haiku 4.5 |

Configuration lives in `config/openclaw.json`.
