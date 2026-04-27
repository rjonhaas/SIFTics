# Deployment Notes — Runtime Migration

## Why this project does not run on OpenClaw

The shipped OpenClaw 2026.4.24 schema is a chat-bridge gateway with ClawHub-published skills. It is structured for individual skills routed through a single gateway, not for hierarchical multi-agent orchestration with structured handoffs and routing-layer enforcement of architectural invariants.

Specifically, OpenClaw 2026.4.24 does not natively express:

- Per-skill model tiering (different models for different roles)
- Hierarchical delegation (IC → Section Chief → Branch)
- COP write isolation (only Situation Unit writes; all others read)
- Tool Broker exclusivity (only one skill has MCP access)
- Safety Officer mirroring (synchronous pre-execution check on every tool call)
- Operational period boundaries (state checkpointing between cycles)

Reshaping skills into OpenClaw 2026.4.24's schema would have moved enforcement of these properties from the runtime layer to skill system prompts, making them prompt-based rather than architectural. This is a measurable regression on architectural-evidence-integrity claims and on the Constraint Implementation judging criterion.

Additionally, OpenClaw's CVE situation between February and April 2026 (137 advisories, including CVSS 9.9 token rotation flaws and HITL approval bypasses) means OpenClaw is not the right foundation for evidence-integrity-critical work, regardless of schema fit.

## Why Claude Code subagents instead

Claude Code's subagent model maps directly onto the ICS architecture:

- Subagents run in isolated context windows (matches per-skill context isolation)
- Per-subagent tool allowlists (matches per-skill MCP permissions)
- Hierarchical delegation through the orchestrating session (matches IC → Section Chief → Branch)
- MCP server discovery and invocation are first-class (the existing typed-function interface stays)
- Maintained by Anthropic with enterprise-grade security cadence

The skills directory and MCP server transitioned to the new runtime without modification. The 17 SKILL.md files become subagent definitions. The MCP server remains the typed-function interface. The orchestrator is a thin layer that loads skills, manages the operational period loop, enforces architectural invariants at the routing layer, and persists state between periods.

## Runtime portability

This migration validates the architecture's runtime-portability principle. The skills and MCP server are the durable artifacts. The runtime is replaceable. Future deployments could target:

- Claude Code subagents (current, hackathon submission)
- LangGraph (better persistence primitives, comparable architectural fit)
- Microsoft Agent Framework (enterprise .NET deployments)
- Bedrock Agents (HIPAA-eligible managed inference)
- Direct Anthropic SDK orchestrator (air-gapped or sovereignty-restricted)

The choice is deployment-time configuration, not architectural commitment.

## What is implemented in this migration

In `orchestrator/`:

- `src/skill_loader.ts` — reads all 17 SKILL.md files and parses YAML frontmatter (`name`, `model_tier`, `reports_to`, `supervises`, `permissions`, including the nested `permissions.mcp_tools` shape used by branch skills). Body is preserved verbatim as the subagent's system prompt.
- `src/routing.ts` — Tool Broker exclusivity, COP write isolation, per-skill MCP allowlist enforcement, and delegation-graph checks. **All in code, not in subagent prompts.**
- `src/persistence/audit_log.ts` — append-only JSONL with SHA-256 hash chain. Replays on open and rejects tamper.
- `src/persistence/cop_store.ts` — JSON file per operational period. All writes go through Router.authorizeCopWrite — only Situation Unit succeeds.
- `src/persistence/period_state.ts` — IC's reasoning, active branch list, rollups per period. Drives `--resume-from`.
- `src/persistence/inter_skill_messages.ts` — routing log of every delegation and tool request.
- `src/safety/safety_mirror.ts` — synchronous pre-execution Safety Officer check, default 200ms window, clear/flag/halt outcomes (timeout = flag + proceed per CLAUDE.md invariant #7).
- `src/operational_period.ts` — period loop with selective branch activation. Hard cap of 4 periods.
- `src/subagent.ts` — one Anthropic API call per skill activation, `temperature=0`, model selected by `model_tier`. Defines the `submit_tool_request` synthetic tool that non-broker skills receive.
- `src/mcp_client.ts` — drives the existing MCP server (unchanged) over stdio.
- `src/directive_loader.ts` — parses incident directive YAML or JSON.
- `src/index.ts` — CLI entry. `--directive --evidence-mount --case-dir [--resume-from] [--dry-run]`.
- `test/routing.test.ts` — eight tests, all passing, that exercise Tool Broker exclusivity, allowlist enforcement, COP write isolation, COP read-open, identity-forgery rejection, and delegation-graph checks against the real shipped SKILL.md files.

## What is not yet implemented

- The live invocation path inside `OperationalPeriodLoop.runPeriod` — wiring branch subagent invocations, capturing `submit_tool_request` emissions, dispatching to the broker subagent, returning structured tool results, and aggregating findings into rollups. The seam exists; the production loop is the next milestone. `--dry-run` exercises every other code path.
- Anthropic SDK live invocation has not been smoke-tested (no API key in this environment).
- Spoliation harness extension for the new RR-001..RR-006 routing-attack vectors (file added at `mcp-server/test/spoliation/attack-vectors/runtime-routing.ts`; integration into the spoliation runner is the remaining work).
- `CYBER_ICS_FRAMEWORK.md` does not exist in this repo — the migration spec referenced it. Skipped.

## Architectural invariant cross-walk

| Invariant | Where enforced |
|---|---|
| Only Tool Broker invokes MCP (#1) | `routing.ts` — `Router.authorizeMcpInvocation` |
| Evidence read-only (#2) | MCP server `ReadOnlyGuard` (unchanged) + bind mount `ro,nodev,noexec,noatime` |
| PathGuard (#3) | MCP server `PathGuard` (unchanged) |
| Findings cite execution_id (#4) | `cop_store.ts` Finding type requires `executionId`; the orchestrator validates before COP write |
| Situation Unit owns COP (#5) | `routing.ts` — `Router.authorizeCopWrite` |
| Legal advisories isolated (#6) | Audit log discriminates `kind`; legal log is a separate append target (out-of-scope of this migration) |
| Safety Officer HALT (#7) | `safety/safety_mirror.ts` — 200ms timeout, flag-on-timeout |
| Content is data, not instructions (#8) | MCP server typed parsing (unchanged) |
| Irreversible actions HITL (#9) | Orchestrator does not execute irreversible actions; surfaces only |
| Audit log hash chain (#10) | `persistence/audit_log.ts` |
| Mac memory platform-conditional (#11) | Memory Branch SKILL.md (unchanged) |
| Inference endpoint deployment-time (#12) | `subagent.ts` resolves model from tier; orchestrator-wide configuration |
| Safety Officer runtime integrity (#13) | Safety Officer SKILL.md (unchanged); `runtime_inventory` MCP tool restricted |
| Selective activation (#14, new) | `operational_period.ts` — `selectBranches` |
| Runtime is replaceable (#15, new) | This migration is the proof |

## How to run

```bash
# Build
cd orchestrator && npm install && npm run build

# Routing tests (no API key needed)
npm test

# Dry run end-to-end against SRL-2018 (no API key needed)
node dist/src/index.js \
  --directive=../scripts/.directive-INC-SRL-2018.json \
  --evidence-mount=/mnt/evidence \
  --case-dir=/working/cases/SRL-2018 \
  --dry-run

# Live run (requires ANTHROPIC_API_KEY and the live-loop wiring above)
ANTHROPIC_API_KEY=sk-ant-... node dist/src/index.js \
  --directive=cases/SRL-2018/directive.json \
  --evidence-mount=/mnt/evidence \
  --case-dir=cases/SRL-2018
```
