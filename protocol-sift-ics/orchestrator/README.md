# Protocol SIFT Orchestrator

Claude Code subagent runtime for the ICS swarm. Replaces OpenClaw 2026.4.24, which did not natively support the multi-agent ICS hierarchy. The skills directory and MCP server are unchanged — this orchestrator is the runtime layer that hosts them and enforces architectural invariants.

## Layout

```
src/
  index.ts                       CLI entry
  directive_loader.ts            parses incident directive (YAML/JSON)
  skill_loader.ts                reads SKILL.md frontmatter, builds subagent configs
  operational_period.ts          period loop: IC objectives → delegation → rollup
  routing.ts                     enforces Tool Broker exclusivity + COP write isolation
  subagent.ts                    Anthropic SDK call per skill activation
  mcp_client.ts                  MCP child-process driver (Tool Broker uses this)
  persistence/
    cop_store.ts                 Situation Unit's COP — JSON file per period
    audit_log.ts                 append-only JSONL with hash chain
    period_state.ts              IC's reasoning, active branches, rollups
    inter_skill_messages.ts      routing log
  safety/
    safety_mirror.ts             synchronous Safety Officer pre-execution check
test/
  routing.test.ts                Tool Broker exclusivity + COP isolation tests
```

## Architectural enforcement (in code, not in prompts)

These three properties are enforced by the orchestrator's routing layer, not by skill instructions:

1. **Tool Broker exclusivity.** Only the `logistics/tool-broker` subagent receives MCP tool definitions. Every other skill receives a `submit_tool_request` synthetic tool. The orchestrator captures the typed request and dispatches it to the broker.
2. **COP write isolation.** The COP store rejects writes from any subagent other than `planning/situation-unit`. Reads are unrestricted.
3. **Audit log append-only with hash chain.** Each entry hashes the prior. Out-of-order or backdated writes are rejected.

## Invocation

```bash
node dist/src/index.js \
  --directive=cases/<id>/directive.yaml \
  --evidence-mount=/mnt/evidence \
  --case-dir=cases/<id> \
  [--resume-from=<period_id>] \
  [--dry-run]
```

`--dry-run` skips Anthropic SDK calls; useful for verifying routing + selective activation logic without burning tokens or needing an API key.

## Models

| Skill tier | Model |
|------------|-------|
| `command` (IC, Legal) | `claude-opus-4-7` |
| `section_chief` (Ops Chief, Plan Chief, Logistics Chief, Section heads) | `claude-sonnet-4-6` |
| `specialist` (branch agents, units) | `claude-sonnet-4-6` |
| `fast` (Triage, Tool Broker, Audit, Token Budget) | `claude-haiku-4-5` |

`temperature=0` for every call. Reproducibility is required for forensic soundness.

## Period budget

Hard cap of 4 operational periods per case. If the IC has not converged on a coherent narrative by period 4, the orchestrator emits the best-available report and exits. This is the structural answer to the multi-agent handoff-cliff failure mode.
