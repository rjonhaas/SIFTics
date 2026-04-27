# Deployment Notes — Findings From First Real Boot

These notes capture concrete issues found when the project was first taken from
"design complete, no actual run yet" to "boot all the way through the MCP
server and pre-flight against real evidence." Status as of 2026-04-26.

## What works end-to-end

- MCP server builds, registers all 45 tools, and serves them over stdio.
- 72/72 unit tests pass.
- PathGuard, ReadOnlyGuard, HashRegistry, and the post-execution evidence-hash
  recheck all run on every tool call.
- Evidence manifest loader (`EVIDENCE_MANIFEST` env var, defaulting to
  `${EVIDENCE_MOUNT}/manifest.json`) registers each entry with `MountManager`
  and baselines its SHA-256 in `HashRegistry` at startup.
- `vol` Volatility 3 binary on PATH; PDB resolution via Microsoft Symbol Server
  works for the SRL-2018 Windows hosts. No Linux symbol packs needed for that
  case (all six hosts are Windows).
- `scripts/preflight.mjs` reports go/no-go with specific failure causes.
- `scripts/build-directive.mjs` produces the IC's input JSON from the manifest.

## What was broken in the shipped repo and is now fixed

1. **`tsc` output path mismatch.** `tsconfig.json` has `rootDir: "."` and
   includes both `src/**/*.ts` and `test/**/*.ts`, so the build emits
   `dist/src/index.js` and `dist/test/...`, not the `dist/index.js` the
   `package.json` `start` script and `config/openclaw.json` referenced.
   Updated both pointers to `dist/src/index.js`.

2. **`isError` was always true on success.** `mcp-server/src/index.ts` checked
   `result.status === "success"` to decide whether to set `isError: false`,
   but tool handlers return raw shapes like
   `{ executionId, samplePath, mimeType, ... }` and throw on error — they
   never set `status`. Every successful call was being reported as an error
   to the MCP client, and the post-execution hash check was silently
   skipped. Replaced with a try/catch-driven flow: success returns the
   handler's data with `isError: false`; thrown errors fall through to the
   existing catch.

3. **`HashRegistry.computeHash` cannot read files >2 GiB.** It used
   `fs.readFile`, which throws `ERR_FS_FILE_TOO_LARGE` for anything past
   2 GiB. The SRL-2018 evidence is six 5 GB memory dumps and a 9 GB AV
   memory dump. Replaced with a streaming `pipeline(createReadStream(),
   createHash("sha256"))` that handles arbitrary sizes.

## What is still a real blocker

### 1. OpenClaw schema mismatch

`config/openclaw.json` was authored against an aspirational OpenClaw
schema that does not match what the actual `openclaw` npm package
(2026.4.24) accepts. Concretely, OpenClaw rejects nearly every top-level
key in the shipped config:

```
agents.defaults.heartbeat: Unrecognized keys: "enabled", "interval_seconds"
gateway.bind: Invalid input (allowed: "auto", "lan", "loopback", "custom", "tailnet")
gateway.auth: Invalid input: expected object, received string
gateway: Unrecognized key: "channels"
memory: Unrecognized keys: "storage", "base_path"
<root>: Unrecognized keys: "_comment", "inference_mode",
   "inference_endpoints", "providers", "skill_provider_map",
   "mcp_servers", "skill_permissions", "safety",
   "prompt_injection_defense", "budget_caps"
```

OpenClaw 2026.4.24 is a multi-channel chat-bridge agent gateway. Its skill
model (`openclaw skills list/install/info`) is built around ClawHub-published
skills, not local SKILL.md manifests with custom permission and model-tier
fields. The 17-skill ICS hierarchy described in `CLAUDE.md` cannot be
expressed in OpenClaw's native skill model without either:

- **Reshaping the config to OpenClaw's schema** and reimplementing each ICS
  skill as a ClawHub-compatible skill, or
- **Replacing OpenClaw with a direct orchestrator** that walks the ICS
  protocol via the Anthropic SDK and treats each SKILL.md as a system
  prompt + permission set for a single Anthropic API call.

Both are real work. The second is closer to what the architecture
documents already imply — every "skill" is effectively a model invocation
with its own role, allowlist, and audit trail entry. The first preserves
the "submission uses OpenClaw as primary framework" hackathon claim more
literally; the second preserves the architectural invariants more cleanly.

The hackathon rules accept either Claude Code or OpenClaw as the primary
agentic framework. A direct Anthropic SDK orchestrator that uses the
existing 17 SKILL.md manifests as system prompts would still satisfy the
"Claude Code" path if scaffolded as a Claude Code subagent fanout, or
could be its own runtime.

### 2. `ANTHROPIC_API_KEY` not set

Pre-flight catches this. The orchestrator cannot call any LLM without it.

## Wiring the orchestrator

When you're ready to actually drive the swarm, the minimum viable
implementation is:

```
scripts/run-incident.sh
  ├─ scripts/preflight.mjs           # already implemented
  ├─ scripts/build-directive.mjs     # already implemented
  └─ scripts/dispatch.mjs            # not yet implemented
       ├─ Spawn the MCP server as a child process (stdio)
       ├─ Open an Anthropic SDK client
       ├─ For each ICS role, instantiate one Claude call with:
       │     - System prompt = SKILL.md body
       │     - Allowed tools = only those in the skill's mcp_tools list
       │     - Audit log entry recording (role, model_id, tool calls)
       ├─ Walk the IC's operational-period loop:
       │     - IC reads COP, sets objectives, tasks Section Chiefs
       │     - Section Chiefs decompose to branches
       │     - Branches submit typed requests to Tool Broker
       │     - Tool Broker (and ONLY Tool Broker) calls the MCP server
       │     - Findings flow up; Situation Unit owns the COP
       └─ Persist audit log + final report under WORKING_DIR
```

Architectural invariants from `CLAUDE.md` that the orchestrator must enforce:

- **Tool Broker is the only MCP caller.** Code-level: only the Tool Broker
  agent's tool definitions include the MCP tools; every other agent gets an
  empty tool list and must `submit_request_to_broker(...)` via a synthetic
  delegation tool.
- **Every finding cites a `tool_execution_id`.** The orchestrator validates
  this before adding any finding to the COP or final report.
- **Append-only hash-chained audit log.** Already implemented in
  `mcp-server/src/audit/audit_log.ts`; the orchestrator should write to it
  for non-MCP events (delegations, IC decisions) too.

## How to run what's there now

```bash
# 1. pre-flight (will currently fail on ANTHROPIC_API_KEY + openclaw schema)
node scripts/preflight.mjs

# 2. show the directive that would go to the IC
node scripts/build-directive.mjs --incident-id INC-001

# 3. wrapper that does both, refuses to dispatch on pre-flight failure unless
#    --dry-run is passed
scripts/run-incident.sh --incident-id INC-SRL-2018 --dry-run

# 4. confirm MCP server boots with the SRL-2018 manifest and a tool call
#    succeeds end-to-end
cd /working && node smoke_mcp.mjs \
  /home/sansforensics/projects/SIFTics/protocol-sift-ics/mcp-server/dist/src/index.js
```

## SRL-2018 case observations

- All 7 evidence pieces are Windows memory dumps (no Linux, no actual disk
  images). `base-file-snapshot5.img` is named "snapshot" but is a VMware-style
  saved memory state — vol3 banner probe returns `ntkrnlmp.pdb` and there is
  no MBR signature at offset 0x1FE.
- Hosts: admin, av, dc, elf, file (×2 memory states), hunt — all Windows.
- Forensics Branch (disk-focused) has no work on this case. The Memory and
  Network branches will do the heavy lifting (`vol_pslist`, `vol_netscan`,
  `vol_malfind`, `vol_cmdline`).
- Evidence is bind-mounted `ro,nodev,noexec,noatime` from `/cases/SRL-2018`
  to `/mnt/evidence`. squashfs would be cleaner and produces a single
  hashable artifact, but disk space (47 GB free, 34 GB raw evidence) does
  not allow building one alongside the source. After a successful run, the
  raw evidence can be packaged into a squashfs and the raw directory removed
  to free space.
