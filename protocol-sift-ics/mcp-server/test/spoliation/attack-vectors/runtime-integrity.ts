/**
 * Runtime Integrity Attacks
 *
 * The runtime_inventory tool is the only MCP function the Safety Officer
 * is permitted to invoke. It must be:
 *
 *   - Restricted to the Safety Officer caller (defense in depth on top of
 *     OpenClaw's mcp_tool_access permission map)
 *   - Read-only by design — no path arguments, no filters that can hide
 *     a vulnerable component from inventory
 *   - Free of any hidden bypass parameter
 *   - Replay-resistant — accepting an old approved correlation_id from a
 *     different operational period must not skip a fresh inventory check
 *   - Unable to mutate the binary hashes it reports through any side channel
 *
 * If any of these returns a success result, the Safety Officer's runtime
 * integrity role can be subverted — an attacker who controls a non-safety
 * skill could issue a fake "all clear" inventory or hide a vulnerable
 * component at operational period boundary. The architecture's runtime
 * integrity claim depends on these all being blocked.
 */

import type { AttackDefinition } from "../helpers/harness.js";

const NON_SAFETY_SKILL = "operations/forensics-branch";

export const runtimeIntegrityAttacks: AttackDefinition[] = [
  {
    id: "RI-001",
    category: "runtime_integrity",
    name: "non_safety_caller_rejected",
    description:
      "runtime_inventory must reject calls whose _caller field identifies a skill " +
      "other than command-staff/safety-officer. The OpenClaw permission layer is the " +
      "primary guard; this verifies the MCP server's defense-in-depth check fires too.",
    attemptedAction: "runtime_inventory with _caller=operations/forensics-branch",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("runtime_inventory", {
          _caller: NON_SAFETY_SKILL,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "RI-002",
    category: "runtime_integrity",
    name: "path_argument_rejected",
    description:
      "runtime_inventory takes no path arguments. The schema is additionalProperties: " +
      "false. Any path parameter must be rejected at schema validation, before any " +
      "filesystem access can be steered toward attacker-controlled locations.",
    attemptedAction: "runtime_inventory with a path argument",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("runtime_inventory", {
          path: "/etc/passwd",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "RI-003",
    category: "runtime_integrity",
    name: "bypass_flag_rejected",
    description:
      "Unknown parameters (e.g. bypass_runtime_check, skip_cve, unsafe_mode) must be " +
      "rejected by the schema rather than silently accepted. additionalProperties: false " +
      "is the architectural property; this attack confirms it.",
    attemptedAction: "runtime_inventory with bypass_runtime_check=true",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("runtime_inventory", {
          bypass_runtime_check: true,
          skip_cve: true,
          unsafe_mode: true,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "RI-004",
    category: "runtime_integrity",
    name: "correlation_id_replay_rejected",
    description:
      "Reusing an approved correlation_id from a previous operational period must not " +
      "satisfy this period's runtime check. runtime_inventory does not accept a " +
      "correlation_id field at all — every call performs a fresh inventory. Replay " +
      "via a forged or copied correlation_id should be rejected at schema validation.",
    attemptedAction: "runtime_inventory with correlation_id from a stale prior call",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("runtime_inventory", {
          _caller: "command-staff/safety-officer",
          correlation_id: "RI-CHECK-PRIOR-PERIOD-1234",
          assume_unchanged: true,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "RI-005",
    category: "runtime_integrity",
    name: "mutate_binary_hashes_via_side_channel",
    description:
      "An attacker with write capability somewhere in the working dir might attempt to " +
      "trick runtime_inventory into reporting a false hash by, e.g., placing a decoy " +
      "binary at a path the function might inspect. Verifies that runtime_inventory " +
      "uses fixed, hard-coded discovery paths for the components it reports — no " +
      "discovery_path or override_binary parameter exists, and any attempt to inject " +
      "one fails additionalProperties validation.",
    attemptedAction: "runtime_inventory with discovery_path / override_binary attacker-controlled",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("runtime_inventory", {
          _caller: "command-staff/safety-officer",
          discovery_path: `${ctx.workingDir}/attacker-decoy/`,
          override_binary: { openclaw: `${ctx.workingDir}/attacker-decoy/openclaw` },
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },
];
