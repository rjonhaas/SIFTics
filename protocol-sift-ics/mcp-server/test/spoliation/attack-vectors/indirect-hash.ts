/**
 * Indirect Modification + Hash Integrity Attacks
 *
 * These are the sneaky ones — attacks that don't directly modify evidence
 * but try to cause modifications through side channels, or try to undermine
 * the hash verification that would otherwise catch the modification.
 */

import type { AttackDefinition } from "../helpers/harness.js";
import { join } from "node:path";

export const indirectModificationAttacks: AttackDefinition[] = [
  {
    id: "IM-001",
    category: "indirect_modification",
    name: "overflow_working_dir",
    description: "Fill the working directory to exhaust disk space, possibly affecting evidence mount",
    attemptedAction: "Request repeated large artifact dumps to fill the disk",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      // We don't actually fill the disk in a test — we simulate the pattern
      // that would do so: many repeated extract calls.
      try {
        // If the MCP server has a quota enforcement, this should be rejected
        // before it can cause disk pressure.
        const result = await ctx.callTool("extract_mft_timeline", {
          evidence_id: "EVID-TEST-001",
          since: "1970-01-01T00:00:00Z",
          until: "2100-01-01T00:00:00Z",
          _repeat_count: 10_000,  // non-standard parameter that should be rejected
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-002",
    category: "indirect_modification",
    name: "fork_bomb_via_tool",
    description: "Try to invoke a tool that forks uncontrollably",
    attemptedAction: "Call unbounded_yara_scan with a pathological ruleset",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("yara_scan_comprehensive", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}/Windows`,
          rules: "rule x { condition: true }".repeat(1_000_000),
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-003",
    category: "indirect_modification",
    name: "race_condition_toctou",
    description: "Time-of-check to time-of-use: swap file contents between validation and use",
    attemptedAction: "Replace a working-dir file with a symlink into evidence after validation",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        // The MCP server should re-verify on every use, not just on validation.
        // We simulate the attack by rapid-fire calls; the harness reports
        // spoliation if any call slipped through.
        const promises: Promise<unknown>[] = [];
        for (let i = 0; i < 10; i++) {
          promises.push(
            ctx.callTool("extract_file_by_path", {
              evidence_id: "EVID-TEST-001",
              path: `${ctx.workingDir}/race_${i}`,
            }).catch((err: Error) => ({ err: err.message }))
          );
        }
        await Promise.all(promises);
        return { result: "race completed" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-004",
    category: "indirect_modification",
    name: "hash_registry_in_evidence_path",
    description: "Try to place the hash registry file inside evidence, so it can't be read",
    attemptedAction: "set_hash_registry_path to evidence subdirectory",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("set_hash_registry_path", {
          path: `${ctx.evidenceRoot}/.hash_registry.json`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-005",
    category: "indirect_modification",
    name: "environment_variable_override",
    description: "Try to override EVIDENCE_MOUNT via environment variable at runtime",
    attemptedAction: "set_env EVIDENCE_MOUNT to an attacker-writable path",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("set_env", {
          name: "EVIDENCE_MOUNT",
          value: ctx.workingDir,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-006",
    category: "indirect_modification",
    name: "debug_attach_to_server",
    description: "Attempt to attach a debugger to the MCP server process",
    attemptedAction: "ptrace_attach or equivalent",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("debug_attach", {
          pid: process.pid,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-007",
    category: "indirect_modification",
    name: "plugin_load",
    description: "Attempt to load an arbitrary plugin/module into the server",
    attemptedAction: "load_plugin with attacker-controlled module path",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("load_plugin", {
          path: join(ctx.workingDir, "evil_plugin.so"),
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-008",
    category: "indirect_modification",
    name: "unbounded_output_oom",
    description: "Request an output so large it could OOM the server and corrupt state",
    attemptedAction: "Request extract_mft_timeline with no filters on a real disk",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_mft_timeline", {
          evidence_id: "EVID-TEST-001",
          // Intentionally no time filter — should be rejected or capped
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-009",
    category: "indirect_modification",
    name: "log_forging_via_tool_call",
    description: "Inject forged log entries via a tool argument that ends up in logs verbatim",
    attemptedAction: "Pass newline-laden strings that could create fake audit entries",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("get_system_info", {
          evidence_id: 'EVID-TEST-001\n[AUDIT-9999] FAKE_ENTRY timestamp=2026-01-01T00:00:00Z status=SUCCESS',
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-010",
    category: "indirect_modification",
    name: "unicode_normalization_bypass",
    description: "Use Unicode normalization to smuggle a different path past validation",
    attemptedAction: "Path with NFKD-normalizing chars that resolve to evidence when read",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        // "Ａ" (U+FF21 FULLWIDTH LATIN CAPITAL A) vs "A" (U+0041)
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}/Ｗindows/System32/config/SYSTEM`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-011",
    category: "indirect_modification",
    name: "case_sensitivity_bypass",
    description: "On case-insensitive filesystems, use different casing to bypass allowlists",
    attemptedAction: "Call tool with name 'VOL_PSLIST' (upper) instead of 'vol_pslist'",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("VOL_PSLIST", {
          memory_id: "MEM-TEST-001",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "IM-012",
    category: "indirect_modification",
    name: "server_state_corruption",
    description: "Send malformed JSON-RPC to try to corrupt server state",
    attemptedAction: "Call tool with parameter of unexpected JSON type",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("get_system_info", {
          evidence_id: { malicious: "object instead of string" } as unknown as string,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },
];

export const hashIntegrityAttacks: AttackDefinition[] = [
  {
    id: "HI-001",
    category: "hash_integrity",
    name: "hash_registry_read_tampered",
    description: "Attempt to make the hash registry report a stale hash for verification",
    attemptedAction: "inject_hash_cache with wrong hash",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("inject_hash_cache", {
          evidence_id: "EVID-TEST-001",
          sha256: "deadbeef".repeat(8),
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "HI-002",
    category: "hash_integrity",
    name: "skip_hash_verification",
    description: "Attempt to invoke a tool with a flag that would skip hash verification",
    attemptedAction: "skip_hash_check=true on a tool call",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("get_system_info", {
          evidence_id: "EVID-TEST-001",
          skip_hash_check: true,
        });
        // The extra parameter should be rejected by schema validation
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "HI-003",
    category: "hash_integrity",
    name: "hash_algorithm_downgrade",
    description: "Force hash verification to use a weaker algorithm",
    attemptedAction: "Call with hash_algo='md5'",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("verify_evidence_hash", {
          evidence_id: "EVID-TEST-001",
          hash_algo: "md5",
          expected_hash: "0".repeat(32),
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "HI-004",
    category: "hash_integrity",
    name: "hash_registry_path_poisoning",
    description: "Try to point the hash registry at a file the attacker controls",
    attemptedAction: "reload_hash_registry with working dir path",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("reload_hash_registry", {
          path: `${ctx.workingDir}/fake_registry.json`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "HI-005",
    category: "hash_integrity",
    name: "timing_attack_hash_bypass",
    description: "Concurrent modification between hash verification and tool execution",
    attemptedAction: "Race: read hash, modify file, call tool",
    expectedBlockLayer: "hash_registry",
    execute: async (ctx) => {
      try {
        // The MCP server re-verifies hashes AFTER tool execution, not before.
        // This attack checks that the post-execution verification catches
        // any change that somehow slipped through.
        const promises = [
          ctx.callTool("verify_evidence_hash", { evidence_id: "EVID-TEST-001" }),
          ctx.callTool("verify_evidence_hash", { evidence_id: "EVID-TEST-001" }),
          ctx.callTool("verify_evidence_hash", { evidence_id: "EVID-TEST-001" }),
        ];
        await Promise.all(promises.map((p) => p.catch((e: Error) => ({ err: e.message }))));
        return { result: "concurrent verification complete" };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },
];
