/**
 * Write Attempt Attacks
 *
 * Every write-class operation must be rejected by the MCP server because
 * the MCP server does not expose write functions on evidence. These attacks
 * verify that assumption directly.
 *
 * If the server returns a success result for any of these, the architecture
 * is broken and the submission's core claim fails.
 */

import type { AttackDefinition } from "../helpers/harness.js";
import { join } from "node:path";

export const writeAttemptAttacks: AttackDefinition[] = [
  {
    id: "WA-001",
    category: "write_attempts",
    name: "no_shell_exec_function",
    description: "Attempt to call a shell exec function that should not exist",
    attemptedAction: "Call exec_shell with 'rm -rf evidence'",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("exec_shell", {
          command: `rm -rf ${ctx.evidenceRoot}`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-002",
    category: "write_attempts",
    name: "no_run_command_function",
    description: "Variant: run_command should not exist",
    attemptedAction: "Call run_command with 'dd if=/dev/zero of=evidence/file'",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("run_command", {
          cmd: "dd",
          args: ["if=/dev/zero", `of=${ctx.evidenceRoot}/Windows/System32/config/SYSTEM`],
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-003",
    category: "write_attempts",
    name: "no_eval_function",
    description: "eval-class function should not exist",
    attemptedAction: "Call eval with a write expression",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("eval", {
          expression: `require('fs').writeFileSync('${ctx.evidenceRoot}/owned', 'x')`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-004",
    category: "write_attempts",
    name: "no_write_file_function",
    description: "write_file function should not exist",
    attemptedAction: "Call write_file to create a new file in evidence",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("write_file", {
          path: `${ctx.evidenceRoot}/newfile.txt`,
          content: "attacker",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-005",
    category: "write_attempts",
    name: "no_delete_file_function",
    description: "delete_file / remove_file function should not exist",
    attemptedAction: "Call delete_file on an evidence file",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("delete_file", {
          path: `${ctx.evidenceRoot}/Windows/System32/config/SYSTEM`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-006",
    category: "write_attempts",
    name: "no_move_file_function",
    description: "move/rename function should not exist",
    attemptedAction: "Call move_file to rename an evidence file",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("move_file", {
          src: `${ctx.evidenceRoot}/Windows/System32/config/SYSTEM`,
          dst: `${ctx.evidenceRoot}/Windows/System32/config/SYSTEM.bak`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-007",
    category: "write_attempts",
    name: "no_chmod_function",
    description: "chmod function should not exist",
    attemptedAction: "Call chmod to make evidence writable",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("chmod", {
          path: ctx.evidenceRoot,
          mode: "0777",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-008",
    category: "write_attempts",
    name: "no_chown_function",
    description: "chown function should not exist",
    attemptedAction: "Call chown on evidence",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("chown", {
          path: ctx.evidenceRoot,
          uid: 0,
          gid: 0,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-009",
    category: "write_attempts",
    name: "extract_file_rejects_evidence_output",
    description: "extract_file_by_path must refuse to write extracted output INTO evidence",
    attemptedAction: "Call extract_file_by_path with output inside EVIDENCE_MOUNT",
    expectedBlockLayer: "path_guard",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("extract_file_by_path", {
          evidence_id: "EVID-TEST-001",
          path: `${ctx.evidenceRoot}/Windows/System32/config/SYSTEM`,
          output_path: `${ctx.evidenceRoot}/extracted/SYSTEM.copy`,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-010",
    category: "write_attempts",
    name: "no_mount_function",
    description: "mount function should not be exposed (Evidence Store handles mounts)",
    attemptedAction: "Call mount to remount evidence as rw",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("mount", {
          source: "evidence",
          target: ctx.evidenceRoot,
          options: "rw,remount",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-011",
    category: "write_attempts",
    name: "no_umount_function",
    description: "umount function should not be exposed",
    attemptedAction: "Call umount on evidence mount",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("umount", {
          target: ctx.evidenceRoot,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-012",
    category: "write_attempts",
    name: "no_raw_volatility_command",
    description: "Volatility wrapper should not accept raw arbitrary plugin with arbitrary args",
    attemptedAction: "vol_raw with plugin='linux.bash.Bash' and attacker-controlled args",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("vol_raw", {
          args: ["--write", ctx.evidenceRoot],
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-013",
    category: "write_attempts",
    name: "registry_write_attempt",
    description: "Attempt to call a 'set' function on registry",
    attemptedAction: "set_registry_key to modify a value in evidence hive",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("set_registry_key", {
          evidence_id: "EVID-TEST-001",
          hive: "SYSTEM",
          key_path: "ControlSet001\\Services\\Pwned",
          value: "attacker",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-014",
    category: "write_attempts",
    name: "registry_delete_attempt",
    description: "Attempt to delete a registry value",
    attemptedAction: "delete_registry_key in evidence hive",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("delete_registry_key", {
          evidence_id: "EVID-TEST-001",
          hive: "SYSTEM",
          key_path: "ControlSet001\\Services",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-015",
    category: "write_attempts",
    name: "event_log_clear_attempt",
    description: "Attempt to clear an event log",
    attemptedAction: "clear_event_log on Security.evtx",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("clear_event_log", {
          evidence_id: "EVID-TEST-001",
          log_name: "Security",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-016",
    category: "write_attempts",
    name: "mft_write_attempt",
    description: "Attempt to modify MFT records",
    attemptedAction: "modify_mft_record",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("modify_mft_record", {
          evidence_id: "EVID-TEST-001",
          record_number: 42,
          new_data: {},
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-017",
    category: "write_attempts",
    name: "memory_write_attempt",
    description: "Attempt to write to a memory dump",
    attemptedAction: "write_memory_region",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("write_memory_region", {
          memory_id: "MEM-TEST-001",
          offset: 0,
          bytes: "41414141",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-018",
    category: "write_attempts",
    name: "pcap_truncate_attempt",
    description: "Attempt to truncate a PCAP file",
    attemptedAction: "truncate_pcap",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("truncate_pcap", {
          pcap_id: "PCAP-TEST-001",
          new_size: 0,
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-019",
    category: "write_attempts",
    name: "inject_pcap_packet",
    description: "Attempt to inject a fake packet into a PCAP",
    attemptedAction: "inject_packet",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("inject_packet", {
          pcap_id: "PCAP-TEST-001",
          packet_hex: "...",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-020",
    category: "write_attempts",
    name: "hash_registry_override",
    description: "Attempt to overwrite the hash registry entry for evidence",
    attemptedAction: "set_hash_registry",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("set_hash_registry", {
          evidence_id: "EVID-TEST-001",
          sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-021",
    category: "write_attempts",
    name: "tool_name_injection",
    description: "Tool name contains shell metacharacters",
    attemptedAction: "Call tool with name 'vol_pslist; rm -rf /evidence'",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("vol_pslist; rm -rf /evidence", {
          memory_id: "MEM-TEST-001",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-022",
    category: "write_attempts",
    name: "parameter_command_injection",
    description: "Inject shell metacharacters into a typed parameter",
    attemptedAction: "evidence_id='EVID-TEST-001; rm -rf /evidence'",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("get_system_info", {
          evidence_id: "EVID-TEST-001; rm -rf /evidence",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-023",
    category: "write_attempts",
    name: "backtick_substitution",
    description: "Backtick command substitution in a parameter",
    attemptedAction: "evidence_id='`touch /tmp/pwned`'",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("get_system_info", {
          evidence_id: "`touch " + join(ctx.evidenceRoot, "pwned") + "`",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },

  {
    id: "WA-024",
    category: "write_attempts",
    name: "dollar_paren_substitution",
    description: "$(cmd) command substitution in a parameter",
    attemptedAction: "evidence_id='$(touch /tmp/pwned)'",
    expectedBlockLayer: "mcp_server",
    execute: async (ctx) => {
      try {
        const result = await ctx.callTool("get_system_info", {
          evidence_id: "$(touch " + join(ctx.evidenceRoot, "pwned") + ")",
        });
        return { result };
      } catch (err) {
        return { thrown: err as Error };
      }
    },
  },
];
