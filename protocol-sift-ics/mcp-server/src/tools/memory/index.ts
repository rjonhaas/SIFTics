/**
 * Registers all memory analysis tools with the MCP server.
 *
 * Called from src/index.ts as `registerMemoryTools(toolRegistry, ctx)`.
 */

import {
  volPsList, VOL_PSLIST_SCHEMA,
  volPsTree, VOL_PSTREE_SCHEMA,
  volPsScan, VOL_PSSCAN_SCHEMA,
  volCmdLine, VOL_CMDLINE_SCHEMA,
  volMalfind, VOL_MALFIND_SCHEMA,
  volNetScan, VOL_NETSCAN_SCHEMA,
  volInfo, VOL_INFO_SCHEMA,
} from "./plugins.js";

import type { VolatilityContext, MemoryImageResolver } from "./volatility.js";
import { DEFAULT_CONFIG } from "./volatility.js";

import type { PathGuard } from "../../safety/path_guard.js";
import type { ReadOnlyGuard } from "../../safety/readonly_guard.js";
import type { MountManager } from "../../evidence/mount_manager.js";
import type { HashRegistry } from "../../evidence/hash_registry.js";

// Tool registry signature shared with src/index.ts
interface ToolHandler {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

interface ServerContext {
  pathGuard: PathGuard;
  readOnlyGuard: ReadOnlyGuard;
  mountManager: MountManager;
  hashRegistry: HashRegistry;
}

export function registerMemoryTools(
  registry: Map<string, ToolHandler>,
  serverCtx: ServerContext
): void {
  const ctx: VolatilityContext = {
    pathGuard: serverCtx.pathGuard,
    readOnlyGuard: serverCtx.readOnlyGuard,
    config: DEFAULT_CONFIG,
  };
  // MountManager implements MemoryImageResolver
  const resolver: MemoryImageResolver = serverCtx.mountManager;

  registry.set("vol_info", {
    name: "vol_info",
    description: "Volatility 3 windows.info — returns OS metadata (kernel base, build version, system time) for a memory image. Always run this first on a new memory image to confirm the agent and Volatility agree on what they're looking at.",
    inputSchema: VOL_INFO_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => volInfo(args as never, ctx, resolver),
  });

  registry.set("vol_pslist", {
    name: "vol_pslist",
    description: "Volatility 3 windows.pslist — list active processes by walking the EPROCESS list. Use as the canonical process inventory. Cross-check against vol_psscan to detect hidden processes.",
    inputSchema: VOL_PSLIST_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => volPsList(args as never, ctx, resolver),
  });

  registry.set("vol_pstree", {
    name: "vol_pstree",
    description: "Volatility 3 windows.pstree — process tree showing parent/child relationships. Use to spot anomalous parent-child pairings (e.g. lsass.exe parenting cmd.exe).",
    inputSchema: VOL_PSTREE_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => volPsTree(args as never, ctx, resolver),
  });

  registry.set("vol_psscan", {
    name: "vol_psscan",
    description: "Volatility 3 windows.psscan — pool-tag scanner that finds processes the EPROCESS walk may have missed. Compare with vol_pslist to find hidden processes.",
    inputSchema: VOL_PSSCAN_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => volPsScan(args as never, ctx, resolver),
  });

  registry.set("vol_cmdline", {
    name: "vol_cmdline",
    description: "Volatility 3 windows.cmdline — full command lines for processes. Critical for spotting encoded PowerShell, LOLBin abuse, and suspicious arguments.",
    inputSchema: VOL_CMDLINE_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => volCmdLine(args as never, ctx, resolver),
  });

  registry.set("vol_malfind", {
    name: "vol_malfind",
    description: "Volatility 3 windows.malfind — finds private memory regions with PAGE_EXECUTE_READWRITE protection or MZ headers, indicating likely process injection or in-memory PE loading.",
    inputSchema: VOL_MALFIND_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => volMalfind(args as never, ctx, resolver),
  });

  registry.set("vol_netscan", {
    name: "vol_netscan",
    description: "Volatility 3 windows.netscan — network connections recovered from memory at the time of capture. Returns local/remote addr+port, state, and owning PID.",
    inputSchema: VOL_NETSCAN_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => volNetScan(args as never, ctx, resolver),
  });
}
