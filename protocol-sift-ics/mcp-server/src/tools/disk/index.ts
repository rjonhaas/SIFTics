/**
 * Registers all disk forensics tools with the MCP server.
 *
 * Called from src/index.ts as `registerDiskTools(toolRegistry, ctx)`.
 *
 * Current tools:
 *   - parse_prefetch_summary   (Triage: fast prefetch overview)
 *   - parse_prefetch_detailed  (Forensics: full prefetch parse)
 *
 * Planned (not yet implemented):
 *   - parse_registry           Registry hive parsing (RegRipper / RECmd)
 *   - parse_mft                $MFT parsing (MFTECmd)
 *   - parse_usnjrnl            $UsnJrnl parsing (MFTECmd --usn)
 *   - parse_evtx               Windows Event Log parsing (EvtxECmd)
 *   - parse_shellbags          Shellbags parsing (SBECmd)
 *   - parse_lnk                LNK file parsing (LECmd)
 *   - parse_srum               SRUM database parsing
 *   - parse_amcache            AmCache.hve parsing
 *   - parse_browser_history    Browser history (BrowsingHistoryView)
 */

import {
  parsePrefetchSummary,
  parsePrefetchDetailed,
  PREFETCH_SUMMARY_SCHEMA,
  PREFETCH_DETAILED_SCHEMA,
} from "./prefetch.js";

import type { PathGuard } from "../../safety/path_guard.js";
import type { ReadOnlyGuard } from "../../safety/readonly_guard.js";
import type { MountManager } from "../../evidence/mount_manager.js";
import type { HashRegistry } from "../../evidence/hash_registry.js";

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

export function registerDiskTools(
  registry: Map<string, ToolHandler>,
  serverCtx: ServerContext
): void {
  const toolCtx = {
    pathGuard: serverCtx.pathGuard,
    readOnlyGuard: serverCtx.readOnlyGuard,
  };

  registry.set("parse_prefetch_summary", {
    name: "parse_prefetch_summary",
    description:
      "Parse Windows Prefetch files and return the top N most recent executions. " +
      "Designed for Triage Branch — fast summary of what ran on the host.",
    inputSchema: PREFETCH_SUMMARY_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => parsePrefetchSummary(args as never, toolCtx),
  });

  registry.set("parse_prefetch_detailed", {
    name: "parse_prefetch_detailed",
    description:
      "Full parse of Windows Prefetch data. Single-file mode returns inline; " +
      "all-files mode writes to an artifact and returns a summary + pointer. " +
      "Use for deep Forensics Branch analysis.",
    inputSchema: PREFETCH_DETAILED_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => parsePrefetchDetailed(args as never, toolCtx),
  });
}
