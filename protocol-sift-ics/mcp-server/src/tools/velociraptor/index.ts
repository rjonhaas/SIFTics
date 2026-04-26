/**
 * Registers all Velociraptor Offline Collector parsing tools with the MCP server.
 *
 * Called from src/index.ts as `registerVelociraptorTools(toolRegistry, ctx)`.
 *
 * Tools:
 *   - parse_collection             Open a VR Offline Collector zip, return a manifest
 *   - vr_extract_unified_log       macOS Unified Log entries
 *   - vr_extract_persistence       LaunchAgents/Daemons (Mac) + Run/Services/Tasks (Win), normalized
 *   - vr_extract_browser_history   Safari/Chrome/Edge/Firefox visits, normalized
 *   - vr_extract_filesystem_metadata  File metadata (timestamps, sizes, hashes) cross-OS
 *   - vr_extract_knowledgec        macOS KnowledgeC.db app activity
 *   - vr_list_users                User enumeration cross-OS
 */

import {
  parseCollection, PARSE_COLLECTION_SCHEMA,
  vrExtractUnifiedLog, VR_EXTRACT_UNIFIED_LOG_SCHEMA,
  vrExtractPersistence, VR_EXTRACT_PERSISTENCE_SCHEMA,
  vrExtractBrowserHistory, VR_EXTRACT_BROWSER_HISTORY_SCHEMA,
  vrExtractFilesystemMetadata, VR_EXTRACT_FILESYSTEM_METADATA_SCHEMA,
  vrExtractKnowledgeC, VR_EXTRACT_KNOWLEDGEC_SCHEMA,
  vrListUsers, VR_LIST_USERS_SCHEMA,
} from "./parsers.js";

import type { ToolContext, VelociraptorCollectionResolver } from "./collection.js";
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

export function registerVelociraptorTools(
  registry: Map<string, ToolHandler>,
  serverCtx: ServerContext
): void {
  const ctx: ToolContext = {
    pathGuard: serverCtx.pathGuard,
    readOnlyGuard: serverCtx.readOnlyGuard,
  };
  const resolver: VelociraptorCollectionResolver = serverCtx.mountManager;

  registry.set("parse_collection", {
    name: "parse_collection",
    description:
      "Open a Velociraptor Offline Collector collection (already extracted to a read-only " +
      "evidence path) and return a structured manifest: host info, OS family, list of " +
      "collected artifacts (with row counts), and uploaded files. Always call this first " +
      "on a new collection_id to discover what data is available before issuing targeted " +
      "extraction calls.",
    inputSchema: PARSE_COLLECTION_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => parseCollection(args as never, ctx, resolver),
  });

  registry.set("vr_extract_unified_log", {
    name: "vr_extract_unified_log",
    description:
      "Read macOS Unified Log entries from a Velociraptor collection. Optional time range " +
      "filtering via since/until (ISO8601). Use as the closest Mac-side equivalent of " +
      "Windows event logs for runtime activity reconstruction. Returns up to max_rows " +
      "(default 50000) and spills to an artifact file when the result exceeds the inline cap.",
    inputSchema: VR_EXTRACT_UNIFIED_LOG_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => vrExtractUnifiedLog(args as never, ctx, resolver),
  });

  registry.set("vr_extract_persistence", {
    name: "vr_extract_persistence",
    description:
      "Extract persistence mechanisms in a normalized cross-OS shape. Windows hosts return " +
      "Run keys, services, scheduled tasks, and WMI subscriptions. macOS hosts return " +
      "LaunchAgents, LaunchDaemons, and login items. Linux hosts return systemd units and " +
      "cron entries. Use os_filter to restrict by OS when the collection contains multi-host " +
      "data; omit to get everything.",
    inputSchema: VR_EXTRACT_PERSISTENCE_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => vrExtractPersistence(args as never, ctx, resolver),
  });

  registry.set("vr_extract_browser_history", {
    name: "vr_extract_browser_history",
    description:
      "Extract browser history from a Velociraptor collection. Safari, Chrome, Edge, and " +
      "Firefox sqlite stores are normalized into the same visit shape (url, title, " +
      "visit_time, visit_count). Optional browser= and user= filters. Returns up to " +
      "max_rows (default 20000) inline; spills excess to an artifact file.",
    inputSchema: VR_EXTRACT_BROWSER_HISTORY_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => vrExtractBrowserHistory(args as never, ctx, resolver),
  });

  registry.set("vr_extract_filesystem_metadata", {
    name: "vr_extract_filesystem_metadata",
    description:
      "File metadata from a Velociraptor file-finder artifact: path, size, MAC times, " +
      "btime where available, mode/uid/gid, and SHA256 if Velociraptor was configured to " +
      "hash. Optional path_filter substring match. Cross-OS: returns whichever artifact " +
      "the collection happened to include.",
    inputSchema: VR_EXTRACT_FILESYSTEM_METADATA_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => vrExtractFilesystemMetadata(args as never, ctx, resolver),
  });

  registry.set("vr_extract_knowledgec", {
    name: "vr_extract_knowledgec",
    description:
      "macOS KnowledgeC.db entries (app focus, usage durations, screen-on episodes). " +
      "Closest macOS equivalent to Windows SRUM/BAM for user activity timelines. " +
      "Returns empty if the collection did not include a KnowledgeC artifact.",
    inputSchema: VR_EXTRACT_KNOWLEDGEC_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => vrExtractKnowledgeC(args as never, ctx, resolver),
  });

  registry.set("vr_list_users", {
    name: "vr_list_users",
    description:
      "Enumerate user accounts in a normalized shape across Windows, macOS, and Linux: " +
      "username, uid, home_dir, shell, last_login, is_admin, is_disabled. Always cheap; " +
      "useful as a sanity check before correlating per-user artifacts (browser history, " +
      "persistence under HKCU, LaunchAgents under ~/Library).",
    inputSchema: VR_LIST_USERS_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => vrListUsers(args as never, ctx, resolver),
  });
}
