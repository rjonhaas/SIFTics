/**
 * Registers all disk forensics tools with the MCP server.
 *
 * Called from src/index.ts as `registerDiskTools(toolRegistry, ctx)`.
 *
 * Current tools:
 *   - parse_prefetch_summary    (Triage: fast prefetch overview)
 *   - parse_prefetch_detailed   (Forensics: full prefetch parse)
 *   - parse_event_logs          (Event log parsing with filtering)
 *   - extract_registry_hive     (Full registry hive parse)
 *   - get_run_keys              (Persistence: Run/RunOnce keys)
 *   - get_services              (Services from SYSTEM hive)
 *   - get_scheduled_tasks       (Scheduled tasks from SOFTWARE hive)
 *   - extract_mft_timeline      ($MFT to timeline with timestomp detection)
 *   - parse_usn_journal         ($UsnJrnl change log)
 *
 * Planned (not yet implemented):
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

import {
  parseEventLogs,
  PARSE_EVENT_LOGS_SCHEMA,
} from "./evtx.js";

import {
  extractRegistryHive,
  getRunKeys,
  getServices,
  getScheduledTasks,
  EXTRACT_REGISTRY_HIVE_SCHEMA,
  GET_RUN_KEYS_SCHEMA,
  GET_SERVICES_SCHEMA,
  GET_SCHEDULED_TASKS_SCHEMA,
} from "./registry.js";

import {
  extractMftTimeline,
  parseUsnJournal,
  EXTRACT_MFT_TIMELINE_SCHEMA,
  PARSE_USN_JOURNAL_SCHEMA,
} from "./mft.js";

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

  // ── Prefetch ──

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

  // ── Event Logs ──

  registry.set("parse_event_logs", {
    name: "parse_event_logs",
    description:
      "Parse Windows Event Log (.evtx) files with optional filtering by log name, " +
      "event IDs, and time range. Key IDs: 4624 (logon), 4688 (process creation), " +
      "7045 (service install), 1102 (log cleared). Supports Security, System, " +
      "Application, PowerShell, Sysmon, RDP, and custom log names.",
    inputSchema: PARSE_EVENT_LOGS_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => parseEventLogs(args as never, toolCtx),
  });

  // ── Registry ──

  registry.set("extract_registry_hive", {
    name: "extract_registry_hive",
    description:
      "Full parse of a Windows registry hive (SYSTEM, SOFTWARE, SAM, SECURITY, " +
      "NTUSER.DAT) with optional key path filtering. Returns typed key/value entries.",
    inputSchema: EXTRACT_REGISTRY_HIVE_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => extractRegistryHive(args as never, toolCtx),
  });

  registry.set("get_run_keys", {
    name: "get_run_keys",
    description:
      "Extract all Run/RunOnce persistence keys from SOFTWARE hive and all " +
      "NTUSER.DAT hives. Critical for persistence mechanism analysis.",
    inputSchema: GET_RUN_KEYS_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => getRunKeys(args as never, toolCtx),
  });

  registry.set("get_services", {
    name: "get_services",
    description:
      "Extract Windows services from the SYSTEM registry hive. Optionally filter " +
      "to services modified after a given date (useful for finding recently installed " +
      "malicious services). Sorted by last write time descending.",
    inputSchema: GET_SERVICES_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => getServices(args as never, toolCtx),
  });

  registry.set("get_scheduled_tasks", {
    name: "get_scheduled_tasks",
    description:
      "Extract scheduled tasks from the SOFTWARE registry hive's TaskCache. " +
      "Returns task name, path, author, and last write time. Sorted by recency.",
    inputSchema: GET_SCHEDULED_TASKS_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => getScheduledTasks(args as never, toolCtx),
  });

  // ── MFT / USN ──

  registry.set("extract_mft_timeline", {
    name: "extract_mft_timeline",
    description:
      "Parse the NTFS $MFT into a timeline of file operations with $STANDARD_INFORMATION " +
      "and $FILE_NAME timestamps. Automatically flags timestomping suspects where $SI and " +
      "$FN creation times differ by > 1 second. Filterable by path, extension, and time range.",
    inputSchema: EXTRACT_MFT_TIMELINE_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => extractMftTimeline(args as never, toolCtx),
  });

  registry.set("parse_usn_journal", {
    name: "parse_usn_journal",
    description:
      "Parse the NTFS $UsnJrnl:$J change journal. Records file creates, deletes, renames, " +
      "and content changes at a granular level. Filterable by filename, reason flags " +
      "(FILE_CREATE, FILE_DELETE, DATA_EXTEND, RENAME_NEW_NAME), and time range.",
    inputSchema: PARSE_USN_JOURNAL_SCHEMA as unknown as Record<string, unknown>,
    execute: (args) => parseUsnJournal(args as never, toolCtx),
  });
}
