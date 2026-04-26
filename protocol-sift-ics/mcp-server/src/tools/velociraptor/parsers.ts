/**
 * Typed parsers for the seven Velociraptor MCP tool functions.
 *
 * Each function follows the project pattern:
 *   - Validates collection path via PathGuard, verifies ReadOnlyGuard
 *   - Reads only from the extracted collection tree (never modifies)
 *   - Returns normalized records with executionId for audit-log citation
 *   - Spills large outputs to the working directory and returns a summary
 *     plus an artifact pointer
 *
 * Mac and Windows artifacts are normalized into a single shape per tool —
 * the agent sees "persistence entries" or "browser visits," not OS-specific
 * field names. The OS is reported as a per-row attribute when relevant.
 */

import { randomUUID } from "node:crypto";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

import {
  openCollection,
  readArtifactRows,
  findArtifact,
  type ToolContext,
  type VelociraptorCollectionResolver,
  type CollectionManifest,
  type OsFamily,
} from "./collection.js";

const INLINE_ROW_CAP = 500;

// ────────────────────────────────────────────────────────────────────
// Shared result shape for spillover tools
// ────────────────────────────────────────────────────────────────────

interface SpilloverResult<T> {
  executionId: string;
  collectionId: string;
  os: OsFamily;
  rowCount: number;
  rowsInline: T[];
  artifactRef?: { path: string; rowsWritten: number };
  artifactsConsulted: string[];
}

async function maybeSpill<T>(
  rows: T[],
  ctx: ToolContext,
  executionId: string,
  label: string
): Promise<{ rowsInline: T[]; artifactRef?: { path: string; rowsWritten: number } }> {
  if (rows.length <= INLINE_ROW_CAP) {
    return { rowsInline: rows };
  }
  const dir = join(ctx.pathGuard.getWorkingDir(), "parsed_artifacts");
  await mkdir(dir, { recursive: true });
  const artifactPath = join(dir, `vr_${label}_${executionId}.jsonl`);
  const canonical = ctx.pathGuard.validatePath(artifactPath, /* allowWrite */ true);
  const body = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
  await writeFile(canonical, body);
  return {
    rowsInline: rows.slice(0, INLINE_ROW_CAP),
    artifactRef: { path: canonical, rowsWritten: rows.length },
  };
}

// ────────────────────────────────────────────────────────────────────
// 1. parse_collection
// ────────────────────────────────────────────────────────────────────

export interface ParseCollectionArgs {
  collection_id: string;
}

export interface ParseCollectionResult {
  executionId: string;
  manifest: CollectionManifest;
}

export async function parseCollection(
  args: ParseCollectionArgs,
  ctx: ToolContext,
  resolver: VelociraptorCollectionResolver
): Promise<ParseCollectionResult> {
  const executionId = `EXEC-${randomUUID()}`;
  const { manifest } = await openCollection(args.collection_id, ctx, resolver);
  return { executionId, manifest };
}

export const PARSE_COLLECTION_SCHEMA = {
  type: "object",
  properties: {
    collection_id: { type: "string" },
  },
  required: ["collection_id"],
  additionalProperties: false,
} as const;

// ────────────────────────────────────────────────────────────────────
// 2. vr_extract_unified_log (macOS)
// ────────────────────────────────────────────────────────────────────

export interface ExtractUnifiedLogArgs {
  collection_id: string;
  predicate?: string;       // VR / log subsystem predicate, recorded as filter only
  since?: string;           // ISO8601 lower bound
  until?: string;           // ISO8601 upper bound
  max_rows?: number;
}

export interface UnifiedLogEntry {
  timestamp: string;
  subsystem: string | null;
  category: string | null;
  process: string | null;
  pid: number | null;
  message: string;
}

interface RawUnifiedLogRow {
  Timestamp?: string;
  EventTime?: string;
  Subsystem?: string;
  Category?: string;
  ProcessImagePath?: string;
  Process?: string;
  ProcessImageUUID?: string;
  ProcessID?: number;
  EventMessage?: string;
  Message?: string;
}

const UNIFIED_LOG_ARTIFACTS = [
  "MacOS.UnifiedLogs.Search",
  "MacOS.System.UnifiedLog",
];

export async function vrExtractUnifiedLog(
  args: ExtractUnifiedLogArgs,
  ctx: ToolContext,
  resolver: VelociraptorCollectionResolver
): Promise<SpilloverResult<UnifiedLogEntry>> {
  const executionId = `EXEC-${randomUUID()}`;
  const { manifest } = await openCollection(args.collection_id, ctx, resolver);
  const artifact = findArtifact(manifest, UNIFIED_LOG_ARTIFACTS);

  if (!artifact) {
    return {
      executionId,
      collectionId: args.collection_id,
      os: manifest.os,
      rowCount: 0,
      rowsInline: [],
      artifactsConsulted: UNIFIED_LOG_ARTIFACTS,
    };
  }

  const sinceMs = args.since ? Date.parse(args.since) : null;
  const untilMs = args.until ? Date.parse(args.until) : null;
  const cap = args.max_rows ?? 50_000;

  const rows: UnifiedLogEntry[] = [];
  for await (const raw of readArtifactRows<RawUnifiedLogRow>(artifact.resultPath, ctx)) {
    if (rows.length >= cap) break;
    const ts = raw.Timestamp ?? raw.EventTime;
    if (!ts) continue;
    const tsMs = Date.parse(ts);
    if (sinceMs !== null && tsMs < sinceMs) continue;
    if (untilMs !== null && tsMs > untilMs) continue;

    rows.push({
      timestamp: ts,
      subsystem: raw.Subsystem ?? null,
      category: raw.Category ?? null,
      process: raw.ProcessImagePath ?? raw.Process ?? null,
      pid: raw.ProcessID ?? null,
      message: raw.EventMessage ?? raw.Message ?? "",
    });
  }

  const spill = await maybeSpill(rows, ctx, executionId, "unified_log");
  return {
    executionId,
    collectionId: args.collection_id,
    os: manifest.os,
    rowCount: rows.length,
    rowsInline: spill.rowsInline,
    artifactRef: spill.artifactRef,
    artifactsConsulted: [artifact.name],
  };
}

export const VR_EXTRACT_UNIFIED_LOG_SCHEMA = {
  type: "object",
  properties: {
    collection_id: { type: "string" },
    predicate: { type: "string", maxLength: 1000 },
    since: { type: "string", format: "date-time" },
    until: { type: "string", format: "date-time" },
    max_rows: { type: "integer", minimum: 1, maximum: 200000 },
  },
  required: ["collection_id"],
  additionalProperties: false,
} as const;

// ────────────────────────────────────────────────────────────────────
// 3. vr_extract_persistence (cross-OS, normalized)
// ────────────────────────────────────────────────────────────────────

export interface ExtractPersistenceArgs {
  collection_id: string;
  os_filter?: OsFamily;
}

export interface PersistenceEntry {
  os: OsFamily;
  mechanism:
    | "launch_agent"
    | "launch_daemon"
    | "login_item"
    | "registry_run"
    | "service"
    | "scheduled_task"
    | "wmi_subscription"
    | "cron"
    | "systemd_unit"
    | "other";
  name: string;
  source: string;        // file/registry path the entry came from
  command: string | null;
  user: string | null;
  enabled: boolean | null;
  hash_sha256: string | null;
  modified: string | null;
  rawArtifact: string;   // the VR artifact name for citation
}

const PERSISTENCE_ARTIFACTS = {
  windows: [
    "Windows.Forensics.Persistence",
    "Windows.System.Services",
    "Windows.System.TaskScheduler",
    "Windows.Registry.NTUser",
  ],
  macos: [
    "MacOS.System.Persistence",
    "MacOS.System.LaunchAgents",
    "MacOS.System.LaunchDaemons",
  ],
  linux: ["Linux.Sys.Services"],
};

interface RawPersistenceWindows {
  Type?: string;
  Source?: string;
  Key?: string;
  Name?: string;
  Command?: string;
  User?: string;
  Enabled?: boolean;
  Hash?: { SHA256?: string };
  Modified?: string;
}

interface RawPersistenceMac {
  Type?: string;
  Path?: string;
  Label?: string;
  Program?: string;
  ProgramArguments?: string[];
  RunAtLoad?: boolean;
  User?: string;
  SHA256?: string;
  Modified?: string;
}

export async function vrExtractPersistence(
  args: ExtractPersistenceArgs,
  ctx: ToolContext,
  resolver: VelociraptorCollectionResolver
): Promise<SpilloverResult<PersistenceEntry>> {
  const executionId = `EXEC-${randomUUID()}`;
  const { manifest } = await openCollection(args.collection_id, ctx, resolver);

  const wantWindows = !args.os_filter || args.os_filter === "windows";
  const wantMac = !args.os_filter || args.os_filter === "macos";
  const wantLinux = !args.os_filter || args.os_filter === "linux";

  const consulted: string[] = [];
  const out: PersistenceEntry[] = [];

  if (wantWindows) {
    for (const name of PERSISTENCE_ARTIFACTS.windows) {
      const a = findArtifact(manifest, [name]);
      if (!a) continue;
      consulted.push(a.name);
      for await (const r of readArtifactRows<RawPersistenceWindows>(a.resultPath, ctx)) {
        out.push(normalizeWindowsPersistence(r, a.name));
      }
    }
  }
  if (wantMac) {
    for (const name of PERSISTENCE_ARTIFACTS.macos) {
      const a = findArtifact(manifest, [name]);
      if (!a) continue;
      consulted.push(a.name);
      for await (const r of readArtifactRows<RawPersistenceMac>(a.resultPath, ctx)) {
        out.push(normalizeMacPersistence(r, a.name));
      }
    }
  }
  if (wantLinux) {
    for (const name of PERSISTENCE_ARTIFACTS.linux) {
      const a = findArtifact(manifest, [name]);
      if (!a) continue;
      consulted.push(a.name);
    }
  }

  const spill = await maybeSpill(out, ctx, executionId, "persistence");
  return {
    executionId,
    collectionId: args.collection_id,
    os: manifest.os,
    rowCount: out.length,
    rowsInline: spill.rowsInline,
    artifactRef: spill.artifactRef,
    artifactsConsulted: consulted,
  };
}

function normalizeWindowsPersistence(
  r: RawPersistenceWindows,
  artifactName: string
): PersistenceEntry {
  const t = (r.Type ?? "").toLowerCase();
  let mechanism: PersistenceEntry["mechanism"] = "other";
  if (t.includes("run") || (r.Source ?? "").toLowerCase().includes("\\run")) mechanism = "registry_run";
  else if (t.includes("service")) mechanism = "service";
  else if (t.includes("task") || t.includes("scheduled")) mechanism = "scheduled_task";
  else if (t.includes("wmi")) mechanism = "wmi_subscription";
  return {
    os: "windows",
    mechanism,
    name: r.Name ?? r.Key ?? "",
    source: r.Source ?? r.Key ?? "",
    command: r.Command ?? null,
    user: r.User ?? null,
    enabled: r.Enabled ?? null,
    hash_sha256: r.Hash?.SHA256 ?? null,
    modified: r.Modified ?? null,
    rawArtifact: artifactName,
  };
}

function normalizeMacPersistence(
  r: RawPersistenceMac,
  artifactName: string
): PersistenceEntry {
  const path = r.Path ?? "";
  let mechanism: PersistenceEntry["mechanism"] = "other";
  const lower = path.toLowerCase();
  if (lower.includes("/launchagents/")) mechanism = "launch_agent";
  else if (lower.includes("/launchdaemons/")) mechanism = "launch_daemon";
  else if (lower.includes("loginitems")) mechanism = "login_item";
  const command = r.Program
    ? [r.Program, ...(r.ProgramArguments ?? []).slice(1)].join(" ")
    : (r.ProgramArguments ?? []).join(" ") || null;
  return {
    os: "macos",
    mechanism,
    name: r.Label ?? path.split("/").pop() ?? "",
    source: path,
    command,
    user: r.User ?? null,
    enabled: r.RunAtLoad ?? null,
    hash_sha256: r.SHA256 ?? null,
    modified: r.Modified ?? null,
    rawArtifact: artifactName,
  };
}

export const VR_EXTRACT_PERSISTENCE_SCHEMA = {
  type: "object",
  properties: {
    collection_id: { type: "string" },
    os_filter: { type: "string", enum: ["windows", "macos", "linux", "unknown"] },
  },
  required: ["collection_id"],
  additionalProperties: false,
} as const;

// ────────────────────────────────────────────────────────────────────
// 4. vr_extract_browser_history
// ────────────────────────────────────────────────────────────────────

export interface ExtractBrowserHistoryArgs {
  collection_id: string;
  browser?: "chrome" | "edge" | "firefox" | "safari" | "all";
  user?: string;
  max_rows?: number;
}

export interface BrowserVisit {
  os: OsFamily;
  browser: string;
  user: string | null;
  url: string;
  title: string | null;
  visit_time: string;
  visit_count: number | null;
  rawArtifact: string;
}

interface RawBrowserRow {
  User?: string;
  Username?: string;
  URL?: string;
  Url?: string;
  Title?: string;
  Visited?: string;
  LastVisit?: string;
  VisitTime?: string;
  VisitCount?: number;
  Visits?: number;
}

const BROWSER_ARTIFACTS: Record<string, string[]> = {
  chrome: ["Windows.Applications.Chrome.History", "MacOS.Applications.Chrome.History"],
  edge: ["Windows.Applications.Edge.History"],
  firefox: ["Windows.Applications.Firefox.History", "MacOS.Applications.Firefox.History"],
  safari: ["MacOS.Applications.Safari.History"],
};

export async function vrExtractBrowserHistory(
  args: ExtractBrowserHistoryArgs,
  ctx: ToolContext,
  resolver: VelociraptorCollectionResolver
): Promise<SpilloverResult<BrowserVisit>> {
  const executionId = `EXEC-${randomUUID()}`;
  const { manifest } = await openCollection(args.collection_id, ctx, resolver);

  const browsers = args.browser && args.browser !== "all"
    ? [args.browser]
    : Object.keys(BROWSER_ARTIFACTS);
  const cap = args.max_rows ?? 20_000;

  const consulted: string[] = [];
  const out: BrowserVisit[] = [];

  for (const browser of browsers) {
    for (const artifactName of BROWSER_ARTIFACTS[browser] ?? []) {
      const a = findArtifact(manifest, [artifactName]);
      if (!a) continue;
      consulted.push(a.name);
      for await (const r of readArtifactRows<RawBrowserRow>(a.resultPath, ctx)) {
        if (out.length >= cap) break;
        const user = r.User ?? r.Username ?? null;
        if (args.user && user !== args.user) continue;
        const url = r.URL ?? r.Url ?? "";
        if (!url) continue;
        out.push({
          os: manifest.os,
          browser,
          user,
          url,
          title: r.Title ?? null,
          visit_time: r.Visited ?? r.LastVisit ?? r.VisitTime ?? "",
          visit_count: r.VisitCount ?? r.Visits ?? null,
          rawArtifact: a.name,
        });
      }
      if (out.length >= cap) break;
    }
    if (out.length >= cap) break;
  }

  const spill = await maybeSpill(out, ctx, executionId, "browser_history");
  return {
    executionId,
    collectionId: args.collection_id,
    os: manifest.os,
    rowCount: out.length,
    rowsInline: spill.rowsInline,
    artifactRef: spill.artifactRef,
    artifactsConsulted: consulted,
  };
}

export const VR_EXTRACT_BROWSER_HISTORY_SCHEMA = {
  type: "object",
  properties: {
    collection_id: { type: "string" },
    browser: { type: "string", enum: ["chrome", "edge", "firefox", "safari", "all"] },
    user: { type: "string", maxLength: 255 },
    max_rows: { type: "integer", minimum: 1, maximum: 100000 },
  },
  required: ["collection_id"],
  additionalProperties: false,
} as const;

// ────────────────────────────────────────────────────────────────────
// 5. vr_extract_filesystem_metadata
// ────────────────────────────────────────────────────────────────────

export interface ExtractFilesystemMetadataArgs {
  collection_id: string;
  path_filter?: string;     // substring match on path
  max_rows?: number;
}

export interface FileMetadata {
  os: OsFamily;
  path: string;
  size_bytes: number | null;
  mtime: string | null;
  atime: string | null;
  ctime: string | null;
  btime: string | null;
  mode: string | null;
  uid: number | null;
  gid: number | null;
  sha256: string | null;
  rawArtifact: string;
}

interface RawFileRow {
  FullPath?: string;
  OSPath?: string;
  Path?: string;
  Size?: number;
  Mtime?: string;
  Atime?: string;
  Ctime?: string;
  Btime?: string;
  Mode?: string | number;
  Uid?: number;
  Gid?: number;
  SHA256?: string;
  Hash?: { SHA256?: string };
}

const FILE_METADATA_ARTIFACTS = [
  "Generic.System.FileFinder",
  "Windows.Search.FileFinder",
  "MacOS.Search.FileFinder",
  "Linux.Search.FileFinder",
];

export async function vrExtractFilesystemMetadata(
  args: ExtractFilesystemMetadataArgs,
  ctx: ToolContext,
  resolver: VelociraptorCollectionResolver
): Promise<SpilloverResult<FileMetadata>> {
  const executionId = `EXEC-${randomUUID()}`;
  const { manifest } = await openCollection(args.collection_id, ctx, resolver);
  const cap = args.max_rows ?? 50_000;
  const filter = args.path_filter ?? "";

  const consulted: string[] = [];
  const out: FileMetadata[] = [];

  for (const name of FILE_METADATA_ARTIFACTS) {
    const a = findArtifact(manifest, [name]);
    if (!a) continue;
    consulted.push(a.name);
    for await (const r of readArtifactRows<RawFileRow>(a.resultPath, ctx)) {
      if (out.length >= cap) break;
      const path = r.FullPath ?? r.OSPath ?? r.Path ?? "";
      if (!path) continue;
      if (filter && !path.includes(filter)) continue;
      out.push({
        os: manifest.os,
        path,
        size_bytes: r.Size ?? null,
        mtime: r.Mtime ?? null,
        atime: r.Atime ?? null,
        ctime: r.Ctime ?? null,
        btime: r.Btime ?? null,
        mode: r.Mode !== undefined ? String(r.Mode) : null,
        uid: r.Uid ?? null,
        gid: r.Gid ?? null,
        sha256: r.SHA256 ?? r.Hash?.SHA256 ?? null,
        rawArtifact: a.name,
      });
    }
    if (out.length >= cap) break;
  }

  const spill = await maybeSpill(out, ctx, executionId, "filesystem_metadata");
  return {
    executionId,
    collectionId: args.collection_id,
    os: manifest.os,
    rowCount: out.length,
    rowsInline: spill.rowsInline,
    artifactRef: spill.artifactRef,
    artifactsConsulted: consulted,
  };
}

export const VR_EXTRACT_FILESYSTEM_METADATA_SCHEMA = {
  type: "object",
  properties: {
    collection_id: { type: "string" },
    path_filter: { type: "string", maxLength: 4096 },
    max_rows: { type: "integer", minimum: 1, maximum: 200000 },
  },
  required: ["collection_id"],
  additionalProperties: false,
} as const;

// ────────────────────────────────────────────────────────────────────
// 6. vr_extract_knowledgec (macOS)
// ────────────────────────────────────────────────────────────────────

export interface ExtractKnowledgeCArgs {
  collection_id: string;
  max_rows?: number;
}

export interface KnowledgeCEntry {
  stream: string;          // e.g. /app/inFocus, /app/usage
  bundle_id: string | null;
  start_time: string | null;
  end_time: string | null;
  duration_seconds: number | null;
  user: string | null;
  rawArtifact: string;
}

interface RawKnowledgeCRow {
  Stream?: string;
  Bundle?: string;
  BundleID?: string;
  Start?: string;
  StartTime?: string;
  End?: string;
  EndTime?: string;
  Duration?: number;
  User?: string;
}

const KNOWLEDGEC_ARTIFACTS = [
  "MacOS.System.KnowledgeC",
  "MacOS.UnifiedLogs.KnowledgeC",
];

export async function vrExtractKnowledgeC(
  args: ExtractKnowledgeCArgs,
  ctx: ToolContext,
  resolver: VelociraptorCollectionResolver
): Promise<SpilloverResult<KnowledgeCEntry>> {
  const executionId = `EXEC-${randomUUID()}`;
  const { manifest } = await openCollection(args.collection_id, ctx, resolver);
  const a = findArtifact(manifest, KNOWLEDGEC_ARTIFACTS);
  const cap = args.max_rows ?? 50_000;

  if (!a) {
    return {
      executionId,
      collectionId: args.collection_id,
      os: manifest.os,
      rowCount: 0,
      rowsInline: [],
      artifactsConsulted: KNOWLEDGEC_ARTIFACTS,
    };
  }

  const out: KnowledgeCEntry[] = [];
  for await (const r of readArtifactRows<RawKnowledgeCRow>(a.resultPath, ctx)) {
    if (out.length >= cap) break;
    out.push({
      stream: r.Stream ?? "",
      bundle_id: r.Bundle ?? r.BundleID ?? null,
      start_time: r.Start ?? r.StartTime ?? null,
      end_time: r.End ?? r.EndTime ?? null,
      duration_seconds: r.Duration ?? null,
      user: r.User ?? null,
      rawArtifact: a.name,
    });
  }

  const spill = await maybeSpill(out, ctx, executionId, "knowledgec");
  return {
    executionId,
    collectionId: args.collection_id,
    os: manifest.os,
    rowCount: out.length,
    rowsInline: spill.rowsInline,
    artifactRef: spill.artifactRef,
    artifactsConsulted: [a.name],
  };
}

export const VR_EXTRACT_KNOWLEDGEC_SCHEMA = {
  type: "object",
  properties: {
    collection_id: { type: "string" },
    max_rows: { type: "integer", minimum: 1, maximum: 200000 },
  },
  required: ["collection_id"],
  additionalProperties: false,
} as const;

// ────────────────────────────────────────────────────────────────────
// 7. vr_list_users
// ────────────────────────────────────────────────────────────────────

export interface ListUsersArgs {
  collection_id: string;
}

export interface UserRecord {
  os: OsFamily;
  username: string;
  uid: number | null;
  home_dir: string | null;
  shell: string | null;
  last_login: string | null;
  is_admin: boolean | null;
  is_disabled: boolean | null;
  rawArtifact: string;
}

interface RawUserRow {
  Name?: string;
  User?: string;
  Username?: string;
  Account?: string;
  UID?: number;
  Uid?: number;
  HomeDir?: string;
  Home?: string;
  Shell?: string;
  LastLogin?: string;
  LastLogon?: string;
  IsAdmin?: boolean;
  IsLocalAdmin?: boolean;
  Disabled?: boolean;
  Enabled?: boolean;
}

const USER_ARTIFACTS = {
  windows: ["Windows.Sys.AllUsers", "Windows.Sys.Users"],
  macos: ["MacOS.System.Users", "MacOS.Sys.Users"],
  linux: ["Linux.Sys.Users"],
};

export async function vrListUsers(
  args: ListUsersArgs,
  ctx: ToolContext,
  resolver: VelociraptorCollectionResolver
): Promise<{
  executionId: string;
  collectionId: string;
  os: OsFamily;
  users: UserRecord[];
  artifactsConsulted: string[];
}> {
  const executionId = `EXEC-${randomUUID()}`;
  const { manifest } = await openCollection(args.collection_id, ctx, resolver);

  const consulted: string[] = [];
  const users: UserRecord[] = [];

  const candidates = [
    ...USER_ARTIFACTS.windows,
    ...USER_ARTIFACTS.macos,
    ...USER_ARTIFACTS.linux,
  ];

  for (const name of candidates) {
    const a = findArtifact(manifest, [name]);
    if (!a) continue;
    consulted.push(a.name);
    for await (const r of readArtifactRows<RawUserRow>(a.resultPath, ctx)) {
      const username = r.Name ?? r.User ?? r.Username ?? r.Account ?? "";
      if (!username) continue;
      users.push({
        os: manifest.os,
        username,
        uid: r.UID ?? r.Uid ?? null,
        home_dir: r.HomeDir ?? r.Home ?? null,
        shell: r.Shell ?? null,
        last_login: r.LastLogin ?? r.LastLogon ?? null,
        is_admin: r.IsAdmin ?? r.IsLocalAdmin ?? null,
        is_disabled: r.Disabled ?? (r.Enabled === undefined ? null : !r.Enabled),
        rawArtifact: a.name,
      });
    }
  }

  return {
    executionId,
    collectionId: args.collection_id,
    os: manifest.os,
    users,
    artifactsConsulted: consulted,
  };
}

export const VR_LIST_USERS_SCHEMA = {
  type: "object",
  properties: {
    collection_id: { type: "string" },
  },
  required: ["collection_id"],
  additionalProperties: false,
} as const;
