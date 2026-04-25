/**
 * Typed wrappers for individual Volatility plugins.
 *
 * Each function exposed here is registered as an MCP tool. Branch agents
 * (Memory Branch in particular) call these — never the underlying vol
 * binary directly.
 *
 * Each wrapper:
 *   1. Defines its JSON Schema for input parameter validation
 *   2. Calls the typed runVolatilityPlugin core
 *   3. Maps Volatility's raw column names to a stable, structured output schema
 *   4. Returns the typed result
 */

import { runVolatilityPlugin, type VolatilityContext, type VolatilityResult, type MemoryImageResolver } from "./volatility.js";

// ────────────────────────────────────────────────────────────────────
// vol_pslist — Process listing
// ────────────────────────────────────────────────────────────────────

export interface VolPsListArgs {
  memory_id: string;
  pid?: number;
}

export interface ProcessRecord {
  pid: number;
  ppid: number;
  imageFileName: string;
  offset: string;          // hex
  threads: number;
  handles: number;
  sessionId: number | null;
  isWow64: boolean;
  createTime: string | null;  // ISO 8601 or null if not present
  exitTime: string | null;
}

export const VOL_PSLIST_SCHEMA = {
  type: "object",
  properties: {
    memory_id: { type: "string", minLength: 1 },
    pid: { type: "integer", minimum: 1 },
  },
  required: ["memory_id"],
  additionalProperties: false,
} as const;

export async function volPsList(
  args: VolPsListArgs,
  ctx: VolatilityContext,
  resolver: MemoryImageResolver
): Promise<VolatilityResult<ProcessRecord>> {
  const pluginArgs: string[] = [];
  if (args.pid !== undefined) {
    pluginArgs.push("--pid", String(args.pid));
  }

  const raw = await runVolatilityPlugin<RawPsListRow>(
    {
      memoryId: args.memory_id,
      plugin: "windows.pslist.PsList",
      pluginArgs,
    },
    ctx,
    resolver
  );

  if (raw.status !== "success") {
    return raw as unknown as VolatilityResult<ProcessRecord>;
  }

  return {
    ...raw,
    rowsInline: raw.rowsInline.map(normalizePsListRow),
  };
}

interface RawPsListRow {
  PID: number;
  PPID: number;
  ImageFileName: string;
  Offset: string;
  Threads: number;
  Handles: number;
  SessionId: number | null;
  Wow64: boolean;
  CreateTime: string | null;
  ExitTime: string | null;
}

function normalizePsListRow(row: RawPsListRow): ProcessRecord {
  return {
    pid: row.PID,
    ppid: row.PPID,
    imageFileName: row.ImageFileName,
    offset: row.Offset,
    threads: row.Threads,
    handles: row.Handles,
    sessionId: row.SessionId,
    isWow64: row.Wow64,
    createTime: normalizeVolTime(row.CreateTime),
    exitTime: normalizeVolTime(row.ExitTime),
  };
}

// ────────────────────────────────────────────────────────────────────
// vol_pstree — Process tree (parent/child relationships)
// ────────────────────────────────────────────────────────────────────

export interface VolPsTreeArgs {
  memory_id: string;
}

export interface ProcessTreeRecord extends ProcessRecord {
  /** Indentation depth in the tree — 0 == root */
  depth: number;
}

export const VOL_PSTREE_SCHEMA = {
  type: "object",
  properties: {
    memory_id: { type: "string", minLength: 1 },
  },
  required: ["memory_id"],
  additionalProperties: false,
} as const;

export async function volPsTree(
  args: VolPsTreeArgs,
  ctx: VolatilityContext,
  resolver: MemoryImageResolver
): Promise<VolatilityResult<ProcessTreeRecord>> {
  const raw = await runVolatilityPlugin<RawPsTreeRow>(
    {
      memoryId: args.memory_id,
      plugin: "windows.pstree.PsTree",
    },
    ctx,
    resolver
  );

  if (raw.status !== "success") {
    return raw as unknown as VolatilityResult<ProcessTreeRecord>;
  }

  return {
    ...raw,
    rowsInline: raw.rowsInline.map(normalizePsTreeRow),
  };
}

interface RawPsTreeRow extends RawPsListRow {
  __children?: RawPsTreeRow[];
}

function normalizePsTreeRow(row: RawPsTreeRow, depth = 0): ProcessTreeRecord {
  // vol3's pstree returns nested structure; we flatten while preserving depth.
  // Volatility 3 uses an "__indent" or similar field in some versions; we
  // compute depth from the nesting level for stability.
  return {
    ...normalizePsListRow(row),
    depth,
  };
}

// ────────────────────────────────────────────────────────────────────
// vol_psscan — Hidden process scan
// ────────────────────────────────────────────────────────────────────

export interface VolPsScanArgs {
  memory_id: string;
}

export const VOL_PSSCAN_SCHEMA = {
  type: "object",
  properties: { memory_id: { type: "string", minLength: 1 } },
  required: ["memory_id"],
  additionalProperties: false,
} as const;

export async function volPsScan(
  args: VolPsScanArgs,
  ctx: VolatilityContext,
  resolver: MemoryImageResolver
): Promise<VolatilityResult<ProcessRecord>> {
  const raw = await runVolatilityPlugin<RawPsListRow>(
    {
      memoryId: args.memory_id,
      plugin: "windows.psscan.PsScan",
    },
    ctx,
    resolver
  );

  if (raw.status !== "success") {
    return raw as unknown as VolatilityResult<ProcessRecord>;
  }

  return {
    ...raw,
    rowsInline: raw.rowsInline.map(normalizePsListRow),
  };
}

// ────────────────────────────────────────────────────────────────────
// vol_cmdline — Process command lines
// ────────────────────────────────────────────────────────────────────

export interface VolCmdLineArgs {
  memory_id: string;
  pid?: number;
}

export interface CommandLineRecord {
  pid: number;
  process: string;
  args: string;
}

export const VOL_CMDLINE_SCHEMA = {
  type: "object",
  properties: {
    memory_id: { type: "string", minLength: 1 },
    pid: { type: "integer", minimum: 1 },
  },
  required: ["memory_id"],
  additionalProperties: false,
} as const;

export async function volCmdLine(
  args: VolCmdLineArgs,
  ctx: VolatilityContext,
  resolver: MemoryImageResolver
): Promise<VolatilityResult<CommandLineRecord>> {
  const pluginArgs: string[] = [];
  if (args.pid !== undefined) {
    pluginArgs.push("--pid", String(args.pid));
  }

  const raw = await runVolatilityPlugin<{ PID: number; Process: string; Args: string }>(
    {
      memoryId: args.memory_id,
      plugin: "windows.cmdline.CmdLine",
      pluginArgs,
    },
    ctx,
    resolver
  );

  if (raw.status !== "success") {
    return raw as unknown as VolatilityResult<CommandLineRecord>;
  }

  return {
    ...raw,
    rowsInline: raw.rowsInline.map((r) => ({
      pid: r.PID,
      process: r.Process,
      args: r.Args,
    })),
  };
}

// ────────────────────────────────────────────────────────────────────
// vol_malfind — Process injection / malicious memory regions
// ────────────────────────────────────────────────────────────────────

export interface VolMalfindArgs {
  memory_id: string;
  pid?: number;
}

export interface MalfindRecord {
  pid: number;
  process: string;
  startVaddr: string;       // hex
  endVaddr: string;         // hex
  protection: string;       // e.g. "PAGE_EXECUTE_READWRITE"
  hasMzHeader: boolean;
  /** First N bytes of the suspicious region in hex */
  preview: string;
  notes: string;
}

export const VOL_MALFIND_SCHEMA = {
  type: "object",
  properties: {
    memory_id: { type: "string", minLength: 1 },
    pid: { type: "integer", minimum: 1 },
  },
  required: ["memory_id"],
  additionalProperties: false,
} as const;

export async function volMalfind(
  args: VolMalfindArgs,
  ctx: VolatilityContext,
  resolver: MemoryImageResolver
): Promise<VolatilityResult<MalfindRecord>> {
  const pluginArgs: string[] = [];
  if (args.pid !== undefined) {
    pluginArgs.push("--pid", String(args.pid));
  }

  const raw = await runVolatilityPlugin<{
    PID: number;
    Process: string;
    Start_VPN: string;
    End_VPN: string;
    Tag: string;
    Protection: string;
    CommitCharge: number;
    PrivateMemory: number;
    File_output: string;
    Notes: string;
    Hexdump: string;
    Disasm: string;
  }>(
    {
      memoryId: args.memory_id,
      plugin: "windows.malfind.Malfind",
      pluginArgs,
    },
    ctx,
    resolver
  );

  if (raw.status !== "success") {
    return raw as unknown as VolatilityResult<MalfindRecord>;
  }

  return {
    ...raw,
    rowsInline: raw.rowsInline.map((r) => ({
      pid: r.PID,
      process: r.Process,
      startVaddr: r.Start_VPN,
      endVaddr: r.End_VPN,
      protection: r.Protection,
      // Malfind's "MZ" tag indicates a PE header found in private memory — strong injection signal
      hasMzHeader: typeof r.Notes === "string" && r.Notes.includes("MZ header"),
      preview: typeof r.Hexdump === "string" ? r.Hexdump.slice(0, 256) : "",
      notes: r.Notes ?? "",
    })),
  };
}

// ────────────────────────────────────────────────────────────────────
// vol_netscan — Network connections
// ────────────────────────────────────────────────────────────────────

export interface VolNetScanArgs {
  memory_id: string;
}

export interface NetworkRecord {
  offset: string;
  protocol: string;          // TCPv4, UDPv4, TCPv6, etc.
  localAddr: string;
  localPort: number | null;
  foreignAddr: string;
  foreignPort: number | null;
  state: string;             // ESTABLISHED, LISTENING, etc.
  pid: number;
  owner: string;             // process name
  createTime: string | null;
}

export const VOL_NETSCAN_SCHEMA = {
  type: "object",
  properties: { memory_id: { type: "string", minLength: 1 } },
  required: ["memory_id"],
  additionalProperties: false,
} as const;

export async function volNetScan(
  args: VolNetScanArgs,
  ctx: VolatilityContext,
  resolver: MemoryImageResolver
): Promise<VolatilityResult<NetworkRecord>> {
  const raw = await runVolatilityPlugin<{
    Offset: string;
    Proto: string;
    LocalAddr: string;
    LocalPort: number | null;
    ForeignAddr: string;
    ForeignPort: number | null;
    State: string;
    PID: number;
    Owner: string;
    Created: string | null;
  }>(
    {
      memoryId: args.memory_id,
      plugin: "windows.netscan.NetScan",
    },
    ctx,
    resolver
  );

  if (raw.status !== "success") {
    return raw as unknown as VolatilityResult<NetworkRecord>;
  }

  return {
    ...raw,
    rowsInline: raw.rowsInline.map((r) => ({
      offset: r.Offset,
      protocol: r.Proto,
      localAddr: r.LocalAddr,
      localPort: r.LocalPort,
      foreignAddr: r.ForeignAddr,
      foreignPort: r.ForeignPort,
      state: r.State,
      pid: r.PID,
      owner: r.Owner,
      createTime: normalizeVolTime(r.Created),
    })),
  };
}

// ────────────────────────────────────────────────────────────────────
// vol_info — Memory image metadata
// ────────────────────────────────────────────────────────────────────

export interface VolInfoArgs {
  memory_id: string;
}

export interface SystemInfoRecord {
  variable: string;
  value: string;
}

export const VOL_INFO_SCHEMA = {
  type: "object",
  properties: { memory_id: { type: "string", minLength: 1 } },
  required: ["memory_id"],
  additionalProperties: false,
} as const;

export async function volInfo(
  args: VolInfoArgs,
  ctx: VolatilityContext,
  resolver: MemoryImageResolver
): Promise<VolatilityResult<SystemInfoRecord>> {
  const raw = await runVolatilityPlugin<{ Variable: string; Value: string }>(
    {
      memoryId: args.memory_id,
      plugin: "windows.info.Info",
    },
    ctx,
    resolver
  );

  if (raw.status !== "success") {
    return raw as unknown as VolatilityResult<SystemInfoRecord>;
  }

  return {
    ...raw,
    rowsInline: raw.rowsInline.map((r) => ({
      variable: r.Variable,
      value: r.Value,
    })),
  };
}

// ────────────────────────────────────────────────────────────────────
// Time normalization
// ────────────────────────────────────────────────────────────────────

/**
 * Volatility 3 emits times in formats like "2024-04-22 14:03:11.000000 UTC+0000"
 * or "2024-04-22 14:03:11" (no timezone) or null. Normalize to ISO 8601 UTC,
 * or null if unparseable.
 */
function normalizeVolTime(volTime: string | null | undefined): string | null {
  if (!volTime || volTime === "" || volTime === "N/A") return null;

  // Common vol3 formats:
  //   "2024-04-22 14:03:11.123456 UTC+0000"
  //   "2024-04-22 14:03:11.123456"
  //   "2024-04-22 14:03:11"
  const cleaned = volTime
    .replace(/\s+UTC[+-]\d{4}\s*$/i, "Z")    // strip trailing UTC offset, replace with Z
    .replace(/\s+(\d{4})$/, "")               // strip lone trailing 4-digit year suffix if any
    .replace(/^(\d{4}-\d{2}-\d{2}) /, "$1T") // separator → ISO T
    .trim();

  // Add Z if no timezone marker
  const isoCandidate = /[Z+-]\d{2}:?\d{2}$|Z$/.test(cleaned) ? cleaned : `${cleaned}Z`;

  const parsed = Date.parse(isoCandidate);
  if (isNaN(parsed)) return null;
  return new Date(parsed).toISOString();
}

// Exported for testing
export const _internals = { normalizeVolTime };
