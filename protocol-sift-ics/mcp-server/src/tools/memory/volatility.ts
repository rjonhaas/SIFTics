/**
 * Volatility 3 invocation wrapper.
 *
 * Wraps the `vol` command-line tool from the Volatility 3 Framework with:
 *   - Strict argument validation (no shell injection possible)
 *   - Read-only enforcement on the memory image
 *   - JSON output parsing into typed records
 *   - Output size capping with artifact-file spillover for large results
 *   - Per-plugin timeout enforcement
 *
 * Volatility 3 reference:
 *   https://volatility3.readthedocs.io/en/stable/vol-cli.html
 *
 * Plugin naming convention (Volatility 3):
 *   windows.<area>.<PluginName>     e.g. windows.pslist.PsList
 *   linux.<area>.<PluginName>       e.g. linux.pslist.PsList
 *
 * Important: global flags (-f, -r, -q, -o) must come BEFORE the plugin name.
 * Plugin-specific flags come AFTER.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, stat, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createHash, randomUUID } from "node:crypto";

import type { PathGuard } from "../../safety/path_guard.js";
import type { ReadOnlyGuard } from "../../safety/readonly_guard.js";

const execFileP = promisify(execFile);

// ────────────────────────────────────────────────────────────────────
// Allowlist of permitted plugins
// ────────────────────────────────────────────────────────────────────
//
// Why allowlist: even though we're using execFile (no shell expansion),
// passing arbitrary plugin names to vol still allows the LLM to invoke
// plugins that may be experimental, unsafe, or destructive (yes, some
// vol3 plugins extract files and write them to disk).
//
// Every plugin in this list:
//   - Has been verified to be read-only with respect to the memory image
//   - Returns structured data that we know how to parse
//   - Has a defined output schema in this module

export const ALLOWED_PLUGINS = new Set<string>([
  "windows.info.Info",
  "windows.pslist.PsList",
  "windows.pstree.PsTree",
  "windows.psscan.PsScan",
  "windows.cmdline.CmdLine",
  "windows.handles.Handles",
  "windows.dlllist.DllList",
  "windows.ldrmodules.LdrModules",
  "windows.malfind.Malfind",
  "windows.netstat.NetStat",
  "windows.netscan.NetScan",
  "windows.filescan.FileScan",
  "windows.svcscan.SvcScan",
  "windows.driverscan.DriverScan",
  "windows.modules.Modules",
  "windows.modscan.ModScan",
  "windows.ssdt.SSDT",
  "windows.callbacks.Callbacks",
  "windows.hashdump.Hashdump",
  "windows.lsadump.Lsadump",
  "windows.cachedump.Cachedump",
  "windows.timeliner.Timeliner",
  "windows.envars.Envars",
  "windows.getsids.GetSIDs",
  "windows.privileges.Privs",
  "windows.sessions.Sessions",
  // Linux subset
  "linux.pslist.PsList",
  "linux.pstree.PsTree",
  "linux.bash.Bash",
  "linux.lsmod.Lsmod",
  "linux.lsof.Lsof",
  // Mac subset
  "mac.pslist.PsList",
  "mac.pstree.PsTree",
]);

/**
 * Plugins that are explicitly NOT allowed because they extract files or
 * have other write-class side effects. Documented for clarity even though
 * they're already excluded by the allowlist above.
 */
export const EXCLUDED_PLUGINS_DOCUMENTED = new Set<string>([
  "windows.dumpfiles.DumpFiles",      // extracts files from memory; write side effect
  "windows.memmap.Memmap",            // can dump memory regions
  "windows.vadyarascan.VadYaraScan",  // requires user-supplied YARA rules — wrap separately
  "yarascan.YaraScan",                // ditto
]);

// ────────────────────────────────────────────────────────────────────
// Configuration
// ────────────────────────────────────────────────────────────────────

export interface VolatilityConfig {
  /** Path to the vol executable (default: "vol", from PATH) */
  volBinary: string;
  /** Default per-call timeout in ms */
  defaultTimeoutMs: number;
  /** Maximum stdout buffer in bytes (vol output can be huge) */
  maxBufferBytes: number;
  /** Maximum result records to embed inline; larger results spill to artifact */
  inlineRowLimit: number;
}

export const DEFAULT_CONFIG: VolatilityConfig = {
  volBinary: "vol",
  defaultTimeoutMs: 5 * 60 * 1000,    // 5 minutes per plugin
  maxBufferBytes: 500 * 1024 * 1024,  // 500 MB
  inlineRowLimit: 200,                // beyond this, results go to artifact file
};

// ────────────────────────────────────────────────────────────────────
// Tool context
// ────────────────────────────────────────────────────────────────────

export interface VolatilityContext {
  pathGuard: PathGuard;
  readOnlyGuard: ReadOnlyGuard;
  config: VolatilityConfig;
}

// ────────────────────────────────────────────────────────────────────
// Result types
// ────────────────────────────────────────────────────────────────────

export interface VolatilityResult<RowType = Record<string, unknown>> {
  executionId: string;
  plugin: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  status: "success" | "error" | "timeout";
  /** Memory image identifier (not the path — agents see opaque IDs only) */
  memoryId: string;
  /** Number of rows returned by Volatility */
  rowCount: number;
  /** Up to inlineRowLimit rows, returned in the response */
  rowsInline: RowType[];
  /** Set when rowCount > inlineRowLimit; full result spilled to working_dir */
  artifactRef?: {
    path: string;
    sizeBytes: number;
    sha256: string;
  };
  /** Error message when status != success */
  error?: string;
  /** Raw stderr from vol — useful when status == error */
  stderr?: string;
}

// ────────────────────────────────────────────────────────────────────
// Memory image registry
// ────────────────────────────────────────────────────────────────────

/**
 * The agents reference memory images by ID (e.g. "MEM-001"), never by path.
 * The registry maps IDs to canonical absolute paths. This is owned by the
 * Evidence Store skill in the ICS architecture, not by this module — but we
 * accept a resolver function in the context so the wrapper stays decoupled.
 */
export interface MemoryImageResolver {
  resolveMemoryPath(memoryId: string): Promise<string>;
}

// ────────────────────────────────────────────────────────────────────
// Core invocation
// ────────────────────────────────────────────────────────────────────

export async function runVolatilityPlugin<RowType = Record<string, unknown>>(
  args: {
    memoryId: string;
    plugin: string;
    pluginArgs?: string[];
    timeoutMs?: number;
  },
  ctx: VolatilityContext,
  resolver: MemoryImageResolver
): Promise<VolatilityResult<RowType>> {
  const executionId = `EXEC-${randomUUID()}`;
  const startedAt = new Date();

  // ── Validation ──
  if (!ALLOWED_PLUGINS.has(args.plugin)) {
    return {
      executionId,
      plugin: args.plugin,
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: 0,
      status: "error",
      memoryId: args.memoryId,
      rowCount: 0,
      rowsInline: [],
      error: `Plugin not in allowlist: ${args.plugin}`,
    };
  }

  // Validate plugin arguments — every arg must match a strict allowed pattern.
  // No shell metacharacters, no leading dashes other than known flags.
  if (args.pluginArgs) {
    for (const arg of args.pluginArgs) {
      if (!isSafePluginArg(arg)) {
        return {
          executionId,
          plugin: args.plugin,
          startedAt: startedAt.toISOString(),
          completedAt: new Date().toISOString(),
          durationMs: 0,
          status: "error",
          memoryId: args.memoryId,
          rowCount: 0,
          rowsInline: [],
          error: `Plugin argument failed validation: ${arg}`,
        };
      }
    }
  }

  // Resolve memory ID to a canonical path; verify path containment + read-only
  let memoryPath: string;
  try {
    memoryPath = await resolver.resolveMemoryPath(args.memoryId);
    ctx.pathGuard.validatePath(memoryPath);
    await ctx.readOnlyGuard.verifyFileReadOnly(memoryPath);
  } catch (err) {
    return {
      executionId,
      plugin: args.plugin,
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: 0,
      status: "error",
      memoryId: args.memoryId,
      rowCount: 0,
      rowsInline: [],
      error: `Memory resolution / validation failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  // ── Execution ──
  // vol command form (global flags MUST come before the plugin name):
  //   vol -q -r json -f <memory_path> <plugin> [plugin_args...]
  const cmdArgs = [
    "-q",                  // quiet (suppress progress on stderr)
    "-r", "json",          // JSON renderer
    "-f", memoryPath,      // memory image
    args.plugin,           // plugin name
    ...(args.pluginArgs ?? []),
  ];

  const timeoutMs = args.timeoutMs ?? ctx.config.defaultTimeoutMs;
  let stdout: string;
  let stderr: string;

  try {
    const result = await execFileP(ctx.config.volBinary, cmdArgs, {
      maxBuffer: ctx.config.maxBufferBytes,
      timeout: timeoutMs,
      // Crucially: NO shell. execFile passes args directly to execve(2).
      // Even if a plugin arg contained shell metacharacters, they wouldn't
      // be interpreted because there's no shell in the loop.
    });
    stdout = result.stdout;
    stderr = result.stderr;
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { stdout?: string; stderr?: string; killed?: boolean; signal?: string };
    const isTimeout = e.killed && e.signal === "SIGTERM";
    return {
      executionId,
      plugin: args.plugin,
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt.getTime(),
      status: isTimeout ? "timeout" : "error",
      memoryId: args.memoryId,
      rowCount: 0,
      rowsInline: [],
      error: isTimeout ? `Plugin exceeded timeout of ${timeoutMs}ms` : e.message,
      stderr: e.stderr,
    };
  }

  // ── Parse ──
  // Volatility 3 JSON renderer output is a JSON array of row objects.
  let rows: RowType[];
  try {
    rows = JSON.parse(stdout) as RowType[];
    if (!Array.isArray(rows)) {
      throw new Error(`Expected array, got ${typeof rows}`);
    }
  } catch (err) {
    return {
      executionId,
      plugin: args.plugin,
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt.getTime(),
      status: "error",
      memoryId: args.memoryId,
      rowCount: 0,
      rowsInline: [],
      error: `Failed to parse vol JSON output: ${err instanceof Error ? err.message : String(err)}`,
      stderr,
    };
  }

  // ── Spill to artifact file if too large ──
  let rowsInline = rows;
  let artifactRef: VolatilityResult["artifactRef"];

  if (rows.length > ctx.config.inlineRowLimit) {
    const artifactDir = join(ctx.pathGuard.getWorkingDir(), "vol_artifacts");
    await mkdir(artifactDir, { recursive: true });
    const artifactPath = join(
      artifactDir,
      `${executionId}_${args.plugin.replace(/\./g, "_")}.json`
    );
    const canonical = ctx.pathGuard.validatePath(artifactPath, true);
    const fullJson = JSON.stringify(rows, null, 2);
    await writeFile(canonical, fullJson);
    const fileStat = await stat(canonical);
    const hash = createHash("sha256").update(fullJson).digest("hex");

    artifactRef = {
      path: canonical,
      sizeBytes: fileStat.size,
      sha256: hash,
    };
    rowsInline = rows.slice(0, ctx.config.inlineRowLimit);
  }

  return {
    executionId,
    plugin: args.plugin,
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt.getTime(),
    status: "success",
    memoryId: args.memoryId,
    rowCount: rows.length,
    rowsInline,
    artifactRef,
  };
}

// ────────────────────────────────────────────────────────────────────
// Argument validation
// ────────────────────────────────────────────────────────────────────

/**
 * Plugin args are restricted to:
 *   - Pure integers (e.g. PID values for --pid)
 *   - Comma-separated integer lists
 *   - Known plugin flag names: --pid, --offset, --physical, --dump (rejected — write)
 *   - Hex addresses with 0x prefix
 *
 * Any arg containing shell metacharacters, spaces, quotes, or path traversal
 * sequences is rejected. This is defense in depth — we already use execFile
 * (no shell), but rejecting suspicious args also catches LLM mistakes early
 * and keeps the audit trail readable.
 */
export function isSafePluginArg(arg: string): boolean {
  if (typeof arg !== "string") return false;
  if (arg.length === 0 || arg.length > 256) return false;

  // Reject shell metacharacters, whitespace, quotes
  if (/[;&|`$<>"'\\\s]/.test(arg)) return false;

  // Reject the dump-class flags that would cause file writes
  const writeFlagPattern = /^(-{1,2})(dump|output|out-?file|extract|save)/i;
  if (writeFlagPattern.test(arg)) return false;

  // Allow known safe patterns
  const allowed = [
    /^-{1,2}pid$/,                         // --pid
    /^-{1,2}pids$/,                        // --pids
    /^-{1,2}offset$/,                      // --offset
    /^-{1,2}physical$/,                    // --physical
    /^-{1,2}virtaddr$/,                    // --virtaddr
    /^-{1,2}help$/,                        // --help
    /^\d+$/,                               // pure integer (PID)
    /^\d+(,\d+)+$/,                        // CSV of integers
    /^0x[0-9a-fA-F]+$/,                    // hex address
  ];

  return allowed.some((re) => re.test(arg));
}
