/**
 * Prefetch parsing tools.
 *
 * This module exemplifies the typed-function pattern used throughout
 * the Protocol SIFT MCP server:
 *
 *   1. Typed parameters (no free-form strings that could be shell-injected)
 *   2. Read-only access to evidence via validated paths
 *   3. Raw tool output parsed into structured records before returning
 *   4. Large results spilled to the working directory with a summary returned
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { PathGuard } from "../../safety/path_guard.js";
import type { ReadOnlyGuard } from "../../safety/readonly_guard.js";

const execFileP = promisify(execFile);

export interface ToolContext {
  pathGuard: PathGuard;
  readOnlyGuard: ReadOnlyGuard;
}

export interface PrefetchSummaryArgs {
  evidence_id: string;
  top_n?: number;
}

export interface PrefetchSummaryResult {
  executionId: string;
  evidenceId: string;
  totalPrefetchFiles: number;
  recentExecutions: Array<{
    executable: string;
    lastRunTime: string;
    runCount: number;
    volume: string;
  }>;
}

/**
 * parse_prefetch_summary
 *
 * Returns the top N most recent executions from prefetch files.
 * Designed for Triage Branch — fast, summary-only.
 */
export async function parsePrefetchSummary(
  args: PrefetchSummaryArgs,
  ctx: ToolContext
): Promise<PrefetchSummaryResult> {
  const executionId = `EXEC-${randomUUID()}`;
  const topN = args.top_n ?? 20;

  // Verify mount is still read-only
  await ctx.readOnlyGuard.verify();

  // Resolve the prefetch directory for this evidence (read-only)
  const prefetchDir = await resolvePrefetchDir(args.evidence_id, ctx);
  ctx.pathGuard.validatePath(prefetchDir);

  // Invoke SIFT's prefetch parser. NOTE: we use execFile (no shell),
  // the binary takes typed arguments, and output is captured and parsed.
  const { stdout } = await execFileP(
    "PECmd.exe",  // SIFT tool — runs under Mono/Wine or native port
    ["-d", prefetchDir, "--json", "-"],
    { maxBuffer: 200 * 1024 * 1024 }
  );

  const raw = JSON.parse(stdout);

  const recent = (raw as Array<RawPrefetchRecord>)
    .sort((a, b) => new Date(b.LastRun).getTime() - new Date(a.LastRun).getTime())
    .slice(0, topN)
    .map((r) => ({
      executable: r.ExecutableName,
      lastRunTime: r.LastRun,
      runCount: r.RunCount,
      volume: r.VolumeInformation?.[0]?.DeviceName ?? "",
    }));

  return {
    executionId,
    evidenceId: args.evidence_id,
    totalPrefetchFiles: raw.length,
    recentExecutions: recent,
  };
}

export interface PrefetchDetailedArgs {
  evidence_id: string;
  prefetch_filename?: string;
}

export interface PrefetchDetailedResult {
  executionId: string;
  evidenceId: string;
  summary: {
    fileCount: number;
    writtenToArtifact: boolean;
  };
  artifactRef?: {
    path: string;
    sizeBytes: number;
    sha256: string;
  };
  record?: ParsedPrefetchRecord;  // populated only if a single file was requested
}

/**
 * parse_prefetch_detailed
 *
 * Full parse of prefetch data. If a single file is requested, returns it inline.
 * If all files are requested, writes parsed records to an artifact file in the
 * branch's working directory and returns a summary + artifact pointer.
 */
export async function parsePrefetchDetailed(
  args: PrefetchDetailedArgs,
  ctx: ToolContext
): Promise<PrefetchDetailedResult> {
  const executionId = `EXEC-${randomUUID()}`;

  await ctx.readOnlyGuard.verify();
  const prefetchDir = await resolvePrefetchDir(args.evidence_id, ctx);
  ctx.pathGuard.validatePath(prefetchDir);

  if (args.prefetch_filename) {
    // Single-file parse — return inline
    const { stdout } = await execFileP(
      "PECmd.exe",
      ["-f", join(prefetchDir, args.prefetch_filename), "--json", "-"]
    );
    const parsed = JSON.parse(stdout) as ParsedPrefetchRecord;
    return {
      executionId,
      evidenceId: args.evidence_id,
      summary: { fileCount: 1, writtenToArtifact: false },
      record: parsed,
    };
  }

  // Full parse — write to artifact
  const { stdout } = await execFileP(
    "PECmd.exe",
    ["-d", prefetchDir, "--json", "-"],
    { maxBuffer: 500 * 1024 * 1024 }
  );

  const records = JSON.parse(stdout) as ParsedPrefetchRecord[];
  const artifactPath = join(
    ctx.pathGuard.getWorkingDir(),
    "parsed_artifacts",
    `prefetch_${executionId}.json`
  );
  const canonicalArtifactPath = ctx.pathGuard.validatePath(artifactPath, /* allowWrite */ true);
  await writeFile(canonicalArtifactPath, JSON.stringify(records, null, 2));

  return {
    executionId,
    evidenceId: args.evidence_id,
    summary: { fileCount: records.length, writtenToArtifact: true },
    artifactRef: {
      path: canonicalArtifactPath,
      sizeBytes: (await import("node:fs/promises")).then ? 0 : 0,  // populated by caller with stat
      sha256: "",  // populated by caller
    },
  };
}

// ────────────────────────────────────────────────────────────────────
// Internals
// ────────────────────────────────────────────────────────────────────

interface RawPrefetchRecord {
  ExecutableName: string;
  LastRun: string;
  RunCount: number;
  VolumeInformation?: Array<{ DeviceName: string }>;
}

interface ParsedPrefetchRecord {
  executableName: string;
  sourceFilename: string;
  runCount: number;
  lastRunTimes: string[];
  hash: string;
  volumeInformation: Array<{
    deviceName: string;
    createdOn: string;
    serialNumber: string;
  }>;
  filesReferenced: string[];
  directoriesReferenced: string[];
}

async function resolvePrefetchDir(evidenceId: string, _ctx: ToolContext): Promise<string> {
  // In a real implementation this consults the evidence inventory to find
  // the mounted Windows root for this evidence_id and returns the path to
  // its Prefetch directory. The inventory lookup is read-only.
  //
  // For the scaffold we return a deterministic path under the mount.
  return `/mnt/evidence/${evidenceId}/Windows/Prefetch`;
}

// ────────────────────────────────────────────────────────────────────
// Registration
// ────────────────────────────────────────────────────────────────────

export const PREFETCH_SUMMARY_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    top_n: { type: "integer", minimum: 1, maximum: 500, default: 20 },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;

export const PREFETCH_DETAILED_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: { type: "string" },
    prefetch_filename: { type: "string" },
  },
  required: ["evidence_id"],
  additionalProperties: false,
} as const;
