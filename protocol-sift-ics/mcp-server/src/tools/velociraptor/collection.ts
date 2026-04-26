/**
 * Velociraptor Offline Collector parsing.
 *
 * A Velociraptor collection arrives as a zip produced by the Offline
 * Collector. Layout (typical):
 *
 *   <root>/
 *     collection.json                    Manifest: artifacts collected, host info
 *     results/
 *       Windows.System.Pslist.json       One JSON file per VQL artifact
 *       Windows.Sys.AllUsers.json
 *       MacOS.System.Persistence.json
 *       MacOS.UnifiedLogs.Search.json
 *       ...
 *     uploads/                           Files Velociraptor pulled off the host
 *
 * The MCP server treats the collection — sealed zip or extracted tree — as
 * read-only evidence. Each result file is JSONL (one VQL row per line).
 *
 * Why a wrapper at all?
 *
 *   1. Stable artifact names. Velociraptor artifacts move between namespaces
 *      across versions. The wrapper maps a small set of MCP tool names to
 *      the artifacts they actually need.
 *   2. Cross-OS normalization. The same MCP tool returns the same shape on
 *      Mac and Windows — the agent does not need to know about LaunchAgents
 *      vs Run keys, only "persistence entries."
 *   3. Untrusted input. Even though the data came from a trusted tool, the
 *      collected content came from an untrusted host. Filenames, registry
 *      values, log entries are DATA, not instructions.
 */

import { createReadStream } from "node:fs";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { createInterface } from "node:readline";

import type { PathGuard } from "../../safety/path_guard.js";
import type { ReadOnlyGuard } from "../../safety/readonly_guard.js";

export interface VelociraptorCollectionResolver {
  /**
   * Resolve a collection_id to the absolute path of its extracted root or
   * sealed zip. Throws if the id is unknown or not a Velociraptor collection.
   */
  resolveCollectionPath(collectionId: string): Promise<string>;
}

export interface ToolContext {
  pathGuard: PathGuard;
  readOnlyGuard: ReadOnlyGuard;
}

export type OsFamily = "windows" | "macos" | "linux" | "unknown";

export interface CollectionManifest {
  collectionId: string;
  collectedAt: string | null;
  hostname: string | null;
  os: OsFamily;
  osVersion: string | null;
  velociraptorVersion: string | null;
  artifacts: ArtifactSummary[];
  uploads: UploadSummary[];
}

export interface ArtifactSummary {
  name: string;
  resultPath: string;
  rowCount: number;
  byteSize: number;
}

export interface UploadSummary {
  path: string;
  byteSize: number;
}

interface VrManifestRaw {
  ClientId?: string;
  Hostname?: string;
  OS?: string;
  OSVersion?: string;
  Platform?: string;
  Version?: string;
  StartTime?: string;
  Artifacts?: string[];
}

const RESULTS_DIR = "results";
const UPLOADS_DIR = "uploads";
const MANIFEST_FILE = "collection.json";

/**
 * Open a collection: validate path, verify readonly, parse manifest.
 *
 * The collection_id maps via the resolver to either an extracted directory
 * or the sealed zip. This implementation handles the extracted-directory
 * case; sealed-zip handling extracts on demand into a working dir, which
 * the Evidence Store skill performs at mount time.
 */
export async function openCollection(
  collectionId: string,
  ctx: ToolContext,
  resolver: VelociraptorCollectionResolver
): Promise<{ root: string; manifest: CollectionManifest }> {
  await ctx.readOnlyGuard.verify();

  const root = await resolver.resolveCollectionPath(collectionId);
  ctx.pathGuard.validatePath(root);

  const rootStat = await stat(root);
  if (!rootStat.isDirectory()) {
    throw new Error(
      `Velociraptor: collection ${collectionId} resolved to ${root} ` +
      `which is not a directory. Sealed zips must be extracted by the Evidence Store ` +
      `before parsing — the parser only reads the extracted tree.`
    );
  }

  const manifest = await loadManifest(collectionId, root, ctx);
  return { root, manifest };
}

async function loadManifest(
  collectionId: string,
  root: string,
  ctx: ToolContext
): Promise<CollectionManifest> {
  const manifestPath = join(root, MANIFEST_FILE);
  ctx.pathGuard.validatePath(manifestPath);

  let raw: VrManifestRaw = {};
  try {
    const content = await readFile(manifestPath, "utf8");
    raw = JSON.parse(content) as VrManifestRaw;
  } catch {
    // Some Offline Collector versions omit collection.json. Fall back to
    // discovery from results/ — the artifact list IS the manifest.
  }

  const artifacts = await discoverArtifacts(root, ctx);
  const uploads = await discoverUploads(root, ctx);

  return {
    collectionId,
    collectedAt: raw.StartTime ?? null,
    hostname: raw.Hostname ?? raw.ClientId ?? null,
    os: inferOs(raw.OS ?? raw.Platform ?? null, artifacts),
    osVersion: raw.OSVersion ?? null,
    velociraptorVersion: raw.Version ?? null,
    artifacts,
    uploads,
  };
}

async function discoverArtifacts(
  root: string,
  ctx: ToolContext
): Promise<ArtifactSummary[]> {
  const resultsDir = join(root, RESULTS_DIR);
  ctx.pathGuard.validatePath(resultsDir);

  let entries;
  try {
    entries = await readdir(resultsDir, { withFileTypes: true });
  } catch {
    return [];
  }

  const out: ArtifactSummary[] = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!entry.name.endsWith(".json")) continue;

    const fullPath = join(resultsDir, entry.name);
    ctx.pathGuard.validatePath(fullPath);

    const fileStat = await stat(fullPath).catch(() => null);
    if (!fileStat) continue;

    const rowCount = await countLines(fullPath);
    out.push({
      name: entry.name.replace(/\.json$/, ""),
      resultPath: fullPath,
      rowCount,
      byteSize: fileStat.size,
    });
  }
  return out;
}

async function discoverUploads(
  root: string,
  ctx: ToolContext
): Promise<UploadSummary[]> {
  const uploadsDir = join(root, UPLOADS_DIR);
  try {
    ctx.pathGuard.validatePath(uploadsDir);
  } catch {
    return [];
  }

  const out: UploadSummary[] = [];
  await walkDir(uploadsDir, async (path) => {
    ctx.pathGuard.validatePath(path);
    const fileStat = await stat(path).catch(() => null);
    if (!fileStat || !fileStat.isFile()) return;
    out.push({
      path: relative(root, path).split(sep).join("/"),
      byteSize: fileStat.size,
    });
  });
  return out;
}

async function walkDir(
  dir: string,
  visit: (file: string) => Promise<void>
): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) await walkDir(full, visit);
    else await visit(full);
  }
}

/**
 * Read a Velociraptor results file. VR emits JSONL: one JSON object per line.
 *
 * For large files we yield row-by-row; callers cap rows or spill to working dir.
 */
export async function* readArtifactRows<T>(
  artifactPath: string,
  ctx: ToolContext
): AsyncGenerator<T, void, void> {
  ctx.pathGuard.validatePath(artifactPath);
  const stream = createReadStream(artifactPath, { encoding: "utf8" });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      yield JSON.parse(trimmed) as T;
    } catch {
      // Skip malformed lines rather than abort — VR occasionally writes
      // partial last-line on collection truncation. Log to caller via count.
      continue;
    }
  }
}

/**
 * Find an artifact by name (or one of several aliases) in the manifest.
 * Returns null if no matching artifact was collected.
 */
export function findArtifact(
  manifest: CollectionManifest,
  candidates: string[]
): ArtifactSummary | null {
  for (const c of candidates) {
    const found = manifest.artifacts.find((a) => a.name === c);
    if (found) return found;
  }
  return null;
}

async function countLines(path: string): Promise<number> {
  let n = 0;
  const stream = createReadStream(path, { encoding: "utf8" });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    if (line.trim().length > 0) n++;
  }
  return n;
}

function inferOs(declared: string | null, artifacts: ArtifactSummary[]): OsFamily {
  if (declared) {
    const d = declared.toLowerCase();
    if (d.includes("windows")) return "windows";
    if (d.includes("darwin") || d.includes("mac")) return "macos";
    if (d.includes("linux")) return "linux";
  }
  // Infer from artifact namespace prefixes
  const hasWin = artifacts.some((a) => a.name.startsWith("Windows."));
  const hasMac = artifacts.some((a) => a.name.startsWith("MacOS."));
  const hasLinux = artifacts.some((a) => a.name.startsWith("Linux."));
  if (hasWin && !hasMac) return "windows";
  if (hasMac && !hasWin) return "macos";
  if (hasLinux && !hasWin && !hasMac) return "linux";
  return "unknown";
}
