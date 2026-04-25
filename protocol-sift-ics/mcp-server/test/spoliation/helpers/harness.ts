/**
 * Spoliation Test Harness
 *
 * Creates an isolated evidence fixture, captures its state (hashes + timestamps
 * + mount options + directory listing), runs an attack function against it,
 * then re-captures state and diffs the two. Any divergence means spoliation
 * occurred and the test fails.
 */

import { readdir, stat, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join, relative } from "node:path";

const execFileP = promisify(execFile);

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface FileSnapshot {
  relativePath: string;
  sizeBytes: number;
  sha256: string;
  // Precision: POSIX mtime is second-precision by default; use nanosecond fields where available
  mtimeNs: bigint;
  atimeNs: bigint;
  ctimeNs: bigint;
  mode: number;
  inode: bigint;
}

export interface MountSnapshot {
  mountPoint: string;
  mountOptions: string[];
  isReadOnly: boolean;
  device: string;
}

export interface EvidenceSnapshot {
  capturedAt: string;
  evidenceRoot: string;
  mount: MountSnapshot;
  files: FileSnapshot[];
  directoryListing: string[];
}

export interface AttackResult {
  attackId: string;
  category: string;
  name: string;
  description: string;
  executedAt: string;
  durationMs: number;
  // What the attack tried to do
  attemptedAction: string;
  // Was the attack blocked at the expected layer?
  expectedBlockLayer: "path_guard" | "readonly_guard" | "mcp_server" | "filesystem" | "hash_registry";
  // What happened
  outcome: "blocked_correctly" | "blocked_wrong_layer" | "not_blocked_but_harmless" | "SPOLIATION";
  blockingLayer?: string;
  errorMessage?: string;
  // Evidence state comparison
  evidenceDiff: EvidenceDiff;
  // Was this a pass (spoliation prevented) or fail (spoliation occurred)?
  passed: boolean;
}

export interface EvidenceDiff {
  filesAdded: string[];
  filesRemoved: string[];
  filesModified: Array<{
    path: string;
    hashChanged: boolean;
    sizeChanged: boolean;
    mtimeChanged: boolean;
    atimeChanged: boolean;
    ctimeChanged: boolean;
    modeChanged: boolean;
    inodeChanged: boolean;
  }>;
  mountOptionsChanged: boolean;
  mountStateWritable: boolean;
}

// ────────────────────────────────────────────────────────────────────
// State capture
// ────────────────────────────────────────────────────────────────────

export async function captureEvidenceState(evidenceRoot: string): Promise<EvidenceSnapshot> {
  const mount = await captureMountState(evidenceRoot);
  const files = await captureFileSnapshots(evidenceRoot);
  const directoryListing = files.map((f) => f.relativePath).sort();

  return {
    capturedAt: new Date().toISOString(),
    evidenceRoot,
    mount,
    files,
    directoryListing,
  };
}

async function captureMountState(mountPoint: string): Promise<MountSnapshot> {
  try {
    const { stdout: optionsOut } = await execFileP("findmnt", [
      "-n", "-o", "OPTIONS", "--target", mountPoint,
    ]);
    const { stdout: sourceOut } = await execFileP("findmnt", [
      "-n", "-o", "SOURCE", "--target", mountPoint,
    ]);
    const options = optionsOut.trim().split(",");
    return {
      mountPoint,
      mountOptions: options,
      isReadOnly: options.includes("ro") && !options.includes("rw"),
      device: sourceOut.trim(),
    };
  } catch {
    // Not a mount point — treat as regular directory for tests
    return {
      mountPoint,
      mountOptions: ["not_mounted"],
      isReadOnly: false,
      device: "directory",
    };
  }
}

async function captureFileSnapshots(root: string): Promise<FileSnapshot[]> {
  const results: FileSnapshot[] = [];
  await walk(root, root, results);
  return results.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
}

async function walk(root: string, current: string, results: FileSnapshot[]): Promise<void> {
  const entries = await readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(current, entry.name);
    const rel = relative(root, full);

    if (entry.isDirectory()) {
      await walk(root, full, results);
      continue;
    }

    if (!entry.isFile()) continue;

    const st = await stat(full, { bigint: true });
    const content = await readFile(full);
    const hash = createHash("sha256").update(content).digest("hex");

    results.push({
      relativePath: rel,
      sizeBytes: Number(st.size),
      sha256: hash,
      mtimeNs: st.mtimeNs,
      atimeNs: st.atimeNs,
      ctimeNs: st.ctimeNs,
      mode: Number(st.mode),
      inode: st.ino,
    });
  }
}

// ────────────────────────────────────────────────────────────────────
// Diff
// ────────────────────────────────────────────────────────────────────

export function diffEvidenceState(
  before: EvidenceSnapshot,
  after: EvidenceSnapshot
): EvidenceDiff {
  const beforeMap = new Map(before.files.map((f) => [f.relativePath, f]));
  const afterMap = new Map(after.files.map((f) => [f.relativePath, f]));

  const filesAdded: string[] = [];
  const filesRemoved: string[] = [];
  const filesModified: EvidenceDiff["filesModified"] = [];

  for (const [path, afterFile] of afterMap) {
    const beforeFile = beforeMap.get(path);
    if (!beforeFile) {
      filesAdded.push(path);
      continue;
    }
    const changes = compareFiles(beforeFile, afterFile);
    if (changes) {
      filesModified.push({ path, ...changes });
    }
  }

  for (const path of beforeMap.keys()) {
    if (!afterMap.has(path)) {
      filesRemoved.push(path);
    }
  }

  return {
    filesAdded,
    filesRemoved,
    filesModified,
    mountOptionsChanged:
      JSON.stringify(before.mount.mountOptions.sort()) !==
      JSON.stringify(after.mount.mountOptions.sort()),
    mountStateWritable: !after.mount.isReadOnly,
  };
}

function compareFiles(before: FileSnapshot, after: FileSnapshot): Omit<EvidenceDiff["filesModified"][0], "path"> | null {
  const hashChanged = before.sha256 !== after.sha256;
  const sizeChanged = before.sizeBytes !== after.sizeBytes;
  const mtimeChanged = before.mtimeNs !== after.mtimeNs;
  const atimeChanged = before.atimeNs !== after.atimeNs;
  const ctimeChanged = before.ctimeNs !== after.ctimeNs;
  const modeChanged = before.mode !== after.mode;
  const inodeChanged = before.inode !== after.inode;

  const anyChange = hashChanged || sizeChanged || mtimeChanged ||
    atimeChanged || ctimeChanged || modeChanged || inodeChanged;

  return anyChange
    ? { hashChanged, sizeChanged, mtimeChanged, atimeChanged, ctimeChanged, modeChanged, inodeChanged }
    : null;
}

// ────────────────────────────────────────────────────────────────────
// Pass/Fail judgment
// ────────────────────────────────────────────────────────────────────

export function judgeAttack(diff: EvidenceDiff): {
  spoliated: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];

  if (diff.filesAdded.length > 0) {
    reasons.push(`Files added to evidence: ${diff.filesAdded.join(", ")}`);
  }
  if (diff.filesRemoved.length > 0) {
    reasons.push(`Files removed from evidence: ${diff.filesRemoved.join(", ")}`);
  }
  if (diff.mountStateWritable) {
    reasons.push("Evidence mount is no longer read-only");
  }
  if (diff.mountOptionsChanged) {
    reasons.push("Mount options were changed during attack");
  }

  for (const mod of diff.filesModified) {
    const issues: string[] = [];
    if (mod.hashChanged) issues.push("hash");
    if (mod.sizeChanged) issues.push("size");
    if (mod.mtimeChanged) issues.push("mtime");
    if (mod.atimeChanged) issues.push("atime");
    if (mod.ctimeChanged) issues.push("ctime");
    if (mod.modeChanged) issues.push("mode");
    if (mod.inodeChanged) issues.push("inode");
    if (issues.length > 0) {
      reasons.push(`File modified (${mod.path}): ${issues.join(", ")}`);
    }
  }

  return {
    spoliated: reasons.length > 0,
    reasons,
  };
}

// ────────────────────────────────────────────────────────────────────
// Attack runner
// ────────────────────────────────────────────────────────────────────

export interface AttackDefinition {
  id: string;
  category: string;
  name: string;
  description: string;
  attemptedAction: string;
  expectedBlockLayer: AttackResult["expectedBlockLayer"];
  execute: (ctx: AttackContext) => Promise<{ thrown?: Error; result?: unknown }>;
}

export interface AttackContext {
  evidenceRoot: string;
  workingDir: string;
  // Helper for calling the MCP server as if it were a branch agent
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
}

export async function runAttack(
  attack: AttackDefinition,
  ctx: AttackContext
): Promise<AttackResult> {
  const startedAt = Date.now();
  const before = await captureEvidenceState(ctx.evidenceRoot);

  let thrown: Error | undefined;
  let rawResult: unknown;

  try {
    const outcome = await attack.execute(ctx);
    thrown = outcome.thrown;
    rawResult = outcome.result;
  } catch (err) {
    thrown = err instanceof Error ? err : new Error(String(err));
  }

  const after = await captureEvidenceState(ctx.evidenceRoot);
  const diff = diffEvidenceState(before, after);
  const judgment = judgeAttack(diff);

  // Categorize the outcome
  let outcomeLabel: AttackResult["outcome"];
  if (judgment.spoliated) {
    outcomeLabel = "SPOLIATION";
  } else if (thrown) {
    outcomeLabel = "blocked_correctly";
  } else {
    // Attack did not throw but also did not cause spoliation.
    // Example: the attack tried to write to an MCP function that the server
    // politely returned a structured error for instead of throwing.
    outcomeLabel = "not_blocked_but_harmless";
  }

  return {
    attackId: attack.id,
    category: attack.category,
    name: attack.name,
    description: attack.description,
    executedAt: new Date(startedAt).toISOString(),
    durationMs: Date.now() - startedAt,
    attemptedAction: attack.attemptedAction,
    expectedBlockLayer: attack.expectedBlockLayer,
    outcome: outcomeLabel,
    blockingLayer: thrown ? inferBlockingLayer(thrown.message) : undefined,
    errorMessage: thrown?.message,
    evidenceDiff: diff,
    passed: !judgment.spoliated,
  };
}

function inferBlockingLayer(errorMessage: string): string {
  if (errorMessage.includes("PathGuard")) return "path_guard";
  if (errorMessage.includes("ReadOnlyGuard")) return "readonly_guard";
  if (errorMessage.includes("EVIDENCE_HASH_MISMATCH")) return "hash_registry";
  if (errorMessage.includes("Unknown tool")) return "mcp_server";
  if (errorMessage.includes("EROFS") || errorMessage.includes("read-only")) return "filesystem";
  return "unknown";
}
