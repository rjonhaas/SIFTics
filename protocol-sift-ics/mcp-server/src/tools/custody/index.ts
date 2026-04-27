/**
 * Evidence Custody tools — the workflow a real-world DFIR analyst performs
 * before any analysis begins:
 *   1. Hash the original (chain of custody starts here)
 *   2. Copy to a working location
 *   3. chmod 444 the copy
 *   4. Hash the copy
 *   5. Verify the two hashes match
 *   6. Append a custody chain entry that pins both hashes
 *
 * The Evidence Store skill owns this tool. After a working copy is
 * prepared, the MountManager's resolvers (resolveMemoryPath,
 * resolveEvidencePath, resolveCollectionPath) automatically prefer the
 * working copy so the analytical branches transparently operate on it.
 *
 * This is what unblocks Volatility on evidence sources whose mode bits
 * aren't already 444 — the original stays sealed at its mount-path mode,
 * the analyst works against a verified 444 copy under /working/evidence/.
 *
 * Path discipline: the source path is read from EVIDENCE_MOUNT (read-only
 * by mount option). The destination is under WORKING_DIR. PathGuard
 * validates both. We never write to the evidence mount.
 */

import { mkdir, copyFile, chmod, stat } from "node:fs/promises";
import { join, basename } from "node:path";

import type { PathGuard } from "../../safety/path_guard.js";
import type { ReadOnlyGuard } from "../../safety/readonly_guard.js";
import type { MountManager } from "../../evidence/mount_manager.js";
import type { HashRegistry } from "../../evidence/hash_registry.js";
import type { CustodyChainLog } from "../../evidence/custody_chain.js";
import { streamSha256 } from "../../evidence/custody_chain.js";

interface ToolHandler {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

interface CustodyContext {
  pathGuard: PathGuard;
  readOnlyGuard: ReadOnlyGuard;
  mountManager: MountManager;
  hashRegistry: HashRegistry;
  custodyChain: CustodyChainLog;
  workingDir: string;
}

const PREPARE_WORKING_COPY_SCHEMA = {
  type: "object",
  properties: {
    evidence_id: {
      type: "string",
      minLength: 1,
      description: "Evidence ID from the manifest (e.g. EVD-001).",
    },
    custodian: {
      type: "string",
      minLength: 1,
      description:
        "Skill ID requesting the working copy. Required for custody chain attribution. " +
        "Typically 'logistics/evidence-store' when the Evidence Store agent is the requester.",
    },
    period: {
      type: "integer",
      minimum: 0,
      description: "Operational period in which the request is made.",
    },
  },
  required: ["evidence_id", "custodian", "period"],
  additionalProperties: false,
};

export function registerCustodyTools(
  registry: Map<string, ToolHandler>,
  ctx: CustodyContext
): void {
  registry.set("prepare_working_copy", {
    name: "prepare_working_copy",
    description:
      "Evidence Store custody operation. Hashes the original evidence on the " +
      "read-only mount, copies it to /working/evidence/<EVD>/, chmods 444, " +
      "hashes the copy, verifies both hashes match, appends a custody chain " +
      "entry, and updates the MountManager so all subsequent tool resolutions " +
      "transparently use the working copy. Mirrors the chain-of-custody " +
      "workflow a human DFIR analyst performs before any analysis. Idempotent: " +
      "if the working copy already exists with a matching hash, the existing " +
      "copy is reused and a new custody entry recorded.",
    inputSchema: PREPARE_WORKING_COPY_SCHEMA,
    execute: async (args) => {
      const evidenceId = String(args.evidence_id);
      const custodian = String(args.custodian);
      const period = Number(args.period);

      const startedAt = new Date().toISOString();

      // Resolve original path (always the mount path, even if a working copy
      // exists — the custody chain pins the *original*, not the prior copy).
      const originalPath = ctx.mountManager.resolveOriginalPath(evidenceId);
      ctx.pathGuard.validatePath(originalPath);

      const inventoryEntry = ctx.mountManager
        .getInventory()
        .find((e) => e.id === evidenceId);
      if (!inventoryEntry) {
        throw new Error(`Evidence ${evidenceId} not in MountManager inventory`);
      }

      // Hash the original (streaming — files are GB-scale).
      const original = await streamSha256(originalPath);

      // Choose working copy location: /working/evidence/<EVD>/<basename>
      const workingDir = join(ctx.workingDir, "evidence", evidenceId);
      await mkdir(workingDir, { recursive: true });
      const workingCopyPath = join(workingDir, basename(originalPath));
      ctx.pathGuard.validatePath(workingCopyPath);

      // Idempotent path: if a copy already exists and its hash matches the
      // original, skip the copy itself but still record a fresh custody entry.
      let copySkipped = false;
      const existing = await stat(workingCopyPath).catch(() => null);
      if (existing) {
        const existingHash = await streamSha256(workingCopyPath);
        if (existingHash.sha256 === original.sha256) {
          copySkipped = true;
        }
      }

      if (!copySkipped) {
        // Working copy does not exist or its hash differs — make a fresh copy.
        // chmod after copy so the read can finish before the file becomes 444
        // (chmod 444 doesn't prevent the copy itself but defense-in-depth).
        await copyFile(originalPath, workingCopyPath);
      }
      // Always re-set 444 — handles the case where a partial run left looser bits.
      await chmod(workingCopyPath, 0o444);

      // Verify the copy.
      const copy = await streamSha256(workingCopyPath);
      const hashesMatch = copy.sha256 === original.sha256;
      if (!hashesMatch) {
        throw new Error(
          `prepare_working_copy: hash mismatch for ${evidenceId}. ` +
            `original=${original.sha256} copy=${copy.sha256}. Custody chain not updated.`
        );
      }

      // Append to custody chain (hash-chained, append-only).
      const custodyEntry = await ctx.custodyChain.append({
        evidenceId,
        evidenceType: inventoryEntry.type,
        originalPath,
        originalSha256: original.sha256,
        originalSizeBytes: original.sizeBytes,
        workingCopyPath,
        workingCopySha256: copy.sha256,
        workingCopySizeBytes: copy.sizeBytes,
        hashesMatch,
        custodian,
        period,
      });

      // Re-pin the working copy in the HashRegistry so the MCP server's
      // post-execution hash check (in index.ts) catches in-flight tampering
      // of the working copy too.
      ctx.hashRegistry.register(workingCopyPath, copy.sha256, copy.sizeBytes);

      // Tell the MountManager to route resolutions through the working copy.
      ctx.mountManager.setWorkingCopyPath(evidenceId, workingCopyPath);

      const completedAt = new Date().toISOString();
      return {
        executionId: custodyEntry.id,
        startedAt,
        completedAt,
        status: "success",
        data: {
          evidence_id: evidenceId,
          evidence_type: inventoryEntry.type,
          original_path: originalPath,
          original_sha256: original.sha256,
          original_size_bytes: original.sizeBytes,
          working_copy_path: workingCopyPath,
          working_copy_sha256: copy.sha256,
          working_copy_size_bytes: copy.sizeBytes,
          hashes_match: hashesMatch,
          custody_chain_id: custodyEntry.id,
          custody_chain_hash: custodyEntry.hash,
          copy_skipped_existing_match: copySkipped,
          custodian,
          period,
        },
      };
    },
  });
}
