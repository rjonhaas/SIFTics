/**
 * Chain of Custody log — records every working-copy preparation event
 * the swarm performs. Each entry pins:
 *   - the original evidence's path and SHA-256
 *   - the working-copy path and SHA-256
 *   - whether the two hashes matched (must always be true for the entry
 *     to be valid; mismatch raises a hard failure)
 *   - the actor (skill id) that requested preparation
 *   - the operational period
 *
 * The custody chain is hash-chained the same way audit_log.ts is: each
 * entry includes the prior entry's hash, and any tampering breaks the
 * chain on replay. This is what the Documentation Unit's `trace_finding`
 * query traverses when establishing forensic provenance back to source.
 *
 * Format: append-only JSONL at /working/custody_chain.jsonl. Layered on
 * top of HashRegistry (which pins evidence hashes for ReadOnlyGuard's
 * post-execution check) — different role: HashRegistry catches mid-run
 * tampering, custody chain documents intentional, pre-analysis copies.
 */

import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile, stat } from "node:fs/promises";
import { existsSync, createReadStream } from "node:fs";
import { dirname } from "node:path";
import { pipeline } from "node:stream/promises";

const GENESIS_HASH = "0".repeat(64);

export interface CustodyEntry {
  id: string;
  ts: string;
  prevHash: string;
  hash: string;
  evidenceId: string;
  evidenceType: string;
  originalPath: string;
  originalSha256: string;
  originalSizeBytes: number;
  workingCopyPath: string;
  workingCopySha256: string;
  workingCopySizeBytes: number;
  hashesMatch: boolean;
  custodian: string;
  period: number;
}

export class CustodyChainLog {
  private nextSeq = 1;
  private lastHash = GENESIS_HASH;

  private constructor(private readonly path: string) {}

  static async open(path: string): Promise<CustodyChainLog> {
    await mkdir(dirname(path), { recursive: true });
    const log = new CustodyChainLog(path);
    if (existsSync(path)) {
      await log.replayChain();
    } else {
      await writeFile(path, "");
    }
    return log;
  }

  async append(
    fields: Omit<CustodyEntry, "id" | "ts" | "prevHash" | "hash">
  ): Promise<CustodyEntry> {
    const entry: CustodyEntry = {
      id: `CUSTODY-${String(this.nextSeq).padStart(6, "0")}`,
      ts: new Date().toISOString(),
      prevHash: this.lastHash,
      hash: "",
      ...fields,
    };
    entry.hash = hashEntry(entry);
    await appendFile(this.path, JSON.stringify(entry) + "\n");
    this.nextSeq++;
    this.lastHash = entry.hash;
    return entry;
  }

  async replayChain(): Promise<CustodyEntry[]> {
    const raw = await readFile(this.path, "utf8");
    const lines = raw.split("\n").filter((l) => l.trim().length > 0);
    const out: CustodyEntry[] = [];
    let expected = GENESIS_HASH;
    for (const line of lines) {
      const e = JSON.parse(line) as CustodyEntry;
      if (e.prevHash !== expected) {
        throw new Error(
          `CustodyChainLog: chain broken at ${e.id} — expected ${expected}, got ${e.prevHash}`
        );
      }
      const recomputed = hashEntry(e);
      if (recomputed !== e.hash) {
        throw new Error(
          `CustodyChainLog: tampered entry ${e.id} — recomputed ${recomputed} ≠ stored ${e.hash}`
        );
      }
      out.push(e);
      expected = e.hash;
    }
    if (out.length > 0) {
      const last = out[out.length - 1];
      const m = last.id.match(/^CUSTODY-(\d+)$/);
      if (m) this.nextSeq = Number(m[1]) + 1;
      this.lastHash = last.hash;
    }
    return out;
  }
}

function hashEntry(e: CustodyEntry): string {
  const { hash: _omit, ...rest } = e;
  return createHash("sha256").update(JSON.stringify(rest)).digest("hex");
}

/** Compute SHA-256 of a file via streaming. Files are GB-scale; do not
 *  buffer in memory. */
export async function streamSha256(path: string): Promise<{ sha256: string; sizeBytes: number }> {
  const hash = createHash("sha256");
  let sizeBytes = 0;
  const stream = createReadStream(path);
  stream.on("data", (chunk) => {
    sizeBytes += chunk.length;
  });
  await pipeline(stream, hash);
  return { sha256: hash.digest("hex"), sizeBytes };
}
