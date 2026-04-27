/**
 * HashRegistry — maintains SHA-256 hashes of all mounted evidence and
 * verifies them on demand (every tool call post-execution, every
 * operational period boundary).
 *
 * Architectural guarantee: if any evidence file's hash changes between
 * registration and verification, the MCP server halts. This makes
 * accidental or malicious evidence modification detectable even if
 * PathGuard and ReadOnlyGuard are somehow bypassed.
 */

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat, readdir } from "node:fs/promises";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";

export interface HashRegistryConfig {
  registryPath: string;
}

interface HashEntry {
  /** Absolute path to the evidence file */
  path: string;
  /** SHA-256 hash computed at registration time */
  sha256: string;
  /** File size in bytes at registration time */
  sizeBytes: number;
  /** ISO timestamp when this entry was registered */
  registeredAt: string;
}

export class HashRegistry {
  private readonly registryPath: string;
  private entries: Map<string, HashEntry> = new Map();

  constructor(config: HashRegistryConfig) {
    this.registryPath = config.registryPath;
  }

  /**
   * Register a single evidence file. Computes its SHA-256 and stores it.
   * Call this at evidence ingest time (before any tool touches it).
   */
  async registerFile(filePath: string): Promise<HashEntry> {
    const hash = await this.computeHash(filePath);
    const fileStat = await stat(filePath);
    const entry: HashEntry = {
      path: filePath,
      sha256: hash,
      sizeBytes: fileStat.size,
      registeredAt: new Date().toISOString(),
    };
    this.entries.set(filePath, entry);
    return entry;
  }

  /**
   * Register all files under a directory (recursive).
   * Used at evidence mount time to baseline the entire image.
   */
  async registerDirectory(dirPath: string): Promise<number> {
    let count = 0;
    const walk = async (dir: string): Promise<void> => {
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch {
        // Permission denied or not a directory — skip
        return;
      }
      for (const entry of entries) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          await walk(full);
        } else if (entry.isFile()) {
          await this.registerFile(full);
          count++;
        }
      }
    };
    await walk(dirPath);
    return count;
  }

  /**
   * Verify all registered evidence files still match their original hashes.
   * Returns true if ALL hashes match; false if ANY mismatch is detected.
   *
   * Called by index.ts after every tool execution and by Evidence Store
   * at operational period boundaries.
   */
  async verifyAllMounted(): Promise<boolean> {
    if (this.entries.size === 0) {
      // No evidence registered — vacuously true.
      // This happens during development/testing without real evidence.
      return true;
    }

    for (const [path, entry] of this.entries) {
      try {
        const currentHash = await this.computeHash(path);
        if (currentHash !== entry.sha256) {
          console.error(
            `HashRegistry: MISMATCH on ${path}. ` +
            `Expected ${entry.sha256}, got ${currentHash}. ` +
            `Evidence may have been tampered with.`
          );
          return false;
        }
      } catch (err) {
        console.error(
          `HashRegistry: could not verify ${path}: ` +
          `${err instanceof Error ? err.message : String(err)}`
        );
        return false;
      }
    }
    return true;
  }

  /**
   * Verify a single file against its registered hash.
   */
  async verifyFile(filePath: string): Promise<boolean> {
    const entry = this.entries.get(filePath);
    if (!entry) {
      throw new Error(`HashRegistry: no registered hash for ${filePath}`);
    }
    const currentHash = await this.computeHash(filePath);
    return currentHash === entry.sha256;
  }

  /**
   * Get the registry snapshot (for audit log serialization).
   */
  getSnapshot(): HashEntry[] {
    return Array.from(this.entries.values());
  }

  /**
   * Number of registered evidence files.
   */
  get size(): number {
    return this.entries.size;
  }

  private async computeHash(filePath: string): Promise<string> {
    // Stream the file — fs.readFile would throw ERR_FS_FILE_TOO_LARGE for >2 GiB
    // (memory dumps and disk images routinely exceed that).
    const hash = createHash("sha256");
    await pipeline(createReadStream(filePath), hash);
    return hash.digest("hex");
  }
}
