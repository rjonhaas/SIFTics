/**
 * ReadOnlyGuard — verifies the evidence mount is actually read-only
 * before any tool runs. A misconfiguration where the mount was set up
 * read-write must not silently pass; it must fail loudly.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

export interface ReadOnlyGuardConfig {
  evidenceMount: string;
}

export class ReadOnlyGuard {
  private readonly evidenceMount: string;
  private lastCheckMs = 0;
  private cachedResult = false;
  private readonly cacheWindowMs = 5_000; // revalidate every 5s

  constructor(config: ReadOnlyGuardConfig) {
    this.evidenceMount = config.evidenceMount;
  }

  /**
   * Verifies the evidence mount is currently mounted read-only.
   * Throws if mount is read-write or missing.
   */
  async verify(): Promise<void> {
    const now = Date.now();
    if (now - this.lastCheckMs < this.cacheWindowMs && this.cachedResult) {
      return;
    }

    let stdout = "";
    try {
      const result = await execFileP("findmnt", [
        "-n", "-o", "OPTIONS", "--target", this.evidenceMount,
      ]);
      stdout = result.stdout;
    } catch (err) {
      throw new Error(
        `ReadOnlyGuard: could not query mount for ${this.evidenceMount}: ` +
        `${err instanceof Error ? err.message : String(err)}`
      );
    }

    const options = stdout.trim().split(",");
    const isReadOnly = options.includes("ro");
    const isWritable = options.includes("rw");

    if (!isReadOnly || isWritable) {
      throw new Error(
        `ReadOnlyGuard: evidence mount ${this.evidenceMount} is NOT read-only. ` +
        `Mount options: ${options.join(",")}. Refusing to execute any tool.`
      );
    }

    this.lastCheckMs = now;
    this.cachedResult = true;
  }

  /**
   * Confirms a single file has no writable bit set for any user.
   * Defense in depth beyond mount options.
   */
  async verifyFileReadOnly(path: string): Promise<void> {
    const { stdout } = await execFileP("stat", ["-c", "%a", path]);
    const mode = parseInt(stdout.trim(), 8);

    // Any write bit set (user, group, other)
    const writableBits = 0o222;
    if ((mode & writableBits) !== 0) {
      throw new Error(
        `ReadOnlyGuard: file ${path} has writable permission bits: ${mode.toString(8)}`
      );
    }
  }

  invalidateCache(): void {
    this.lastCheckMs = 0;
    this.cachedResult = false;
  }
}
