/**
 * PathGuard — enforces the architectural guarantee that every file path
 * referenced by any tool call is contained within either:
 *   1. The evidence mount (read-only)
 *   2. An assigned branch working directory (writable to its branch only)
 *
 * Any attempt to reference a path outside these boundaries fails before
 * the tool runs. This is defense in depth — the MCP server also does
 * not expose write functions, but PathGuard catches path traversal
 * attempts at the argument layer.
 */

import { resolve, isAbsolute, relative } from "node:path";

export interface PathGuardConfig {
  evidenceMount: string;
  workingDir: string;
}

export class PathGuard {
  private readonly evidenceMount: string;
  private readonly workingDir: string;

  constructor(config: PathGuardConfig) {
    // Canonical, absolute paths. Any symlink resolution happens here.
    this.evidenceMount = resolve(config.evidenceMount);
    this.workingDir = resolve(config.workingDir);
  }

  /**
   * Throws if the given path is not contained within evidence or working dirs.
   * Returns the canonical resolved path if valid.
   */
  validatePath(candidate: string, allowWrite = false): string {
    if (!candidate || typeof candidate !== "string") {
      throw new Error(`PathGuard: invalid path value`);
    }
    if (!isAbsolute(candidate)) {
      throw new Error(`PathGuard: relative paths not permitted: ${candidate}`);
    }

    const canonical = resolve(candidate);

    const inEvidence = this.isContained(canonical, this.evidenceMount);
    const inWorking = this.isContained(canonical, this.workingDir);

    if (!inEvidence && !inWorking) {
      throw new Error(
        `PathGuard: path is outside allowed boundaries: ${candidate} ` +
        `(allowed: ${this.evidenceMount}, ${this.workingDir})`
      );
    }

    if (allowWrite && inEvidence) {
      throw new Error(
        `PathGuard: write operations are not permitted on evidence paths: ${candidate}`
      );
    }

    return canonical;
  }

  /**
   * Scan tool arguments recursively for anything that looks like a path
   * and validate it. Call this on every tool invocation as a safety net.
   */
  validateArguments(args: Record<string, unknown>): void {
    const pathKeys = [
      "path", "file_path", "sample_path", "evidence_path",
      "output_path", "source", "target", "destination",
    ];

    const walk = (obj: unknown): void => {
      if (obj === null || obj === undefined) return;
      if (typeof obj === "string") return; // values walked via parent key check

      if (Array.isArray(obj)) {
        for (const item of obj) walk(item);
        return;
      }

      if (typeof obj === "object") {
        for (const [key, value] of Object.entries(obj)) {
          if (typeof value === "string" && this.keyLooksLikePath(key, pathKeys)) {
            this.validatePath(value);
          } else {
            walk(value);
          }
        }
      }
    };

    walk(args);
  }

  private keyLooksLikePath(key: string, pathKeys: string[]): boolean {
    const lower = key.toLowerCase();
    return pathKeys.some((pk) => lower === pk || lower.endsWith(`_${pk}`) || lower.endsWith(`${pk}`));
  }

  private isContained(candidate: string, container: string): boolean {
    const rel = relative(container, candidate);
    return !rel.startsWith("..") && !isAbsolute(rel);
  }

  getEvidenceMount(): string {
    return this.evidenceMount;
  }

  getWorkingDir(): string {
    return this.workingDir;
  }
}
