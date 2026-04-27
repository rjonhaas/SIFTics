/**
 * MountManager — manages evidence mounting lifecycle and provides
 * path resolution for evidence IDs.
 *
 * In the ICS architecture, the Evidence Store skill owns the mounting
 * policy (ro,noatime,noexec,nodev). This module implements the
 * mechanics: tracking what's mounted, resolving opaque evidence IDs
 * to filesystem paths, and providing the MemoryImageResolver interface
 * that the Volatility wrapper needs.
 *
 * Architectural guarantees:
 *   - Evidence is always read-only (verified by ReadOnlyGuard)
 *   - Paths are always within EVIDENCE_MOUNT (verified by PathGuard)
 *   - Evidence IDs are opaque — agents never see raw filesystem paths
 */

import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";

import type { PathGuard } from "../safety/path_guard.js";
import type { ReadOnlyGuard } from "../safety/readonly_guard.js";
import type { MemoryImageResolver } from "../tools/memory/volatility.js";
import type { VelociraptorCollectionResolver } from "../tools/velociraptor/collection.js";

export interface MountManagerConfig {
  evidenceMount: string;
  pathGuard: PathGuard;
  readOnlyGuard: ReadOnlyGuard;
}

interface EvidenceEntry {
  /** Opaque ID assigned at registration (e.g. "EVD-001") */
  id: string;
  /** Absolute path under the evidence mount — original, never analyzed directly */
  mountPath: string;
  /** Path to the analyst's working copy (mode 444) once Evidence Store has
   *  prepared it. Resolvers prefer this over mountPath. Per the chain-of-custody
   *  workflow, all analysis runs on the working copy; the original is sealed. */
  workingCopyPath?: string;
  /** Type of evidence: disk image, memory dump, PCAP, etc. */
  type: "disk" | "memory" | "pcap" | "logs" | "velociraptor" | "other";
  /** ISO timestamp when registered */
  registeredAt: string;
}

export class MountManager implements MemoryImageResolver, VelociraptorCollectionResolver {
  private readonly evidenceMount: string;
  private readonly pathGuard: PathGuard;
  private readonly readOnlyGuard: ReadOnlyGuard;
  private readonly evidence: Map<string, EvidenceEntry> = new Map();
  private nextId = 1;

  constructor(config: MountManagerConfig) {
    this.evidenceMount = config.evidenceMount;
    this.pathGuard = config.pathGuard;
    this.readOnlyGuard = config.readOnlyGuard;
  }

  /**
   * Register a piece of evidence by its path under the mount.
   * Returns the opaque evidence ID that agents will use.
   */
  registerEvidence(
    relativePath: string,
    type: EvidenceEntry["type"]
  ): string {
    const fullPath = join(this.evidenceMount, relativePath);
    this.pathGuard.validatePath(fullPath);

    const id = `EVD-${String(this.nextId++).padStart(3, "0")}`;
    this.evidence.set(id, {
      id,
      mountPath: fullPath,
      type,
      registeredAt: new Date().toISOString(),
    });
    return id;
  }

  /**
   * Resolve an evidence ID to its absolute filesystem path. Prefers the
   * Evidence Store-prepared working copy over the original mount path.
   * Used by disk/network/malware tools.
   */
  resolveEvidencePath(evidenceId: string): string {
    const entry = this.requireEntry(evidenceId, "evidence");
    return entry.workingCopyPath ?? entry.mountPath;
  }

  /** Always returns the path to the original on the read-only mount, regardless
   *  of whether a working copy exists. Used by the Evidence Store custody tool
   *  when computing the original's hash. */
  resolveOriginalPath(evidenceId: string): string {
    return this.requireEntry(evidenceId, "evidence").mountPath;
  }

  /** Set the working copy path for an evidence entry (called by the
   *  prepare_working_copy custody tool after a verified copy is made). */
  setWorkingCopyPath(evidenceId: string, workingCopyPath: string): void {
    const entry = this.requireEntry(evidenceId, "evidence");
    entry.workingCopyPath = workingCopyPath;
  }

  hasWorkingCopy(evidenceId: string): boolean {
    return Boolean(this.evidence.get(evidenceId)?.workingCopyPath);
  }

  /**
   * MemoryImageResolver implementation — used by the Volatility wrapper.
   * Returns the working copy when present; falls back to the original mount
   * path otherwise (which will fail ReadOnlyGuard's mode check unless the
   * source files happen to already be 444 — by design, this surfaces missing
   * custody preparation as an error rather than silently analyzing originals).
   */
  async resolveMemoryPath(memoryId: string): Promise<string> {
    const entry = this.requireEntry(memoryId, "memory");
    if (entry.type !== "memory") {
      throw new Error(
        `MountManager: evidence "${memoryId}" is type "${entry.type}", not "memory"`
      );
    }
    return entry.workingCopyPath ?? entry.mountPath;
  }

  /**
   * VelociraptorCollectionResolver implementation — used by the VR parsers.
   */
  async resolveCollectionPath(collectionId: string): Promise<string> {
    const entry = this.requireEntry(collectionId, "collection");
    if (entry.type !== "velociraptor") {
      throw new Error(
        `MountManager: evidence "${collectionId}" is type "${entry.type}", not "velociraptor"`
      );
    }
    return entry.workingCopyPath ?? entry.mountPath;
  }

  private requireEntry(id: string, kind: string): EvidenceEntry {
    const entry = this.evidence.get(id);
    if (!entry) {
      throw new Error(
        `MountManager: unknown ${kind} ID "${id}". ` +
        `Registered: ${Array.from(this.evidence.keys()).join(", ") || "(none)"}`
      );
    }
    return entry;
  }

  /**
   * Auto-discover evidence under the mount point.
   * Scans top-level directories and registers them based on file extensions.
   */
  async discoverEvidence(): Promise<string[]> {
    const registered: string[] = [];

    let entries;
    try {
      entries = await readdir(this.evidenceMount, { withFileTypes: true });
    } catch {
      // Mount may not exist yet (development/testing)
      return registered;
    }

    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue;

      const fullPath = join(this.evidenceMount, entry.name);
      const fileStat = await stat(fullPath).catch(() => null);
      if (!fileStat) continue;

      if (entry.isDirectory()) {
        // Directories are likely mounted disk images
        const id = this.registerEvidence(entry.name, "disk");
        registered.push(id);
      } else if (entry.isFile()) {
        const type = this.inferType(entry.name);
        const id = this.registerEvidence(entry.name, type);
        registered.push(id);
      }
    }

    return registered;
  }

  /**
   * Get the inventory of all registered evidence (for audit logging).
   */
  getInventory(): EvidenceEntry[] {
    return Array.from(this.evidence.values());
  }

  /**
   * Number of registered evidence items.
   */
  get size(): number {
    return this.evidence.size;
  }

  private inferType(filename: string): EvidenceEntry["type"] {
    const lower = filename.toLowerCase();
    if (lower.endsWith(".raw") || lower.endsWith(".vmem") || lower.endsWith(".dmp") || lower.endsWith(".lime")) {
      return "memory";
    }
    if (lower.endsWith(".pcap") || lower.endsWith(".pcapng")) {
      return "pcap";
    }
    if (lower.endsWith(".e01") || lower.endsWith(".dd") || lower.endsWith(".img") || lower.endsWith(".vhd") || lower.endsWith(".vhdx") || lower.endsWith(".vmdk")) {
      return "disk";
    }
    if (lower.endsWith(".evtx") || lower.endsWith(".log")) {
      return "logs";
    }
    // Velociraptor Offline Collector outputs are zips; convention here is
    // a directory whose name starts with "Collection-" or contains a
    // "results/" subdirectory. The Evidence Store skill is responsible for
    // extracting sealed zips into a read-only directory before registration.
    if (lower.startsWith("collection-") || lower.endsWith(".vr.zip") || lower.endsWith(".velociraptor.zip")) {
      return "velociraptor";
    }
    return "other";
  }
}
