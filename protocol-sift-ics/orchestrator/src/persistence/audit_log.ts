// Append-only hash-chained JSONL audit log for the orchestrator.
//
// Every entry includes:
//   - id        AUDIT-NNNNNNN (sequential, zero-padded to 7)
//   - ts        microsecond UTC ISO8601
//   - prevHash  SHA-256 of the prior entry's serialized record
//   - hash      SHA-256 of this entry's serialized record (excluding `hash`)
//   - kind      event type — one of the EVENT_KINDS literals below
//   - skill     calling subagent id (set by orchestrator from context, never
//               from payload — forging identity is a routing layer concern)
//   - period    operational period number (>=1) or 0 for pre-period events
//   - payload   event-specific details
//
// The chain is verified at startup; any tampering halts the run.
//
// This is the orchestrator-side audit log. The MCP server has its own
// audit log inside mcp-server/src/audit/audit_log.ts; the orchestrator log
// links to MCP execution IDs but does not duplicate MCP entries.

import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";

export const EVENT_KINDS = [
  "incident_open",
  "period_start",
  "period_close",
  "ic_decision",
  "skill_invocation_start",
  "skill_invocation_end",
  "tool_request_submitted",
  "safety_mirror_clear",
  "safety_mirror_flag",
  "safety_mirror_halt",
  "mcp_call",
  "cop_write",
  "cop_write_rejected",
  "delegation",
  "rollup",
  "incident_close",
  "incident_truncated",
] as const;
export type EventKind = (typeof EVENT_KINDS)[number];

export interface AuditEntry {
  id: string;
  ts: string;
  prevHash: string;
  hash: string;
  kind: EventKind;
  skill: string;
  period: number;
  payload: Record<string, unknown>;
}

const GENESIS_HASH = "0".repeat(64);

export class AuditLog {
  private nextSeq = 1;
  private lastHash = GENESIS_HASH;

  private constructor(private readonly path: string) {}

  static async open(path: string): Promise<AuditLog> {
    await mkdir(dirname(path), { recursive: true });
    const log = new AuditLog(path);
    if (existsSync(path)) {
      await log.replayChain();
    } else {
      await writeFile(path, "");
    }
    return log;
  }

  /** Append a new entry, set its hash, and persist to disk. */
  async append(
    kind: EventKind,
    skill: string,
    period: number,
    payload: Record<string, unknown> = {}
  ): Promise<AuditEntry> {
    const entry: AuditEntry = {
      id: `AUDIT-${String(this.nextSeq).padStart(7, "0")}`,
      ts: nowUtcMicroseconds(),
      prevHash: this.lastHash,
      hash: "",
      kind,
      skill,
      period,
      payload,
    };
    entry.hash = hashEntry(entry);
    await appendFile(this.path, JSON.stringify(entry) + "\n");
    this.nextSeq++;
    this.lastHash = entry.hash;
    return entry;
  }

  /** Read every entry; verify hash chain on the way. Throws on tamper. */
  async replayChain(): Promise<AuditEntry[]> {
    const raw = await readFile(this.path, "utf8");
    const lines = raw.split("\n").filter((l) => l.trim().length > 0);
    const out: AuditEntry[] = [];
    let expected = GENESIS_HASH;
    for (const line of lines) {
      const e = JSON.parse(line) as AuditEntry;
      if (e.prevHash !== expected) {
        throw new Error(
          `AuditLog: chain broken at ${e.id} — expected prevHash ${expected}, got ${e.prevHash}`
        );
      }
      const recomputed = hashEntry(e);
      if (recomputed !== e.hash) {
        throw new Error(
          `AuditLog: tampered entry ${e.id} — recomputed hash ${recomputed} ≠ stored ${e.hash}`
        );
      }
      out.push(e);
      expected = e.hash;
    }
    if (out.length > 0) {
      const last = out[out.length - 1];
      const m = last.id.match(/^AUDIT-(\d+)$/);
      if (m) this.nextSeq = Number(m[1]) + 1;
      this.lastHash = last.hash;
    }
    return out;
  }
}

function hashEntry(e: AuditEntry): string {
  const { hash: _omit, ...rest } = e;
  return createHash("sha256").update(JSON.stringify(rest)).digest("hex");
}

function nowUtcMicroseconds(): string {
  // hrtime gives nanosecond resolution; we surface microseconds in ISO format.
  const now = new Date();
  const usSinceMs = Number(process.hrtime.bigint() % 1_000_000n);
  const ms = now.toISOString().slice(0, -1); // drop "Z"
  return `${ms}${String(usSinceMs).padStart(3, "0")}Z`;
}
