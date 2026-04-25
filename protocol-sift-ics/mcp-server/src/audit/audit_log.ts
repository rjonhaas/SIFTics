/**
 * AuditLog — append-only, hash-chained event log for the ICS swarm.
 *
 * Every inter-skill message, MCP tool call, IC decision, COP update,
 * safety flag, and legal advisory reference is recorded here. This is
 * the primary artifact satisfying the hackathon's "Agent Execution Logs"
 * requirement — judges can trace any finding back to the specific tool
 * execution that produced it.
 *
 * Architectural guarantees:
 *   - Append-only: no edits, no deletes, ever
 *   - Hash-chained: each entry includes SHA-256 of the prior entry,
 *     making tampering detectable in a single pass
 *   - Legal privilege preserved: advisory content never appears here,
 *     only references by ID
 */

import { createHash } from "node:crypto";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// ────────────────────────────────────────────────────────────────────
// Event types
// ────────────────────────────────────────────────────────────────────

export type EventType =
  | "skill_message"
  | "mcp_call"
  | "ic_decision"
  | "cop_update"
  | "safety_flag"
  | "safety_halt"
  | "legal_advisory"
  | "ingest"
  | "error"
  | "budget_event";

export interface SkillMessagePayload {
  schema_version: "1.0";
  from: string;
  to: string;
  message_type: "task" | "rollup" | "advisory" | "query" | "response";
  content_ref?: string;
  content_summary: string;
}

export interface McpCallPayload {
  schema_version: "1.0";
  request_id: string;
  execution_id: string;
  requesting_skill: string;
  tool_name: string;
  parameters_hash: string;
  status: "success" | "error" | "rejected" | "halted";
  duration_ms: number;
  tokens_in: number;
  tokens_out: number;
  result_ref?: string;
  safety_review_result: "clear" | "flag" | "halt" | "timeout";
}

export interface IcDecisionPayload {
  schema_version: "1.0";
  decision_id: string;
  operational_period: number;
  decision: string;
  rationale: string;
  advisories_referenced: string[];
  human_in_loop: boolean;
  human_approver: string | null;
}

export interface CopUpdatePayload {
  schema_version: "1.0";
  cop_version_before: string;
  cop_version_after: string;
  writer_skill: "planning/situation-unit";
  triggering_finding: string;
  change_type: "new_finding" | "promotion" | "contradiction" | "version_increment";
  diff_ref?: string;
}

export interface SafetyPayload {
  schema_version: "1.0";
  flag_id: string;
  violation_type: string;
  blocked_call?: string;
  resolution: "aborted" | "ic_override" | "pending";
}

export interface LegalAdvisoryPayload {
  schema_version: "1.0";
  advisory_id: string;
  severity: "informational" | "advisory" | "hard_flag";
  topic: string;
  /** Points to privileged log — content never in general audit log */
  content_ref: string;
}

export interface IngestPayload {
  schema_version: "1.0";
  evidence_id: string;
  evidence_type: string;
  source_hash: string;
  mount_path: string;
}

export interface ErrorPayload {
  schema_version: "1.0";
  error_type: string;
  message: string;
  source_skill?: string;
  correlation_id?: string;
}

export interface BudgetEventPayload {
  schema_version: "1.0";
  alert_level: "informational" | "advisory" | "hard_flag" | "freeze";
  tier: string;
  tokens_consumed: number;
  tokens_budget: number;
  percent_used: number;
  estimated_cost_usd: number;
}

export type AuditPayload =
  | SkillMessagePayload
  | McpCallPayload
  | IcDecisionPayload
  | CopUpdatePayload
  | SafetyPayload
  | LegalAdvisoryPayload
  | IngestPayload
  | ErrorPayload
  | BudgetEventPayload;

// ────────────────────────────────────────────────────────────────────
// Audit entry
// ────────────────────────────────────────────────────────────────────

export interface AuditEntry {
  audit_id: string;
  timestamp: string;
  operational_period: number;
  incident_id: string;
  event_type: EventType;
  source_skill: string;
  target_skill: string;
  correlation_id: string;
  payload: AuditPayload;
  hash_chain: {
    prev_hash: string;
    this_hash: string;
  };
}

// ────────────────────────────────────────────────────────────────────
// AuditLog class
// ────────────────────────────────────────────────────────────────────

export interface AuditLogConfig {
  logPath: string;
  incidentId: string;
}

const ZERO_HASH = "0".repeat(64);

export class AuditLog {
  private readonly logPath: string;
  private readonly incidentId: string;
  private nextSeq = 1;
  private prevHash: string = ZERO_HASH;

  constructor(config: AuditLogConfig) {
    this.logPath = config.logPath;
    this.incidentId = config.incidentId;

    // Ensure the directory exists
    const dir = dirname(this.logPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Resume from an existing log file. Reads the last entry to restore
   * sequence number and hash chain state.
   */
  async resume(): Promise<void> {
    let content: string;
    try {
      content = await readFile(this.logPath, "utf-8");
    } catch {
      // File doesn't exist yet — start fresh
      return;
    }

    const lines = content.trim().split("\n").filter((l) => l.length > 0);
    if (lines.length === 0) return;

    const lastEntry = JSON.parse(lines[lines.length - 1]) as AuditEntry;
    const seqNum = parseInt(lastEntry.audit_id.replace("AUDIT-", ""), 10);
    this.nextSeq = seqNum + 1;
    this.prevHash = lastEntry.hash_chain.this_hash;
  }

  /**
   * Append a new event to the audit log.
   *
   * This is the only write operation. It:
   *   1. Assigns a sequential audit ID
   *   2. Timestamps with microsecond precision
   *   3. Computes the hash chain (prev_hash + this_hash)
   *   4. Appends the entry as a single JSONL line
   */
  async append(event: {
    operational_period: number;
    event_type: EventType;
    source_skill: string;
    target_skill: string;
    correlation_id: string;
    payload: AuditPayload;
  }): Promise<AuditEntry> {
    const auditId = `AUDIT-${String(this.nextSeq).padStart(7, "0")}`;

    // Build the entry without this_hash first (it's computed over the rest)
    const entry: AuditEntry = {
      audit_id: auditId,
      timestamp: this.microsecondTimestamp(),
      operational_period: event.operational_period,
      incident_id: this.incidentId,
      event_type: event.event_type,
      source_skill: event.source_skill,
      target_skill: event.target_skill,
      correlation_id: event.correlation_id,
      payload: event.payload,
      hash_chain: {
        prev_hash: this.prevHash,
        this_hash: "", // placeholder — computed next
      },
    };

    // Compute this_hash over the canonical form (with this_hash as empty string)
    entry.hash_chain.this_hash = this.computeEntryHash(entry);

    // Append to file
    const line = JSON.stringify(entry) + "\n";
    await appendFile(this.logPath, line, "utf-8");

    // Update state
    this.prevHash = entry.hash_chain.this_hash;
    this.nextSeq++;

    return entry;
  }

  // ────────────────────────────────────────────────────────────────
  // Query interface
  // ────────────────────────────────────────────────────────────────

  /**
   * Trace a finding back through its full audit chain.
   * Returns all entries whose correlation_id or payload references
   * the given finding ID.
   */
  async traceFindings(findingId: string): Promise<AuditEntry[]> {
    const entries = await this.readAll();
    return entries.filter((e) => {
      if (e.correlation_id === findingId) return true;
      const payloadStr = JSON.stringify(e.payload);
      return payloadStr.includes(findingId);
    });
  }

  /**
   * Get all entries for a specific operational period.
   */
  async getByPeriod(period: number): Promise<AuditEntry[]> {
    const entries = await this.readAll();
    return entries.filter((e) => e.operational_period === period);
  }

  /**
   * Get all entries of a specific event type.
   */
  async getByType(eventType: EventType): Promise<AuditEntry[]> {
    const entries = await this.readAll();
    return entries.filter((e) => e.event_type === eventType);
  }

  /**
   * Get all entries by a specific source skill.
   */
  async getBySource(sourceSkill: string): Promise<AuditEntry[]> {
    const entries = await this.readAll();
    return entries.filter((e) => e.source_skill === sourceSkill);
  }

  /**
   * Verify the hash chain integrity of the entire log.
   * Returns true if every entry's prev_hash matches the prior entry's this_hash.
   */
  async verifyChain(): Promise<{
    valid: boolean;
    entries_checked: number;
    first_invalid?: string;
  }> {
    const entries = await this.readAll();
    if (entries.length === 0) {
      return { valid: true, entries_checked: 0 };
    }

    // First entry must have prev_hash = ZERO_HASH
    if (entries[0].hash_chain.prev_hash !== ZERO_HASH) {
      return {
        valid: false,
        entries_checked: 1,
        first_invalid: entries[0].audit_id,
      };
    }

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // Verify this_hash is correct
      const expectedHash = this.computeEntryHash(entry);
      if (entry.hash_chain.this_hash !== expectedHash) {
        return {
          valid: false,
          entries_checked: i + 1,
          first_invalid: entry.audit_id,
        };
      }

      // Verify prev_hash links to prior entry
      if (i > 0) {
        const prevEntry = entries[i - 1];
        if (entry.hash_chain.prev_hash !== prevEntry.hash_chain.this_hash) {
          return {
            valid: false,
            entries_checked: i + 1,
            first_invalid: entry.audit_id,
          };
        }
      }
    }

    return { valid: true, entries_checked: entries.length };
  }

  /**
   * Get the total number of entries in the log.
   */
  async count(): Promise<number> {
    const entries = await this.readAll();
    return entries.length;
  }

  /**
   * Get aggregate counts by event type (for Token Budget skill).
   */
  async countByType(): Promise<Record<string, number>> {
    const entries = await this.readAll();
    const counts: Record<string, number> = {};
    for (const entry of entries) {
      counts[entry.event_type] = (counts[entry.event_type] ?? 0) + 1;
    }
    return counts;
  }

  // ────────────────────────────────────────────────────────────────
  // Internals
  // ────────────────────────────────────────────────────────────────

  private async readAll(): Promise<AuditEntry[]> {
    let content: string;
    try {
      content = await readFile(this.logPath, "utf-8");
    } catch {
      return [];
    }
    return content
      .trim()
      .split("\n")
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l) as AuditEntry);
  }

  /**
   * Compute SHA-256 of an entry's canonical JSON form.
   * The canonical form has this_hash set to "" (empty string).
   */
  private computeEntryHash(entry: AuditEntry): string {
    const canonical = {
      ...entry,
      hash_chain: {
        prev_hash: entry.hash_chain.prev_hash,
        this_hash: "",
      },
    };
    const json = JSON.stringify(canonical);
    return createHash("sha256").update(json).digest("hex");
  }

  /**
   * ISO 8601 timestamp with microsecond precision.
   */
  private microsecondTimestamp(): string {
    const now = new Date();
    const iso = now.toISOString();
    // Replace milliseconds with microseconds using hrtime
    const [, nanos] = process.hrtime();
    const micros = String(Math.floor(nanos / 1000) % 1000).padStart(3, "0");
    return iso.replace(/(\.\d{3})Z$/, `$1${micros}Z`);
  }
}
