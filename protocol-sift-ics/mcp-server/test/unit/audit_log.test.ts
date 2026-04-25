/**
 * Unit tests for the AuditLog.
 *
 * Tests append-only behavior, hash chain integrity, query interface,
 * and tamper detection. No external dependencies — runs fast.
 *
 * Run: node --test dist/test/unit/audit_log.test.js
 */

import { test, describe, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { AuditLog } from "../../src/audit/audit_log.js";
import type { SkillMessagePayload, McpCallPayload } from "../../src/audit/audit_log.js";

let logDir: string;
let logPath: string;

beforeEach(async () => {
  logDir = await mkdtemp(join(tmpdir(), "audit-test-"));
  logPath = join(logDir, "audit.jsonl");
});

// ────────────────────────────────────────────────────────────────────
// Append and basic structure
// ────────────────────────────────────────────────────────────────────

describe("append", () => {
  test("creates first entry with AUDIT-0000001 and zero prev_hash", async () => {
    const log = new AuditLog({ logPath, incidentId: "INC-001" });

    const entry = await log.append({
      operational_period: 1,
      event_type: "skill_message",
      source_skill: "operations/triage-branch",
      target_skill: "logistics/tool-broker",
      correlation_id: "REQ-001",
      payload: {
        schema_version: "1.0",
        from: "operations/triage-branch",
        to: "logistics/tool-broker",
        message_type: "task",
        content_summary: "Request prefetch parse",
      } satisfies SkillMessagePayload,
    });

    assert.equal(entry.audit_id, "AUDIT-0000001");
    assert.equal(entry.incident_id, "INC-001");
    assert.equal(entry.hash_chain.prev_hash, "0".repeat(64));
    assert.ok(entry.hash_chain.this_hash.length === 64);
    assert.ok(entry.timestamp.endsWith("Z"));
  });

  test("assigns sequential IDs", async () => {
    const log = new AuditLog({ logPath, incidentId: "INC-001" });

    const e1 = await log.append({
      operational_period: 1,
      event_type: "skill_message",
      source_skill: "a",
      target_skill: "b",
      correlation_id: "REQ-001",
      payload: { schema_version: "1.0", from: "a", to: "b", message_type: "task", content_summary: "first" },
    });

    const e2 = await log.append({
      operational_period: 1,
      event_type: "skill_message",
      source_skill: "a",
      target_skill: "b",
      correlation_id: "REQ-002",
      payload: { schema_version: "1.0", from: "a", to: "b", message_type: "task", content_summary: "second" },
    });

    assert.equal(e1.audit_id, "AUDIT-0000001");
    assert.equal(e2.audit_id, "AUDIT-0000002");
  });

  test("writes valid JSONL to disk", async () => {
    const log = new AuditLog({ logPath, incidentId: "INC-001" });

    await log.append({
      operational_period: 1,
      event_type: "ingest",
      source_skill: "logistics/evidence-store",
      target_skill: "finance-admin/audit-log",
      correlation_id: "EVD-001",
      payload: { schema_version: "1.0", evidence_id: "EVD-001", evidence_type: "disk", source_hash: "abc123", mount_path: "/mnt/evidence/EVD-001" },
    });

    const content = await readFile(logPath, "utf-8");
    const lines = content.trim().split("\n");
    assert.equal(lines.length, 1);
    assert.doesNotThrow(() => JSON.parse(lines[0]));
  });
});

// ────────────────────────────────────────────────────────────────────
// Hash chain integrity
// ────────────────────────────────────────────────────────────────────

describe("hash chain", () => {
  test("each entry's prev_hash matches prior entry's this_hash", async () => {
    const log = new AuditLog({ logPath, incidentId: "INC-001" });
    const payload: SkillMessagePayload = {
      schema_version: "1.0",
      from: "a",
      to: "b",
      message_type: "task",
      content_summary: "test",
    };

    const e1 = await log.append({ operational_period: 1, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "X", payload });
    const e2 = await log.append({ operational_period: 1, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "Y", payload });
    const e3 = await log.append({ operational_period: 1, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "Z", payload });

    assert.equal(e2.hash_chain.prev_hash, e1.hash_chain.this_hash);
    assert.equal(e3.hash_chain.prev_hash, e2.hash_chain.this_hash);
  });

  test("verifyChain passes on valid log", async () => {
    const log = new AuditLog({ logPath, incidentId: "INC-001" });
    const payload: SkillMessagePayload = {
      schema_version: "1.0",
      from: "a",
      to: "b",
      message_type: "task",
      content_summary: "test",
    };

    await log.append({ operational_period: 1, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "X", payload });
    await log.append({ operational_period: 1, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "Y", payload });
    await log.append({ operational_period: 2, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "Z", payload });

    const result = await log.verifyChain();
    assert.equal(result.valid, true);
    assert.equal(result.entries_checked, 3);
  });

  test("verifyChain detects tampered entry", async () => {
    const log = new AuditLog({ logPath, incidentId: "INC-001" });
    const payload: SkillMessagePayload = {
      schema_version: "1.0",
      from: "a",
      to: "b",
      message_type: "task",
      content_summary: "test",
    };

    await log.append({ operational_period: 1, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "X", payload });
    await log.append({ operational_period: 1, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "Y", payload });

    // Tamper with the log file — modify the first entry
    const content = await readFile(logPath, "utf-8");
    const lines = content.trim().split("\n");
    const entry = JSON.parse(lines[0]);
    entry.correlation_id = "TAMPERED";
    lines[0] = JSON.stringify(entry);
    const { writeFile: wf } = await import("node:fs/promises");
    await wf(logPath, lines.join("\n") + "\n");

    const result = await log.verifyChain();
    assert.equal(result.valid, false);
    assert.equal(result.first_invalid, "AUDIT-0000001");
  });

  test("verifyChain passes on empty log", async () => {
    const log = new AuditLog({ logPath, incidentId: "INC-001" });
    const result = await log.verifyChain();
    assert.equal(result.valid, true);
    assert.equal(result.entries_checked, 0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Resume from existing log
// ────────────────────────────────────────────────────────────────────

describe("resume", () => {
  test("resumes sequence and hash chain from existing log", async () => {
    const log1 = new AuditLog({ logPath, incidentId: "INC-001" });
    const payload: SkillMessagePayload = {
      schema_version: "1.0",
      from: "a",
      to: "b",
      message_type: "task",
      content_summary: "test",
    };

    const e2 = await log1.append({ operational_period: 1, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "X", payload });
    await log1.append({ operational_period: 1, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "Y", payload });

    // Create new instance and resume
    const log2 = new AuditLog({ logPath, incidentId: "INC-001" });
    await log2.resume();

    const e3 = await log2.append({ operational_period: 2, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "Z", payload });

    assert.equal(e3.audit_id, "AUDIT-0000003");

    // Full chain should still verify
    const result = await log2.verifyChain();
    assert.equal(result.valid, true);
    assert.equal(result.entries_checked, 3);
  });
});

// ────────────────────────────────────────────────────────────────────
// Query interface
// ────────────────────────────────────────────────────────────────────

describe("queries", () => {
  test("traceFindings returns entries matching a finding ID", async () => {
    const log = new AuditLog({ logPath, incidentId: "INC-001" });

    await log.append({
      operational_period: 1,
      event_type: "mcp_call",
      source_skill: "logistics/tool-broker",
      target_skill: "mcp-server",
      correlation_id: "FND-042",
      payload: {
        schema_version: "1.0",
        request_id: "REQ-010",
        execution_id: "EXEC-789",
        requesting_skill: "operations/forensics-branch",
        tool_name: "parse_prefetch_summary",
        parameters_hash: "abc",
        status: "success",
        duration_ms: 1200,
        tokens_in: 500,
        tokens_out: 800,
        safety_review_result: "clear",
      } satisfies McpCallPayload,
    });

    await log.append({
      operational_period: 1,
      event_type: "skill_message",
      source_skill: "operations/forensics-branch",
      target_skill: "planning/situation-unit",
      correlation_id: "UNRELATED",
      payload: { schema_version: "1.0", from: "a", to: "b", message_type: "rollup", content_summary: "other" },
    });

    const trace = await log.traceFindings("FND-042");
    assert.equal(trace.length, 1);
    assert.equal(trace[0].correlation_id, "FND-042");
  });

  test("getByPeriod filters by operational period", async () => {
    const log = new AuditLog({ logPath, incidentId: "INC-001" });
    const payload: SkillMessagePayload = { schema_version: "1.0", from: "a", to: "b", message_type: "task", content_summary: "test" };

    await log.append({ operational_period: 1, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "X", payload });
    await log.append({ operational_period: 2, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "Y", payload });
    await log.append({ operational_period: 2, event_type: "skill_message", source_skill: "a", target_skill: "b", correlation_id: "Z", payload });

    const p2 = await log.getByPeriod(2);
    assert.equal(p2.length, 2);
  });

  test("getByType filters by event type", async () => {
    const log = new AuditLog({ logPath, incidentId: "INC-001" });

    await log.append({
      operational_period: 1,
      event_type: "skill_message",
      source_skill: "a",
      target_skill: "b",
      correlation_id: "X",
      payload: { schema_version: "1.0", from: "a", to: "b", message_type: "task", content_summary: "test" },
    });

    await log.append({
      operational_period: 1,
      event_type: "safety_halt",
      source_skill: "command-staff/safety-officer",
      target_skill: "logistics/tool-broker",
      correlation_id: "HALT-001",
      payload: { schema_version: "1.0", flag_id: "HALT-001", violation_type: "write_attempt", blocked_call: "REQ-005", resolution: "aborted" },
    });

    const halts = await log.getByType("safety_halt");
    assert.equal(halts.length, 1);
    assert.equal(halts[0].correlation_id, "HALT-001");
  });
});
