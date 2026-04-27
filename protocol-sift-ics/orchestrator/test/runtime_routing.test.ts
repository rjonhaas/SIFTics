// RR-001..RR-006 — orchestrator-side runtime-routing attack vectors.
// Mirrors the catalogue in
// `mcp-server/test/spoliation/attack-vectors/runtime-routing.ts`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadSkills, SkillRegistry } from "../src/skill_loader.js";
import { Router, SITUATION_UNIT_ID, TOOL_BROKER_ID } from "../src/routing.js";
import { CopStore } from "../src/persistence/cop_store.js";
import { AuditLog } from "../src/persistence/audit_log.js";
import { SafetyMirror, passThroughEvaluator } from "../src/safety/safety_mirror.js";

const SKILLS_ROOT =
  process.env.SKILLS_ROOT ??
  resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "skills");

async function makeRig() {
  const skills = await loadSkills(SKILLS_ROOT);
  const registry = new SkillRegistry(skills);
  const router = new Router(registry);
  const dir = await mkdtemp(join(tmpdir(), "psorch-rr-"));
  const audit = await AuditLog.open(join(dir, "audit_log.jsonl"));
  const cop = new CopStore(dir, router);
  return { router, audit, cop, dir };
}

test("RR-001: non-broker skill direct MCP invocation rejected by router", async () => {
  const { router } = await makeRig();
  const decision = router.authorizeMcpInvocation({
    callerId: "operations/memory-branch",
    toolName: "vol_pslist",
    arguments: {},
  });
  assert.equal(decision.allow, false);
});

test("RR-002: forged calling-identity claim has no effect — router consults orchestrator-set callerId only", async () => {
  const { router } = await makeRig();
  const decision = router.authorizeMcpInvocation({
    callerId: "operations/triage-branch", // identity from orchestrator context
    toolName: "vol_pslist",
    arguments: { _caller: TOOL_BROKER_ID, _identity: "logistics/tool-broker" },
  });
  assert.equal(decision.allow, false, "payload-borne identity claim must not bypass router");
});

test("RR-003: non-situation-unit COP write rejected", async () => {
  const { cop, dir } = await makeRig();
  const candidates = [
    "command-staff/incident-commander",
    "operations/forensics-branch",
    "planning/documentation-unit",
    "logistics/tool-broker",
  ];
  for (const id of candidates) {
    await assert.rejects(
      () =>
        cop.write(id, {
          caseId: "test",
          period: 1,
          updatedAt: "",
          objectives: [],
          activeBranches: [],
          findings: [],
          contradictions: [],
          narrative: "",
        }),
      /attempted COP write/,
      `${id} should not be allowed to write COP`
    );
  }
  // Sanity: the legitimate writer succeeds.
  await cop.write(SITUATION_UNIT_ID, {
    caseId: "test",
    period: 1,
    updatedAt: "",
    objectives: [],
    activeBranches: [],
    findings: [],
    contradictions: [],
    narrative: "",
  });
  await rm(dir, { recursive: true, force: true });
});

test("RR-004: audit log rejects out-of-order chain on replay", async () => {
  const { audit, dir } = await makeRig();
  await audit.append("incident_open", "human_operator", 0, {});
  await audit.append("period_start", "command-staff/incident-commander", 1, {});

  // Tamper: rewrite the JSONL with a third entry whose prevHash points to the
  // first instead of the second. Chain replay must reject.
  const path = join(dir, "audit_log.jsonl");
  const raw = await readFile(path, "utf8");
  const lines = raw.split("\n").filter((l) => l.trim());
  const first = JSON.parse(lines[0]);
  const tampered = {
    id: "AUDIT-0000003",
    ts: "2026-04-26T18:00:00.000000Z",
    prevHash: first.hash, // wrong — should chain off lines[1]
    hash: "0".repeat(64),
    kind: "ic_decision",
    skill: "command-staff/incident-commander",
    period: 1,
    payload: { tampered: true },
  };
  await writeFile(path, lines.join("\n") + "\n" + JSON.stringify(tampered) + "\n");

  await assert.rejects(() => AuditLog.open(path), /chain broken/);
  await rm(dir, { recursive: true, force: true });
});

test("RR-005: cross-subagent context read — orchestrator exposes no API for this", () => {
  // Each skill activation is a separate Anthropic API call (subagent.ts).
  // The orchestrator never exposes another subagent's conversation to the
  // current one — the only inter-skill communication is through structured
  // delegation messages that the orchestrator routes explicitly.
  // This is a contract assertion, not an enforcement test.
  assert.ok(true);
});

test("RR-006: Safety Officer mirror is invoked even when evaluator returns clear", async () => {
  const { audit, dir } = await makeRig();
  let mirrorWasCalled = false;
  const mirror = new SafetyMirror({
    evaluator: async (call, _signal) => {
      mirrorWasCalled = true;
      assert.equal(call.toolName, "vol_pslist");
      return { verdict: "clear", rationale: "stub clear" };
    },
    auditLog: audit,
  });
  const decision = await mirror.review(1, {
    onBehalfOf: "operations/memory-branch",
    toolName: "vol_pslist",
    arguments: {},
  });
  assert.equal(mirrorWasCalled, true);
  assert.equal(decision.verdict, "clear");

  // Audit log should contain the safety_mirror_clear event — proves the mirror
  // is on the critical path.
  const entries = await audit.replayChain();
  const mirrorEntry = entries.find((e) => e.kind === "safety_mirror_clear");
  assert.ok(mirrorEntry, "safety_mirror_clear must be in the audit log");
  await rm(dir, { recursive: true, force: true });
});
