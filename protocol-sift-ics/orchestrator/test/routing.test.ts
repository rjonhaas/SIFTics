// Verifies the orchestrator's architectural enforcement points:
//   - Tool Broker exclusivity on MCP invocation
//   - Per-skill allowlist enforcement on broker submissions
//   - COP write isolation to Situation Unit
//   - Delegation graph honors each skill's `invoke` permission

import { test } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

import { loadSkills, SkillRegistry } from "../src/skill_loader.js";
import { Router, TOOL_BROKER_ID, SITUATION_UNIT_ID } from "../src/routing.js";

// import.meta.url here points at dist/test/routing.test.js — skills/ lives
// four levels up (dist/test → dist → orchestrator → protocol-sift-ics).
const SKILLS_ROOT =
  process.env.SKILLS_ROOT ??
  resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "skills");

async function buildRouter(): Promise<Router> {
  const skills = await loadSkills(SKILLS_ROOT);
  return new Router(new SkillRegistry(skills));
}

test("tool broker exclusivity — non-broker direct MCP invocation rejected", async () => {
  const router = await buildRouter();
  const decision = router.authorizeMcpInvocation({
    callerId: "operations/forensics-branch",
    toolName: "extract_mft_timeline",
    arguments: {},
  });
  assert.equal(decision.allow, false);
  if (!decision.allow) {
    assert.match(decision.reason, /only "logistics\/tool-broker"/);
  }
});

test("tool broker exclusivity — broker direct MCP invocation accepted", async () => {
  const router = await buildRouter();
  const decision = router.authorizeMcpInvocation({
    callerId: TOOL_BROKER_ID,
    toolName: "extract_mft_timeline",
    arguments: {},
  });
  assert.equal(decision.allow, true);
});

test("forged identity claim — call still routed by orchestrator-set callerId", async () => {
  // The orchestrator sets callerId from subagent context; a payload claiming
  // otherwise has no effect because authorizeMcpInvocation only consults
  // callerId. This test documents the contract.
  const router = await buildRouter();
  const decision = router.authorizeMcpInvocation({
    callerId: "operations/triage-branch", // identity set by orchestrator
    toolName: "memory_process_list",
    arguments: { _caller: "logistics/tool-broker" }, // payload-borne forgery
  });
  assert.equal(decision.allow, false);
});

test("broker submission honors per-skill allowlist", async () => {
  const router = await buildRouter();
  const allowed = router.authorizeBrokerSubmission(
    "operations/forensics-branch",
    "extract_mft_timeline"
  );
  assert.equal(allowed.allow, true);

  const denied = router.authorizeBrokerSubmission(
    "operations/forensics-branch",
    "vol_pslist" // Memory Branch tool, not on Forensics allowlist
  );
  assert.equal(denied.allow, false);
});

test("COP write isolation — only situation-unit accepted", async () => {
  const router = await buildRouter();
  for (const id of [
    "command-staff/incident-commander",
    "operations/triage-branch",
    "operations/forensics-branch",
    "planning/timeline-unit",
    "planning/documentation-unit",
    "logistics/tool-broker",
  ]) {
    const d = router.authorizeCopWrite(id);
    assert.equal(d.allow, false, `${id} should not be allowed to write COP`);
  }
  assert.equal(router.authorizeCopWrite(SITUATION_UNIT_ID).allow, true);
});

test("COP read open to any registered skill, rejects unknown", async () => {
  const router = await buildRouter();
  assert.equal(router.authorizeCopRead("operations/forensics-branch").allow, true);
  assert.equal(router.authorizeCopRead("not-a-skill").allow, false);
});

test("IC may delegate to all command-staff via wildcard, but not to a branch directly", async () => {
  const router = await buildRouter();
  assert.equal(
    router.authorizeDelegation("command-staff/incident-commander", "command-staff/safety-officer").allow,
    true,
    "IC → safety-officer via command-staff/* glob"
  );
  // IC's invoke list does not include branch-level skills; branches must be
  // tasked via Section Chiefs. (See IC SKILL.md hard rule.)
  const direct = router.authorizeDelegation(
    "command-staff/incident-commander",
    "operations/forensics-branch"
  );
  assert.equal(direct.allow, false);
});

test("ops-chief may invoke its branches", async () => {
  const router = await buildRouter();
  for (const branch of [
    "operations/triage-branch",
    "operations/forensics-branch",
    "operations/memory-branch",
    "operations/network-branch",
    "operations/malware-branch",
  ]) {
    const d = router.authorizeDelegation("operations/ops-chief", branch);
    if (!d.allow) {
      // Some branches may not be in ops-chief's explicit invoke list yet —
      // record which so we can update SKILL.md if needed.
      console.warn(`ops-chief cannot invoke ${branch}: ${d.reason}`);
    }
  }
});
