/**
 * Runtime Routing Attacks (RR-001..RR-006)
 *
 * These vectors verify the orchestrator's routing-layer enforcement of
 * architectural invariants. The actual enforcement code lives in
 * `orchestrator/src/routing.ts` — see `orchestrator/test/runtime_routing.test.ts`
 * for the executable harness against the real Router. This module declares
 * the attack catalogue so the spoliation runner can include them in its
 * coverage report.
 *
 * Each vector targets a different bypass attempt:
 *   RR-001  Non-broker skill attempts direct MCP invocation
 *   RR-002  Skill attempts forged calling-identity claim (payload-borne)
 *   RR-003  Non-Situation-Unit subagent attempts COP write
 *   RR-004  Audit log out-of-order append (skipping a hash chain entry)
 *   RR-005  Subagent attempts to read another subagent's private context
 *   RR-006  Tool Broker attempts to skip Safety Officer mirror
 *
 * Coverage status is tracked in DEPLOYMENT_NOTES.md.
 */

export interface RuntimeRoutingAttack {
  id: string;
  name: string;
  invariantId: string; // CLAUDE.md invariant number this protects
  description: string;
  attempt: string;
  expectedBlockLayer: "router" | "audit_log" | "subagent_isolation" | "safety_mirror";
  /** Pointer to the executable test that exercises this attack. */
  testReference: string;
}

export const runtimeRoutingAttacks: RuntimeRoutingAttack[] = [
  {
    id: "RR-001",
    name: "non_broker_direct_mcp_invocation",
    invariantId: "1",
    description: "Skill other than tool-broker attempts to invoke MCP server directly.",
    attempt:
      "operations/forensics-branch calls authorizeMcpInvocation with its own callerId.",
    expectedBlockLayer: "router",
    testReference: "orchestrator/test/runtime_routing.test.ts → RR-001",
  },
  {
    id: "RR-002",
    name: "forged_calling_identity",
    invariantId: "1",
    description:
      "Skill attempts to invoke MCP server via a forged calling-skill identity claim. " +
      "The orchestrator establishes calling identity from subagent context, not the request payload, " +
      "so the forgery has no effect.",
    attempt:
      "Triage submits a tool call with arguments._caller=logistics/tool-broker; orchestrator's " +
      "callerId is set from subagent context and overrides any payload-borne claim.",
    expectedBlockLayer: "router",
    testReference: "orchestrator/test/runtime_routing.test.ts → RR-002",
  },
  {
    id: "RR-003",
    name: "non_situation_unit_cop_write",
    invariantId: "5",
    description: "Subagent other than situation-unit attempts to write to the COP.",
    attempt:
      "Documentation Unit / IC / Forensics Branch calls CopStore.write with their own ID. " +
      "Router.authorizeCopWrite rejects every callerId other than planning/situation-unit.",
    expectedBlockLayer: "router",
    testReference: "orchestrator/test/runtime_routing.test.ts → RR-003",
  },
  {
    id: "RR-004",
    name: "audit_log_out_of_order_append",
    invariantId: "10",
    description:
      "Subagent attempts to write to the audit log out of order (skipping a hash-chain entry).",
    attempt:
      "Inject a JSONL entry whose prevHash does not match the current chain tail. " +
      "AuditLog.replayChain rejects the chain on open and refuses to continue.",
    expectedBlockLayer: "audit_log",
    testReference: "orchestrator/test/runtime_routing.test.ts → RR-004",
  },
  {
    id: "RR-005",
    name: "cross_subagent_context_read",
    invariantId: "implicit (Claude Code subagent isolation)",
    description:
      "Subagent attempts to read another subagent's private context window. " +
      "Each skill activation is a separate Anthropic API call with its own messages; " +
      "no subagent has access to another's conversation. This is enforced by the runtime, " +
      "not by the orchestrator code, but is documented here for completeness.",
    attempt: "N/A — there is no API the orchestrator exposes that would allow cross-context reads.",
    expectedBlockLayer: "subagent_isolation",
    testReference: "orchestrator/test/runtime_routing.test.ts → RR-005 (assertion-only)",
  },
  {
    id: "RR-006",
    name: "tool_broker_skips_safety_mirror",
    invariantId: "7",
    description:
      "Tool Broker subagent attempts to invoke an MCP tool without first triggering the " +
      "Safety Officer mirror. Mirroring is enforced at the orchestrator's routing layer: " +
      "every MCP invocation is wrapped with safetyMirror.review() before the call reaches the " +
      "MCP server. The broker has no API to bypass this.",
    attempt: "Broker calls MCP client directly — but routing layer interposes the mirror.",
    expectedBlockLayer: "safety_mirror",
    testReference: "orchestrator/test/runtime_routing.test.ts → RR-006",
  },
];
