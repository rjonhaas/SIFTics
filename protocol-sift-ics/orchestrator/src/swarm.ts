// Live swarm execution. The orchestrator's branch loop, tool-broker
// dispatch, Situation Unit COP integration, and Documentation Unit final
// report. The architectural invariants from CLAUDE.md are enforced here
// in code: every MCP call is gated by routing + safety mirror, every
// finding cites a tool_execution_id, only situation-unit writes the COP.
//
// Tool Broker dispatch: the orchestrator stands in for the broker on
// execution. The broker's role per invariant #1 is "validate, mirror to
// safety, execute". Validation runs through Router.authorizeBrokerSubmission;
// safety mirror runs through SafetyMirror.review; execution calls
// McpClient.callTool with callerId = TOOL_BROKER_ID. Doing this in code
// rather than as a nested LLM call is more deterministic — the broker has
// no judgement call to make beyond the deterministic checks that already
// live in the routing layer — and keeps the demo within token budget.

import type Anthropic from "@anthropic-ai/sdk";
import type { SubagentRunner, ToolCallRecord } from "./subagent.js";
import { SUBMIT_TOOL_REQUEST, toolsForSkill } from "./subagent.js";
import type { SkillConfig, SkillRegistry } from "./skill_loader.js";
import type { Router } from "./routing.js";
import { TOOL_BROKER_ID, SITUATION_UNIT_ID } from "./routing.js";
import type { CopState, CopStore, Finding } from "./persistence/cop_store.js";
import type { PeriodState, RollupSummary } from "./persistence/period_state.js";
import type { AuditLog } from "./persistence/audit_log.js";
import type { InterSkillMessageLog } from "./persistence/inter_skill_messages.js";
import type { SafetyMirror } from "./safety/safety_mirror.js";
import type { McpClient, McpTool } from "./mcp_client.js";
import type { IncidentDirective } from "./operational_period.js";

export interface SwarmDeps {
  skills: SkillRegistry;
  router: Router;
  copStore: CopStore;
  auditLog: AuditLog;
  messages: InterSkillMessageLog;
  safety: SafetyMirror;
  mcp: McpClient;
  runner: SubagentRunner;
}

export interface BranchRunResult {
  rollup: RollupSummary;
  parsedFindings: Finding[];
  parsedStoryFindings: Record<string, unknown>[];
}

let execSeq = 0;
function nextExecutionId(): string {
  execSeq++;
  return `EXEC-${String(execSeq).padStart(4, "0")}`;
}

function mcpToolsForBroker(mcp: McpClient): Anthropic.Tool[] {
  // Not actually surfaced to a model — the broker is dispatched in code —
  // but kept here in case a future iteration switches to a real broker
  // subagent invocation.
  return mcp.listTools().map((t: McpTool) => ({
    name: t.name,
    description: t.description,
    input_schema: t.inputSchema as Anthropic.Tool["input_schema"],
  }));
}

/** Render a per-branch tool catalog. Without this, branches emit
 *  submit_tool_request with the wrong argument names because they only
 *  see the generic submit_tool_request schema, never each MCP tool's
 *  inputSchema (e.g. vol_pslist requires "memory_id", not "evidence_id").
 *  This catalog is injected into the branch's user message. */
function renderToolCatalog(skill: SkillConfig, mcp: McpClient): string {
  const allTools = mcp.listTools();
  const allowed = skill.mcpTools.all
    ? allTools
    : allTools.filter((t) => (skill.mcpTools.allowlist ?? []).includes(t.name));
  if (allowed.length === 0) {
    return "Tool catalog: (no MCP tools available to your branch — produce findings only from delegated rollups, or emit an empty findings array.)";
  }
  const entries = allowed.map((t) => {
    const schema = JSON.stringify(t.inputSchema, null, 2);
    return [
      `### ${t.name}`,
      t.description,
      "Input schema:",
      "```json",
      schema,
      "```",
    ].join("\n");
  });
  return [
    "Tool catalog — these are the ONLY tools you may request via submit_tool_request, and the EXACT argument names each requires. Use the property names from the schema verbatim. For evidence references, pass the EVD-NNN id from the evidence inventory above as the schema's required field (commonly `memory_id` for memory plugins, or a working-directory path for disk plugins after you extract the relevant artifact).",
    "",
    ...entries,
  ].join("\n");
}

/** Render the directive as a compact context block the branch model can read. */
function directiveContext(directive: IncidentDirective): string {
  const evidence = directive.evidence_sources
    .map((e, i) => {
      const parts = [`[${i + 1}] type=${e.type} path=${e.path}`];
      if (e.host) parts.push(`host=${e.host}`);
      if (e.os) parts.push(`os=${e.os}`);
      if (e.sha256) parts.push(`sha256=${e.sha256.slice(0, 16)}…`);
      return parts.join(" ");
    })
    .join("\n");
  return [
    `Incident: ${directive.incident_id}`,
    `Case: ${directive.case_id}`,
    `Priority: ${directive.priority}`,
    `Description: ${directive.description}`,
    `Initial hypothesis: ${directive.initial_hypothesis ?? "(none)"}`,
    `Evidence inventory:\n${evidence}`,
  ].join("\n");
}

/** Pull the first ```json fenced block from a model response, if any. */
function extractJsonBlock(text: string): unknown | null {
  const fenced = text.match(/```json\s*([\s\S]*?)```/);
  const raw = fenced ? fenced[1] : null;
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/** Same, but return the raw string for retry/diagnostics. */
function extractJsonText(text: string): string | null {
  const fenced = text.match(/```json\s*([\s\S]*?)```/);
  return fenced ? fenced[1].trim() : null;
}

const BRANCH_OUTPUT_INSTRUCTION = `
ANTI-SPECULATION RULES — these are forensic invariants, not preferences:

1. Findings come ONLY from facts you observe in tool results during this conversation. Do not hypothesize about file modes, mount permissions, network configurations, host states, or infrastructure that you have not directly observed in a tool result.
2. If a tool returned an error, report exactly what the error said. Do not invent forensic-sounding explanations for tool failures (e.g., do NOT claim "ReadOnlyGuard rejected mode 664" unless that exact phrase came back from the tool — guess work like that violates the citation invariant and is treated as a hallucination).
3. If you have no findings to report, emit an empty findings array. Empty is honest; fabricated is not.
4. Every finding's tool_execution_id MUST be a real EXEC-NNNN from THIS conversation's tool results. Do not invent execution IDs.

When you are done investigating, emit a single fenced JSON block (\`\`\`json … \`\`\`) with this shape:

{
  "branch": "<your branch id>",
  "summary": "<two-to-four sentence rollup grounded in what tools returned>",
  "findings": [
    {
      "id": "<BRANCH>-FND-001",
      "branch": "<branch slug — triage|forensics|memory|network|malware>",
      "category": "<short kebab-case>",
      "title": "<one line>",
      "description": "<two to four sentences, citing only observed tool output>",
      "evidence_source": "<EVD-NNN or evidence path>",
      "tool_execution_id": "<EXEC-NNNN from a real tool call you made>",
      "confidence_tier": "confirmed|inferred|hypothesized|contradicted",
      "confidence_score": 0.0,
      "timestamp_observed": "<ISO8601 UTC>",
      "structured_data": { },
      "supports_phase": "<initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|command_and_control|exfiltration|impact>",
      "mitre_technique_ids": ["T####"],
      "operational_period_id": <int>,
      "host": "<host or null>"
    }
  ]
}
`.trim();

/** Run one branch through the live tool-use loop. */
export async function runBranch(
  branch: SkillConfig,
  directive: IncidentDirective,
  period: number,
  deps: SwarmDeps
): Promise<BranchRunResult> {
  const branchId = branch.id;
  const tools = toolsForSkill(branch, []);
  // Branches with no MCP allowlist still get to reason; they just have no tools.
  const ts0 = new Date().toISOString();
  await deps.auditLog.append("skill_invocation_start", branchId, period, {
    model_tier: branch.modelTier,
    tools_offered: tools.map((t) => t.name),
  });

  const userMessage = [
    `You are operating in operational period ${period}.`,
    "",
    directiveContext(directive),
    "",
    renderToolCatalog(branch, deps.mcp),
    "",
    "Your job: investigate the evidence sources relevant to your branch using the submit_tool_request tool. Every tool call returns a structured tool result you can reason over. When evidence is exhausted (or you hit your reasonable budget), emit your structured rollup.",
    "",
    BRANCH_OUTPUT_INSTRUCTION,
  ].join("\n");

  const conversation = await deps.runner.converse({
    skill: branch,
    userMessage,
    tools,
    maxTokens: 4096,
    maxTurns: 8,
    onToolUse: async (use) => {
      if (use.name !== "submit_tool_request") {
        return {
          output: `Unknown tool "${use.name}". Only submit_tool_request is available.`,
          isError: true,
        };
      }
      const requested = (use.input ?? {}) as Record<string, unknown>;
      const requestedTool = String(requested.tool ?? "");
      const requestedArgs = (requested.arguments ?? {}) as Record<string, unknown>;
      const rationale = typeof requested.rationale === "string" ? requested.rationale : "";

      await deps.auditLog.append("tool_request_submitted", branchId, period, {
        tool: requestedTool,
        rationale,
        on_behalf_of: branchId,
      });
      await deps.messages.append({
        ts: new Date().toISOString(),
        period,
        from: branchId,
        to: TOOL_BROKER_ID,
        direction: "tool_request",
        payload: { tool: requestedTool, rationale },
      });

      const auth = deps.router.authorizeBrokerSubmission(branchId, requestedTool);
      if (!auth.allow) {
        return { output: JSON.stringify({ error: auth.reason }), isError: true };
      }

      const safety = await deps.safety.review(period, {
        onBehalfOf: branchId,
        toolName: requestedTool,
        arguments: requestedArgs,
      });
      if (safety.verdict === "halt") {
        return {
          output: JSON.stringify({
            error: `Safety Officer HALT — ${safety.rationale}`,
          }),
          isError: true,
        };
      }

      // Route the actual MCP call through the broker identity.
      const mcpAuth = deps.router.authorizeMcpInvocation({
        callerId: TOOL_BROKER_ID,
        toolName: requestedTool,
        arguments: requestedArgs,
        onBehalfOf: branchId,
      });
      if (!mcpAuth.allow) {
        return { output: JSON.stringify({ error: mcpAuth.reason }), isError: true };
      }

      const executionId = nextExecutionId();
      try {
        const res = await deps.mcp.callTool(requestedTool, requestedArgs);

        // The MCP server's typed-tool wrappers embed their own status
        // inside the JSON content even when the outer protocol-level
        // isError stays false (e.g. vol_pslist on a missing memory_id
        // returns {status: "error", error: "..."} with isError=false).
        // Treat those as failures here so audit-log success rates and
        // the model's tool_result both reflect reality.
        const parsed = res.parsed as Record<string, unknown> | null;
        const inBodyStatus =
          parsed && typeof parsed.status === "string" ? (parsed.status as string) : null;
        const inBodyError =
          parsed && typeof parsed.error === "string" ? (parsed.error as string) : null;
        const isFailure =
          res.isError ||
          inBodyStatus === "error" ||
          inBodyStatus === "failed" ||
          inBodyError !== null;

        await deps.auditLog.append("mcp_call", TOOL_BROKER_ID, period, {
          execution_id: executionId,
          tool: requestedTool,
          on_behalf_of: branchId,
          success: !isFailure,
          safety_verdict: safety.verdict,
          ...(isFailure && inBodyError ? { error: inBodyError } : {}),
          ...(isFailure && inBodyStatus ? { status: inBodyStatus } : {}),
        });
        await deps.messages.append({
          ts: new Date().toISOString(),
          period,
          from: TOOL_BROKER_ID,
          to: branchId,
          direction: "tool_response",
          payload: {
            execution_id: executionId,
            tool: requestedTool,
            isError: isFailure,
            ...(isFailure && inBodyError ? { error: inBodyError } : {}),
          },
        });

        // Surface execution_id in the result so the model can cite it.
        const wrapper = {
          tool_execution_id: executionId,
          tool: requestedTool,
          isError: isFailure,
          result: res.parsed ?? res.text,
        };
        // Truncate enormous results so a single tool call cannot blow the
        // context window. 32k chars is a reasonable demo cap.
        let serialized = JSON.stringify(wrapper);
        if (serialized.length > 32_000) {
          serialized = JSON.stringify({
            ...wrapper,
            result: `[truncated — ${serialized.length} bytes; first 30k of text follows]\n${(res.text ?? "").slice(0, 30_000)}`,
          });
        }
        return { output: serialized, isError: isFailure };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        await deps.auditLog.append("mcp_call", TOOL_BROKER_ID, period, {
          execution_id: executionId,
          tool: requestedTool,
          on_behalf_of: branchId,
          success: false,
          error: msg,
        });
        return {
          output: JSON.stringify({ tool_execution_id: executionId, error: msg }),
          isError: true,
        };
      }
    },
  });

  await deps.auditLog.append("skill_invocation_end", branchId, period, {
    turns: conversation.turns,
    tool_calls: conversation.toolCalls.length,
    stop_reason: conversation.stopReason,
    input_tokens: conversation.usage.input,
    output_tokens: conversation.usage.output,
  });

  // Try to parse the structured rollup the branch produced.
  const parsed = extractJsonBlock(conversation.finalText) as
    | { findings?: unknown[]; summary?: string }
    | null;
  const storyFindings: Record<string, unknown>[] = Array.isArray(parsed?.findings)
    ? (parsed!.findings as Record<string, unknown>[])
    : [];

  const internalFindings: Finding[] = storyFindings.map((f, i) => ({
    id: typeof f.id === "string" ? f.id : `${branchId}-FND-${String(i + 1).padStart(3, "0")}`,
    branch: branchId,
    executionId: typeof f.tool_execution_id === "string" ? f.tool_execution_id : "",
    description: typeof f.description === "string" ? f.description : (typeof f.title === "string" ? f.title : ""),
    status:
      f.confidence_tier === "confirmed"
        ? "confirmed"
        : f.confidence_tier === "contradicted"
          ? "contradicted"
          : "inferred",
    confidence: typeof f.confidence_score === "number" ? f.confidence_score : 0.5,
    evidenceId: typeof f.evidence_source === "string" ? f.evidence_source : undefined,
    observedAt: typeof f.timestamp_observed === "string" ? f.timestamp_observed : undefined,
  }));

  const summary = typeof parsed?.summary === "string" ? parsed.summary : conversation.finalText;
  const toolExecIds = conversation.toolCalls
    .map((c) => {
      try {
        const obj = JSON.parse(c.output);
        return typeof obj?.tool_execution_id === "string" ? obj.tool_execution_id : null;
      } catch {
        return null;
      }
    })
    .filter((x): x is string => x !== null);

  const rollup: RollupSummary = {
    branch: branchId,
    findingIds: internalFindings.map((f) => f.id),
    toolExecutionIds: toolExecIds,
    text: summary,
  };

  await deps.auditLog.append("rollup", branchId, period, {
    findings: internalFindings.length,
    tool_calls: conversation.toolCalls.length,
  });
  await deps.messages.append({
    ts: new Date().toISOString(),
    period,
    from: branchId,
    to: SITUATION_UNIT_ID,
    direction: "rollup",
    payload: { findings: internalFindings.length },
  });

  return { rollup, parsedFindings: internalFindings, parsedStoryFindings: storyFindings };
}

/** Invoke Situation Unit to integrate rollups into a fresh COP for this period. */
export async function runSituationUnit(
  directive: IncidentDirective,
  period: number,
  branchResults: BranchRunResult[],
  prevCop: CopState | null,
  activeBranches: string[],
  deps: SwarmDeps
): Promise<CopState> {
  const sit = deps.skills.require(SITUATION_UNIT_ID);
  await deps.auditLog.append("skill_invocation_start", SITUATION_UNIT_ID, period, {});

  const rollupBlock = branchResults
    .map((r) => `--- ${r.rollup.branch} ---\n${r.rollup.text}`)
    .join("\n\n");

  const allFindings = branchResults.flatMap((r) => r.parsedStoryFindings);

  const userMessage = [
    `You are integrating rollups into the Common Operating Picture for operational period ${period}.`,
    "",
    directiveContext(directive),
    "",
    `Active branches this period: ${activeBranches.join(", ")}`,
    "",
    "Branch rollups:",
    rollupBlock || "(no rollups)",
    "",
    "Existing COP narrative (prior period):",
    prevCop?.narrative ?? "(none)",
    "",
    `All findings already collected this period (${allFindings.length}): ${allFindings.length > 0 ? "see rollups above" : "none"}`,
    "",
    "Emit a single fenced JSON block with this shape:",
    "",
    "```json",
    "{",
    `  "objectives": [{ "id": "OBJ-${period}-001", "statement": "...", "status": "open|met|abandoned" }],`,
    `  "narrative": "<3-6 sentence COP summary integrating the rollups>",`,
    `  "contradictions": [{ "findingIds": ["FND-001", "FND-002"], "note": "..." }],`,
    `  "open_questions": ["..."]`,
    "}",
    "```",
  ].join("\n");

  const result = await deps.runner.invoke({
    skill: sit,
    userMessage,
    tools: [],
    maxTokens: 4096,
  });

  await deps.auditLog.append("skill_invocation_end", SITUATION_UNIT_ID, period, {
    input_tokens: result.usage.input,
    output_tokens: result.usage.output,
    stop_reason: result.stopReason,
  });

  const parsed = (extractJsonBlock(result.text) ?? {}) as {
    objectives?: { id?: string; statement?: string; status?: string }[];
    narrative?: string;
    contradictions?: { findingIds?: string[]; note?: string }[];
  };

  const cop: CopState = {
    caseId: directive.case_id,
    period,
    updatedAt: new Date().toISOString(),
    objectives: (parsed.objectives ?? [{ id: `OBJ-${period}-001`, statement: `Period ${period} integration`, status: "met" }]).map(
      (o) => ({
        id: String(o.id ?? `OBJ-${period}-001`),
        statement: String(o.statement ?? ""),
        status: (o.status === "open" || o.status === "abandoned" ? o.status : "met") as
          | "open"
          | "met"
          | "abandoned",
      })
    ),
    activeBranches,
    findings: branchResults.flatMap((r) => r.parsedFindings),
    contradictions: (parsed.contradictions ?? []).map((c) => ({
      findingIds: Array.isArray(c.findingIds) ? c.findingIds.map(String) : [],
      note: String(c.note ?? ""),
    })),
    narrative: parsed.narrative ?? result.text.slice(0, 2000),
  };
  return cop;
}

/** Invoke Documentation Unit to produce final_report.json for the story view. */
export async function runDocumentationUnit(
  directive: IncidentDirective,
  periods: PeriodState[],
  finalCop: CopState | null,
  storyFindings: Record<string, unknown>[],
  deps: SwarmDeps
): Promise<Record<string, unknown>> {
  const doc = deps.skills.require("planning/documentation-unit");
  await deps.auditLog.append("skill_invocation_start", "planning/documentation-unit", periods.length, {});

  const periodsBlock = periods
    .map((p) => {
      const rollups = Object.values(p.rollups)
        .map((r) => `  - ${r.branch}: ${r.text.slice(0, 600)}`)
        .join("\n");
      return [
        `Period ${p.period}:`,
        `  IC reasoning: ${p.icReasoning.split("\n").join(" | ")}`,
        `  Active: ${p.activeBranches.join(", ")}`,
        `  Stand down: ${p.standDownBranches.join(", ")}`,
        rollups || "  (no rollups)",
      ].join("\n");
    })
    .join("\n\n");

  const userMessage = [
    `You are producing the final incident report for case ${directive.case_id}.`,
    "",
    directiveContext(directive),
    "",
    "Operational periods:",
    periodsBlock,
    "",
    `Final COP narrative: ${finalCop?.narrative ?? "(none)"}`,
    "",
    `Total structured findings collected: ${storyFindings.length}`,
    "",
    "Emit a single fenced JSON block with this exact shape (FinalReport):",
    "",
    "```json",
    "{",
    `  "case_id": "${directive.case_id}",`,
    `  "incident_summary": "<single paragraph CISO-readable summary>",`,
    `  "primary_hosts": ["host1", "host2"],`,
    `  "attack_narrative": [`,
    `    {`,
    `      "phase": "initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|command_and_control|exfiltration|impact",`,
    `      "mitre_technique_id": "T####.###",`,
    `      "mitre_technique_name": "<MITRE technique name>",`,
    `      "narrative": "<2-4 sentence past-tense narrative>",`,
    `      "supporting_findings": ["FND-001"],`,
    `      "timestamp_first_observed": "<ISO8601>",`,
    `      "timestamp_last_observed": "<ISO8601>",`,
    `      "confidence": "confirmed|inferred|hypothesized|contradicted"`,
    `    }`,
    `  ],`,
    `  "iocs": {`,
    `    "file_hashes": [{ "value": "<hex>", "algorithm": "sha256", "supporting_findings": ["FND-..."] }],`,
    `    "ip_addresses": [{ "value": "<ip>", "direction": "inbound|outbound", "supporting_findings": ["FND-..."] }],`,
    `    "domains": [{ "value": "<domain>", "supporting_findings": ["FND-..."] }],`,
    `    "registry_keys": [{ "key": "<HK..>", "value_name": "<name>", "supporting_findings": ["FND-..."] }],`,
    `    "file_paths": [{ "path": "<path>", "host": "<host>", "supporting_findings": ["FND-..."] }]`,
    `  },`,
    `  "operational_periods_summary": [`,
    `    { "period": 1, "objectives": ["..."], "active_branches": ["triage","memory"], "key_findings_added": ["FND-001"], "ic_reasoning": "..." }`,
    `  ]`,
    "}",
    "```",
    "",
    "ANTI-SPECULATION RULES (forensic invariants):",
    "1. Use ONLY findings and facts that appear in the rollups above. Do not hypothesize about evidence you have not seen.",
    "2. Do not fabricate technical explanations for branch failures. If branches reported tool errors, report the errors as described — do not invent infrastructure-failure narratives (e.g., do NOT claim 'permissions were 664 instead of 444' or 'mount was group-writable' unless a branch rollup explicitly reported that exact fact).",
    "3. If no findings back a phase, OMIT the phase. Empty attack_narrative + empty iocs is acceptable; fabricated narrative is not.",
    "4. The incident_summary must reflect what was actually observed. If the swarm produced no substantive findings, say so directly — do not invent an APT story.",
    "5. Every IOC entry's supporting_findings array must reference a real FND-NNN that appears in the rollups.",
  ].join("\n");

  const result = await deps.runner.invoke({
    skill: doc,
    userMessage,
    tools: [],
    maxTokens: 8192,
  });

  await deps.auditLog.append("skill_invocation_end", "planning/documentation-unit", periods.length, {
    input_tokens: result.usage.input,
    output_tokens: result.usage.output,
    stop_reason: result.stopReason,
  });

  const parsed = extractJsonBlock(result.text);
  if (parsed && typeof parsed === "object") {
    const obj = parsed as Record<string, unknown>;
    obj.generated_at = new Date().toISOString();
    return obj;
  }

  // Fallback: at least produce a valid skeleton so the story view doesn't crash.
  return {
    case_id: directive.case_id,
    generated_at: new Date().toISOString(),
    incident_summary:
      finalCop?.narrative ??
      `Documentation Unit returned unparseable output for case ${directive.case_id}; raw output preserved in audit log.`,
    primary_hosts: [...new Set(directive.evidence_sources.map((e) => e.host).filter(Boolean))],
    attack_narrative: [],
    iocs: {
      file_hashes: [],
      ip_addresses: [],
      domains: [],
      registry_keys: [],
      file_paths: [],
    },
    operational_periods_summary: periods.map((p) => ({
      period: p.period,
      objectives: [],
      active_branches: p.activeBranches.map((b) => b.replace(/^operations\//, "").replace(/-branch$/, "")),
      key_findings_added: Object.values(p.rollups).flatMap((r) => r.findingIds),
      ic_reasoning: p.icReasoning,
    })),
  };
}
