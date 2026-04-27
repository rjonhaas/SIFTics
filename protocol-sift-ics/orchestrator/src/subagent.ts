// One Anthropic API call per skill activation. Subagent isolation comes from
// every invocation getting its own conversation — no shared messages array
// across skills. The orchestrator owns the conversation; the model only
// sees its own SKILL.md as system prompt and the user message it was
// activated with.
//
// Per the migration spec: temperature=0 always. Reproducibility is required
// for forensic soundness.

import Anthropic from "@anthropic-ai/sdk";

import type { SkillConfig } from "./skill_loader.js";
import { TIER_TO_MODEL } from "./skill_loader.js";
import { TOOL_BROKER_ID } from "./routing.js";

export interface InvocationInput {
  skill: SkillConfig;
  /** User message — the directive, task, or rollup request. */
  userMessage: string;
  /** Tool definitions surfaced to the model. */
  tools: Anthropic.Tool[];
  /** Soft cap on assistant output tokens. */
  maxTokens?: number;
}

export interface InvocationOutput {
  /** Full text content of the assistant's reply (concatenated text blocks). */
  text: string;
  /** Tool-use blocks the model emitted, in order. */
  toolUses: { id: string; name: string; input: Record<string, unknown> }[];
  /** Stop reason from the model. */
  stopReason: string;
  /** Usage stats (input/output tokens). */
  usage: { input: number; output: number };
}

export interface SubagentRunner {
  invoke(input: InvocationInput): Promise<InvocationOutput>;
}

export class AnthropicSubagentRunner implements SubagentRunner {
  private readonly client: Anthropic;

  constructor(apiKey?: string) {
    this.client = new Anthropic({ apiKey: apiKey ?? process.env.ANTHROPIC_API_KEY });
  }

  async invoke(input: InvocationInput): Promise<InvocationOutput> {
    const model = TIER_TO_MODEL[input.skill.modelTier];
    const resp = await this.client.messages.create({
      model,
      max_tokens: input.maxTokens ?? 8192,
      temperature: 0,
      system: input.skill.systemPrompt,
      tools: input.tools,
      messages: [{ role: "user", content: input.userMessage }],
    });

    const text = resp.content
      .filter((b): b is Anthropic.TextBlock => b.type === "text")
      .map((b) => b.text)
      .join("\n");

    const toolUses = resp.content
      .filter((b): b is Anthropic.ToolUseBlock => b.type === "tool_use")
      .map((b) => ({ id: b.id, name: b.name, input: b.input as Record<string, unknown> }));

    return {
      text,
      toolUses,
      stopReason: resp.stop_reason ?? "unknown",
      usage: { input: resp.usage.input_tokens, output: resp.usage.output_tokens },
    };
  }
}

/** Synthetic tool every non-broker skill receives. The orchestrator captures
 *  these emissions, validates the typed payload, and routes through the
 *  Tool Broker subagent. */
export const SUBMIT_TOOL_REQUEST: Anthropic.Tool = {
  name: "submit_tool_request",
  description:
    "Submit a typed forensic-tool request to the Tool Broker. Branch agents " +
    "do not have direct access to forensic tools; every tool invocation must " +
    "be brokered. Provide the MCP tool name and its arguments. The broker " +
    "validates against your allowlist, mirrors to the Safety Officer, and " +
    "returns the structured result.",
  input_schema: {
    type: "object",
    properties: {
      tool: { type: "string", description: "MCP tool name from your allowlist" },
      arguments: { type: "object", description: "Arguments object for the tool" },
      rationale: {
        type: "string",
        description: "Why this call is being made — for audit trail",
      },
    },
    required: ["tool", "arguments"],
  },
};

/** Returns the tool list the orchestrator should pass to a given skill. */
export function toolsForSkill(
  skill: SkillConfig,
  mcpTools: Anthropic.Tool[]
): Anthropic.Tool[] {
  if (skill.id === TOOL_BROKER_ID) {
    // Broker gets the full MCP tool surface.
    return mcpTools;
  }
  // Non-broker skills get the synthetic submit_tool_request only when they
  // have any allowed MCP access. Skills with empty allowlists (IC, planning
  // units, etc.) get no tools — they only delegate or write COP/etc.
  if (skill.mcpTools.all || (skill.mcpTools.allowlist?.length ?? 0) > 0) {
    return [SUBMIT_TOOL_REQUEST];
  }
  return [];
}
