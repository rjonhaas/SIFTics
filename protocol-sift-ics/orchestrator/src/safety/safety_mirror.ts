// Safety Officer mirror — synchronous pre-execution hook on every Tool
// Broker MCP invocation.
//
// The orchestrator hands every proposed MCP call to the Safety Officer
// subagent; the officer returns clear / flag / halt within a configurable
// window (default 200ms). Halt aborts the call. Flag annotates and
// proceeds. Timeout = log + proceed (per CLAUDE.md invariant #7).
//
// This module owns the timeout, the audit-log linkage, and the contract
// the Safety Officer subagent must satisfy. The actual model invocation
// behind `evaluate` is plugged in by the orchestrator at wire-up time.

import type { AuditLog } from "../persistence/audit_log.js";
import { SAFETY_OFFICER_ID } from "../routing.js";

export type SafetyVerdict = "clear" | "flag" | "halt";

export interface ProposedCall {
  /** Originating skill (the broker is dispatching on this skill's behalf). */
  onBehalfOf: string;
  toolName: string;
  arguments: Record<string, unknown>;
}

export interface SafetyDecision {
  verdict: SafetyVerdict;
  /** Free-form rationale. Always present, even on `clear`, for audit. */
  rationale: string;
  /** True when the verdict came from the timeout path (defaults to clear+flag). */
  timedOut: boolean;
}

/** Plug-in evaluator. Real implementation calls Safety Officer subagent;
 *  tests can substitute a deterministic stub. */
export type SafetyEvaluator = (
  call: ProposedCall,
  signal: AbortSignal
) => Promise<{ verdict: SafetyVerdict; rationale: string }>;

export interface SafetyMirrorConfig {
  /** Per-call timeout in ms. Default 200. CLAUDE.md invariant #7. */
  timeoutMs?: number;
  evaluator: SafetyEvaluator;
  auditLog: AuditLog;
}

export class SafetyMirror {
  private readonly timeoutMs: number;

  constructor(private readonly config: SafetyMirrorConfig) {
    this.timeoutMs = config.timeoutMs ?? 200;
  }

  async review(period: number, call: ProposedCall): Promise<SafetyDecision> {
    const ac = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const timeoutPromise = new Promise<SafetyDecision>((resolve) => {
      timer = setTimeout(() => {
        ac.abort();
        resolve({
          verdict: "flag",
          rationale: `safety mirror timed out after ${this.timeoutMs}ms — proceeding with flag annotation`,
          timedOut: true,
        });
      }, this.timeoutMs);
    });

    const evalPromise = this.config.evaluator(call, ac.signal).then((r) => ({
      verdict: r.verdict,
      rationale: r.rationale,
      timedOut: false,
    }));

    let decision: SafetyDecision;
    try {
      decision = await Promise.race([evalPromise, timeoutPromise]);
    } finally {
      if (timer) clearTimeout(timer);
    }

    const kind =
      decision.verdict === "halt"
        ? "safety_mirror_halt"
        : decision.verdict === "flag"
          ? "safety_mirror_flag"
          : "safety_mirror_clear";

    await this.config.auditLog.append(kind, SAFETY_OFFICER_ID, period, {
      tool: call.toolName,
      onBehalfOf: call.onBehalfOf,
      verdict: decision.verdict,
      rationale: decision.rationale,
      timedOut: decision.timedOut,
    });

    return decision;
  }
}

/** Default evaluator: trivial pass-through that approves everything cleanly.
 *  Useful in dry-run / pre-LLM testing; the real evaluator wraps a Safety
 *  Officer subagent invocation. */
export const passThroughEvaluator: SafetyEvaluator = async () => ({
  verdict: "clear",
  rationale: "pass-through evaluator (no Safety Officer subagent wired)",
});
