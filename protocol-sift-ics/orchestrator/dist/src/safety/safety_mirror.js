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
import { SAFETY_OFFICER_ID } from "../routing.js";
export class SafetyMirror {
    config;
    timeoutMs;
    constructor(config) {
        this.config = config;
        this.timeoutMs = config.timeoutMs ?? 200;
    }
    async review(period, call) {
        const ac = new AbortController();
        let timer;
        const timeoutPromise = new Promise((resolve) => {
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
        let decision;
        try {
            decision = await Promise.race([evalPromise, timeoutPromise]);
        }
        finally {
            if (timer)
                clearTimeout(timer);
        }
        const kind = decision.verdict === "halt"
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
export const passThroughEvaluator = async () => ({
    verdict: "clear",
    rationale: "pass-through evaluator (no Safety Officer subagent wired)",
});
//# sourceMappingURL=safety_mirror.js.map