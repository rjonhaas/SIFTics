// Routing layer — the single architectural enforcement point of the swarm.
//
// Three properties are enforced here, in code, NOT in subagent prompts:
//
//   1. Tool Broker exclusivity. Only `logistics/tool-broker` may invoke
//      MCP tools. Every other skill submits a typed request that the
//      router dispatches to the broker.
//
//   2. COP write isolation. Only `planning/situation-unit` may write to
//      the COP store. All other skills read.
//
//   3. Audit-log identity. Every event is tagged with the calling skill's
//      identity as established from subagent context — never from the
//      request payload. A subagent cannot forge identity.
//
// Tests in test/routing.test.ts verify each of these.
export const TOOL_BROKER_ID = "logistics/tool-broker";
export const SITUATION_UNIT_ID = "planning/situation-unit";
export const SAFETY_OFFICER_ID = "command-staff/safety-officer";
export class Router {
    skills;
    constructor(skills) {
        this.skills = skills;
    }
    /** Direct MCP invocation: only the Tool Broker may do this. */
    authorizeMcpInvocation(request) {
        if (request.callerId !== TOOL_BROKER_ID) {
            return {
                allow: false,
                reason: `Routing: skill "${request.callerId}" attempted direct MCP invocation; ` +
                    `only "${TOOL_BROKER_ID}" may invoke MCP tools.`,
            };
        }
        // Even the broker honors per-skill allowlists when dispatching on
        // behalf of another skill.
        if (request.onBehalfOf) {
            const skill = this.skills.get(request.onBehalfOf);
            if (!skill) {
                return { allow: false, reason: `Routing: unknown originating skill "${request.onBehalfOf}"` };
            }
            if (!skillMayCallTool(skill, request.toolName)) {
                return {
                    allow: false,
                    reason: `Routing: skill "${request.onBehalfOf}" allowlist does not include ` +
                        `"${request.toolName}".`,
                };
            }
        }
        return { allow: true };
    }
    /** Branch-side: a non-broker skill submits a typed request to be
     *  forwarded to the Tool Broker. The router checks the requesting skill's
     *  allowlist before forwarding. */
    authorizeBrokerSubmission(callerId, toolName) {
        if (callerId === TOOL_BROKER_ID) {
            return { allow: false, reason: "Routing: tool-broker should call MCP directly, not submit_tool_request to itself" };
        }
        const skill = this.skills.get(callerId);
        if (!skill) {
            return { allow: false, reason: `Routing: unknown caller "${callerId}"` };
        }
        if (!skillMayCallTool(skill, toolName)) {
            return {
                allow: false,
                reason: `Routing: skill "${callerId}" allowlist does not include "${toolName}". ` +
                    `Allowed: [${(skill.mcpTools.allowlist ?? []).join(", ")}]`,
            };
        }
        return { allow: true };
    }
    /** Only Situation Unit may write to the COP. */
    authorizeCopWrite(callerId) {
        if (callerId !== SITUATION_UNIT_ID) {
            return {
                allow: false,
                reason: `Routing: skill "${callerId}" attempted COP write; ` +
                    `only "${SITUATION_UNIT_ID}" may write the COP.`,
            };
        }
        return { allow: true };
    }
    /** COP reads are open to any registered skill. */
    authorizeCopRead(callerId) {
        if (!this.skills.get(callerId)) {
            return { allow: false, reason: `Routing: unknown caller "${callerId}"` };
        }
        return { allow: true };
    }
    /** A skill may delegate to another only if its `invoke` permission allows
     *  the target. `command-staff/*` glob is permitted on the IC. */
    authorizeDelegation(callerId, targetId) {
        const caller = this.skills.get(callerId);
        if (!caller)
            return { allow: false, reason: `Routing: unknown caller "${callerId}"` };
        for (const allowed of caller.permissions.invoke) {
            if (allowed === targetId)
                return { allow: true };
            if (allowed.endsWith("/*")) {
                const prefix = allowed.slice(0, -1);
                if (targetId.startsWith(prefix))
                    return { allow: true };
            }
        }
        return {
            allow: false,
            reason: `Routing: skill "${callerId}" cannot invoke "${targetId}". ` +
                `Allowed: [${caller.permissions.invoke.join(", ")}]`,
        };
    }
}
function skillMayCallTool(skill, toolName) {
    if (skill.mcpTools.all)
        return true;
    return (skill.mcpTools.allowlist ?? []).includes(toolName);
}
//# sourceMappingURL=routing.js.map