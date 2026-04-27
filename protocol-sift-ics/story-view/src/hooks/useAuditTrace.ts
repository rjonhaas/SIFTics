import { useMemo } from "react";
import type { AuditEntry, CaseData, Finding } from "../types";

export interface TraceNode {
  kind:
    | "finding"
    | "tool_invocation"
    | "inter_skill_message"
    | "objective"
    | "ic_reasoning"
    | "missing";
  label: string;
  detail: string;
  audit?: AuditEntry;
  hashOk: boolean;
  prevHash?: string;
  thisHash?: string;
  finding?: Finding;
  children: TraceNode[];
}

interface TraceResult {
  root: TraceNode | null;
  chainIntact: boolean;
  brokenAt?: string;
}

function verifyChain(audit: AuditEntry[]): { ok: boolean; brokenAt?: string } {
  // Naive verification: every entry's prev_hash must equal the previous entry's this_hash.
  // (Real cryptographic verification happens in the orchestrator. The story view checks
  // structural continuity for the UI badge.)
  for (let i = 1; i < audit.length; i++) {
    if (audit[i].prev_hash !== audit[i - 1].this_hash) {
      return { ok: false, brokenAt: audit[i].audit_id };
    }
  }
  return { ok: true };
}

function findingToNode(finding: Finding, hashOk: boolean): TraceNode {
  return {
    kind: "finding",
    label: finding.id,
    detail: finding.title,
    hashOk,
    finding,
    children: [],
  };
}

function auditToNode(
  entry: AuditEntry,
  kind: TraceNode["kind"],
  label: string,
  detail: string,
  hashOk: boolean
): TraceNode {
  return {
    kind,
    label,
    detail,
    audit: entry,
    hashOk,
    prevHash: entry.prev_hash,
    thisHash: entry.this_hash,
    children: [],
  };
}

export function useAuditTrace(
  caseData: CaseData | undefined,
  findingId: string | null
) {
  return useMemo<TraceResult>(() => {
    if (!caseData || !findingId) return { root: null, chainIntact: true };

    const finding = caseData.findingsById.get(findingId);
    if (!finding) {
      return {
        root: {
          kind: "missing",
          label: findingId,
          detail: "No finding with that ID exists in this case.",
          hashOk: false,
          children: [],
        },
        chainIntact: false,
      };
    }

    const verification = verifyChain(caseData.auditLog);

    // Locate the audit chain backward from the finding.
    const findingAudit = caseData.auditLog.find(
      (a) =>
        a.event_type === "finding_produced" &&
        (a.payload.finding_id === finding.id ||
          (a.payload as Record<string, unknown>).id === finding.id)
    );

    const findingNode = findingToNode(finding, verification.ok);

    if (!findingAudit) {
      findingNode.children.push({
        kind: "missing",
        label: "audit gap",
        detail: "No audit entry references this finding's production.",
        hashOk: false,
        children: [],
      });
      return {
        root: findingNode,
        chainIntact: false,
        brokenAt: verification.brokenAt,
      };
    }

    const toolInvocationId = finding.tool_execution_id;
    const toolAudit = caseData.auditLog.find(
      (a) =>
        a.event_type === "tool_invocation" &&
        ((a.payload.tool_execution_id ?? a.payload.id) === toolInvocationId)
    );

    if (!toolAudit) {
      findingNode.children.push({
        kind: "missing",
        label: toolInvocationId,
        detail: "Tool execution audit entry not found.",
        hashOk: false,
        children: [],
      });
      return {
        root: findingNode,
        chainIntact: false,
        brokenAt: verification.brokenAt,
      };
    }

    const fn = (toolAudit.payload.mcp_function ?? "tool") as string;
    const toolNode = auditToNode(
      toolAudit,
      "tool_invocation",
      fn,
      `MCP function ${fn} executed by ${toolAudit.subagent}`,
      verification.ok
    );

    // Inter-skill message (the request that asked the tool to run)
    const parentId = toolAudit.payload.parent_audit_id as string | undefined;
    const messageAudit =
      parentId !== undefined
        ? caseData.auditById.get(parentId)
        : caseData.auditLog
            .filter((a) => a.event_type === "inter_skill_message")
            .find((a) => a.timestamp <= toolAudit.timestamp);

    if (messageAudit) {
      const msgNode = auditToNode(
        messageAudit,
        "inter_skill_message",
        messageAudit.subagent,
        (messageAudit.payload.message as string) ?? "(no message text)",
        verification.ok
      );

      // Operational-period objective audit
      const objectiveAudit = caseData.auditLog
        .filter(
          (a) =>
            a.event_type === "objective_set" &&
            (a.payload.period ?? -1) === finding.operational_period_id
        )
        .at(-1);

      if (objectiveAudit) {
        const objNode = auditToNode(
          objectiveAudit,
          "objective",
          `Period ${objectiveAudit.payload.period}`,
          (objectiveAudit.payload.objective as string) ?? "objective",
          verification.ok
        );

        const reasoningAudit = caseData.auditLog
          .filter(
            (a) =>
              a.event_type === "ic_reasoning" &&
              (a.payload.period ?? -1) === finding.operational_period_id
          )
          .at(-1);

        if (reasoningAudit) {
          objNode.children.push(
            auditToNode(
              reasoningAudit,
              "ic_reasoning",
              "IC",
              (reasoningAudit.payload.reasoning as string) ?? "(no reasoning)",
              verification.ok
            )
          );
        }
        msgNode.children.push(objNode);
      }
      toolNode.children.push(msgNode);
    }

    findingNode.children.push(toolNode);

    return {
      root: findingNode,
      chainIntact: verification.ok,
      brokenAt: verification.brokenAt,
    };
  }, [caseData, findingId]);
}
