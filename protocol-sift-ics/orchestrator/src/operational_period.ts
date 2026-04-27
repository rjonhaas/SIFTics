// The operational period loop. The IC sets objectives, decides which
// branches to activate, awaits rollups, the Situation Unit integrates
// findings into the COP, and the IC decides whether to open another
// period or close. Hard cap of MAX_PERIODS per case.
//
// This module is the conductor; it does not do the model invocations
// itself. Plug in a SubagentRunner + Router + persistence stack at
// construction. In --dry-run mode the SubagentRunner is replaced by a
// deterministic stub that exercises the routing/persistence path
// without burning tokens.

import type { SubagentRunner } from "./subagent.js";
import type { SkillConfig, SkillRegistry } from "./skill_loader.js";
import type { Router } from "./routing.js";
import type { CopState, CopStore, Finding } from "./persistence/cop_store.js";
import type { PeriodState, PeriodStateStore, RollupSummary } from "./persistence/period_state.js";
import type { AuditLog } from "./persistence/audit_log.js";
import type { InterSkillMessageLog } from "./persistence/inter_skill_messages.js";
import type { SafetyMirror } from "./safety/safety_mirror.js";
import type { McpClient } from "./mcp_client.js";

import { TOOL_BROKER_ID, SITUATION_UNIT_ID } from "./routing.js";

export const MAX_PERIODS = 4;

export interface DirectiveEvidenceSource {
  type: "memory" | "disk" | "pcap" | "logs" | "velociraptor" | "endpoint" | "other";
  path: string;
  host?: string;
  os?: string;
  sha256?: string;
  sizeBytes?: number;
}

export interface IncidentDirective {
  incident_id: string;
  case_id: string;
  description: string;
  evidence_sources: DirectiveEvidenceSource[];
  initial_hypothesis?: string;
  priority: "low" | "medium" | "high" | "critical";
  constraints?: string[];
}

export interface PeriodLoopDeps {
  skills: SkillRegistry;
  router: Router;
  copStore: CopStore;
  periodStore: PeriodStateStore;
  auditLog: AuditLog;
  messages: InterSkillMessageLog;
  safety: SafetyMirror;
  mcp: McpClient | null;
  runner: SubagentRunner | null; // null when --dry-run
}

export interface PeriodLoopResult {
  periods: PeriodState[];
  finalCop: CopState | null;
  closeReason: PeriodState["closeReason"];
}

export class OperationalPeriodLoop {
  constructor(private readonly deps: PeriodLoopDeps) {}

  async run(directive: IncidentDirective, dryRun: boolean): Promise<PeriodLoopResult> {
    await this.deps.auditLog.append("incident_open", "human_operator", 0, {
      incident_id: directive.incident_id,
      case_id: directive.case_id,
      evidence_count: directive.evidence_sources.length,
      priority: directive.priority,
      dry_run: dryRun,
    });

    const periods: PeriodState[] = [];
    let closeReason: PeriodState["closeReason"] = "completed";

    for (let p = 1; p <= MAX_PERIODS; p++) {
      const period = await this.runPeriod(p, directive, dryRun);
      periods.push(period);

      if (period.closeReason === "safety_halt") {
        closeReason = "safety_halt";
        break;
      }

      // The IC's final reasoning at period close determines whether to open
      // another period. In dry-run we close after one period to keep output
      // bounded.
      if (dryRun) {
        closeReason = "completed";
        break;
      }

      const cop = await this.deps.copStore.readCurrent("planning/situation-unit");
      const open = (cop?.objectives ?? []).some((o) => o.status === "open");
      if (!open) {
        closeReason = "completed";
        break;
      }
      if (p === MAX_PERIODS) {
        closeReason = "budget";
      }
    }

    await this.deps.auditLog.append(
      closeReason === "budget" ? "incident_truncated" : "incident_close",
      "command-staff/incident-commander",
      periods.length,
      { periods_run: periods.length, close_reason: closeReason }
    );

    const finalCop = await this.deps.copStore.readCurrent("planning/situation-unit");
    return { periods, finalCop, closeReason };
  }

  private async runPeriod(
    p: number,
    directive: IncidentDirective,
    dryRun: boolean
  ): Promise<PeriodState> {
    const startedAt = new Date().toISOString();
    await this.deps.auditLog.append("period_start", "command-staff/incident-commander", p, {
      directive_id: directive.incident_id,
    });

    const activeBranches = this.selectBranches(directive);
    const standDownBranches = this.skillsByPath("operations/")
      .filter((s) => s.id.endsWith("-branch") && !activeBranches.includes(s.id))
      .map((s) => s.id);

    const icReasoning = this.formatIcReasoning(directive, activeBranches, standDownBranches);

    await this.deps.auditLog.append("ic_decision", "command-staff/incident-commander", p, {
      active_branches: activeBranches,
      stand_down: standDownBranches,
      reasoning: icReasoning,
    });

    const rollups: Record<string, RollupSummary> = {};
    if (!dryRun && this.deps.runner !== null) {
      // Real run: each active branch is invoked through the orchestrator.
      // The full delegation/rollup conversation is not yet implemented in
      // this iteration; this is the seam where the production swarm runner
      // plugs in. The dry-run path below exercises every routing and
      // persistence touchpoint that does not require an LLM.
      throw new Error(
        "Live swarm execution not yet implemented at this milestone. " +
          "Run with --dry-run to validate routing and persistence."
      );
    } else {
      for (const id of activeBranches) {
        rollups[id] = {
          branch: id,
          findingIds: [],
          toolExecutionIds: [],
          text: `[dry-run] ${id} would investigate ${directive.evidence_sources.length} evidence source(s).`,
        };
        await this.deps.messages.append({
          ts: new Date().toISOString(),
          period: p,
          from: "command-staff/incident-commander",
          to: id,
          direction: "delegate",
          payload: { dry_run: true, evidence_count: directive.evidence_sources.length },
        });
      }
    }

    // Situation Unit integrates rollups into the COP. In dry-run the COP
    // is still produced and written so the persistence layer is exercised.
    const cop: CopState = {
      caseId: directive.case_id,
      period: p,
      updatedAt: new Date().toISOString(),
      objectives: [
        {
          id: `OBJ-${p}-001`,
          statement: `Period ${p} dry-run sweep`,
          status: "met",
        },
      ],
      activeBranches,
      findings: [], // dry-run produces no findings
      contradictions: [],
      narrative:
        `[dry-run period ${p}] selective activation chose ${activeBranches.length} branch(es); ` +
        `${standDownBranches.length} stood down for absence of relevant evidence.`,
    };
    await this.deps.copStore.write(SITUATION_UNIT_ID, cop);
    await this.deps.auditLog.append("cop_write", SITUATION_UNIT_ID, p, {
      findings: cop.findings.length,
      objectives: cop.objectives.length,
    });

    const closedAt = new Date().toISOString();
    await this.deps.auditLog.append("period_close", "command-staff/incident-commander", p, {
      close_reason: "completed",
    });

    const state: PeriodState = {
      caseId: directive.case_id,
      period: p,
      startedAt,
      closedAt,
      icReasoning,
      activeBranches,
      standDownBranches,
      rollups,
      closeReason: "completed",
    };
    await this.deps.periodStore.write(state);
    return state;
  }

  /** Selective activation: branches with no relevant evidence stand down. */
  private selectBranches(directive: IncidentDirective): string[] {
    const sources = directive.evidence_sources;
    const has = (t: DirectiveEvidenceSource["type"]) => sources.some((s) => s.type === t);
    const active = new Set<string>(["operations/triage-branch"]);
    if (has("memory")) active.add("operations/memory-branch");
    if (has("pcap")) active.add("operations/network-branch");
    if (has("disk") || has("logs") || has("velociraptor")) active.add("operations/forensics-branch");
    // Malware Branch only activates when something else flags an executable;
    // not yet wired here. (Per CLAUDE.md activation pattern.)
    return [...active];
  }

  private skillsByPath(prefix: string): SkillConfig[] {
    return this.deps.skills.all().filter((s) => s.id.startsWith(prefix));
  }

  private formatIcReasoning(
    directive: IncidentDirective,
    active: string[],
    standDown: string[]
  ): string {
    const types = new Set(directive.evidence_sources.map((s) => s.type));
    return [
      `Evidence inventory: ${[...types].join(", ") || "(empty)"}`,
      `Activated: ${active.join(", ")}`,
      `Stood down: ${standDown.join(", ") || "(none)"}`,
      `Initial hypothesis: ${directive.initial_hypothesis ?? "(none provided)"}`,
    ].join("\n");
  }
}
