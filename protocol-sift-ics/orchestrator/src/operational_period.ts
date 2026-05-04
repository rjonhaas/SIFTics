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
import { runBranch, runSituationUnit, type BranchRunResult } from "./swarm.js";

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
  /** When set, restricts evidence-prep to only these EVD-NNN ids. Used to
   *  keep working-copy disk usage bounded on demo runs. Empty/unset means
   *  prepare every memory/disk source in the directive. */
  prepareOnly?: string[];
  /** When set, overrides selective branch activation with this explicit list
   *  (e.g. ["operations/memory-branch"] to run Memory only). Used for tight
   *  test-cycle iteration when full multi-branch coverage isn't needed. */
  branchesOverride?: string[];
}

export interface PeriodLoopResult {
  periods: PeriodState[];
  finalCop: CopState | null;
  closeReason: PeriodState["closeReason"];
  /** Story-view-shaped findings collected across all periods. Used by index.ts
   *  to write findings.json. Empty in dry-run. */
  storyFindings: Record<string, unknown>[];
}

export class OperationalPeriodLoop {
  constructor(private readonly deps: PeriodLoopDeps) {}

  /** Story-view findings accumulated across periods (live runs only). */
  private storyFindings: Record<string, unknown>[] = [];

  async run(directive: IncidentDirective, dryRun: boolean): Promise<PeriodLoopResult> {
    await this.deps.auditLog.append("incident_open", "human_operator", 0, {
      incident_id: directive.incident_id,
      case_id: directive.case_id,
      evidence_count: directive.evidence_sources.length,
      priority: directive.priority,
      dry_run: dryRun,
    });

    this.storyFindings = [];
    const periods: PeriodState[] = [];
    let closeReason: PeriodState["closeReason"] = "completed";

    // Evidence Store custody preparation. Real DFIR practice: hash original,
    // copy to working location, chmod 444, hash copy, verify match, log
    // chain entry. Until this runs, the analytical branches' tools cannot
    // read evidence (the ReadOnlyGuard rejects originals whose mode bits
    // aren't already 444). This is the orchestrator dispatching as the
    // Evidence Store skill; the Logistics Chief's role per CLAUDE.md
    // org chart.
    if (!dryRun && this.deps.mcp !== null) {
      await this.prepareEvidenceCustody(directive);
    }

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
    return { periods, finalCop, closeReason, storyFindings: [...this.storyFindings] };
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
    let cop: CopState;

    if (!dryRun && this.deps.runner !== null && this.deps.mcp !== null) {
      // Live run: invoke each active branch via the swarm helpers, then
      // hand rollups to the Situation Unit for COP integration.
      const swarmDeps = {
        skills: this.deps.skills,
        router: this.deps.router,
        copStore: this.deps.copStore,
        auditLog: this.deps.auditLog,
        messages: this.deps.messages,
        safety: this.deps.safety,
        mcp: this.deps.mcp,
        runner: this.deps.runner,
      };

      const branchResults: BranchRunResult[] = [];
      for (const id of activeBranches) {
        const skill = this.deps.skills.get(id);
        if (!skill) {
          await this.deps.auditLog.append("ic_decision", "command-staff/incident-commander", p, {
            note: `active branch "${id}" not found in registry — skipping`,
          });
          continue;
        }
        await this.deps.messages.append({
          ts: new Date().toISOString(),
          period: p,
          from: "command-staff/incident-commander",
          to: id,
          direction: "delegate",
          payload: { evidence_count: directive.evidence_sources.length },
        });
        const result = await runBranch(skill, directive, p, swarmDeps);
        rollups[id] = result.rollup;
        branchResults.push(result);
        for (const f of result.parsedStoryFindings) this.storyFindings.push(f);
      }

      const prevCop = await this.deps.copStore.readCurrent(SITUATION_UNIT_ID);
      cop = await runSituationUnit(directive, p, branchResults, prevCop, activeBranches, swarmDeps);
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
      cop = {
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
    }

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

  /** Evidence Store custody pass: invoke prepare_working_copy via MCP for
   *  each memory/disk evidence source in the directive (or only those in
   *  prepareOnly when set). The orchestrator dispatches as the Evidence
   *  Store skill — identity is set by the orchestrator, not the payload. */
  private async prepareEvidenceCustody(directive: IncidentDirective): Promise<void> {
    if (this.deps.mcp === null) return;
    const evidenceStoreId = "logistics/evidence-store";
    const prepareTypes = new Set(["memory", "disk", "velociraptor"]);
    const sources = directive.evidence_sources.filter((s) =>
      prepareTypes.has(s.type as string)
    );
    const limit = this.deps.prepareOnly && this.deps.prepareOnly.length > 0
      ? new Set(this.deps.prepareOnly)
      : null;

    // Map directive paths to EVD-NNN ids. The MCP server registers them in
    // manifest order (EVD-001..N). We reproduce that ordering here so the
    // orchestrator can address them by id.
    const evidence_ids = sources.map((_, i) => `EVD-${String(i + 1).padStart(3, "0")}`);

    for (let i = 0; i < sources.length; i++) {
      const id = evidence_ids[i];
      if (limit && !limit.has(id)) {
        await this.deps.auditLog.append("ic_decision", evidenceStoreId, 0, {
          note: `evidence prep skipped for ${id} (not in prepareOnly list)`,
        });
        continue;
      }

      await this.deps.auditLog.append("tool_request_submitted", evidenceStoreId, 0, {
        tool: "prepare_working_copy",
        on_behalf_of: evidenceStoreId,
        evidence_id: id,
      });

      // Routing: Evidence Store is permitted prepare_working_copy; the
      // orchestrator stands in as Tool Broker on execution (same pattern
      // as the branch tool dispatch).
      const auth = this.deps.router.authorizeBrokerSubmission(
        evidenceStoreId,
        "prepare_working_copy"
      );
      if (!auth.allow) {
        await this.deps.auditLog.append("mcp_call", TOOL_BROKER_ID, 0, {
          execution_id: `EXEC-PREP-${id}`,
          tool: "prepare_working_copy",
          on_behalf_of: evidenceStoreId,
          success: false,
          error: auth.reason,
        });
        continue;
      }

      const startedAt = Date.now();
      try {
        const res = await this.deps.mcp.callTool("prepare_working_copy", {
          evidence_id: id,
          custodian: evidenceStoreId,
          period: 0,
        });
        const parsed = res.parsed as Record<string, unknown> | null;
        const inBodyError =
          parsed && typeof parsed.error === "string" ? (parsed.error as string) : null;
        const success = !res.isError && !inBodyError;
        const data = (parsed?.data ?? {}) as Record<string, unknown>;

        await this.deps.auditLog.append("mcp_call", TOOL_BROKER_ID, 0, {
          execution_id: typeof data.custody_chain_id === "string" ? data.custody_chain_id : `EXEC-PREP-${id}`,
          tool: "prepare_working_copy",
          on_behalf_of: evidenceStoreId,
          success,
          duration_ms: Date.now() - startedAt,
          ...(success
            ? {
                custody_chain_id: data.custody_chain_id,
                original_sha256: data.original_sha256,
                working_copy_sha256: data.working_copy_sha256,
                hashes_match: data.hashes_match,
              }
            : { error: inBodyError ?? "unknown error" }),
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        await this.deps.auditLog.append("mcp_call", TOOL_BROKER_ID, 0, {
          execution_id: `EXEC-PREP-${id}`,
          tool: "prepare_working_copy",
          on_behalf_of: evidenceStoreId,
          success: false,
          error: msg,
        });
      }
    }
  }

  /** Selective activation: branches with no relevant evidence stand down.
   *  An explicit override (CLI --branches) takes precedence over the
   *  evidence-driven selection. */
  private selectBranches(directive: IncidentDirective): string[] {
    if (this.deps.branchesOverride && this.deps.branchesOverride.length > 0) {
      return [...this.deps.branchesOverride];
    }
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
