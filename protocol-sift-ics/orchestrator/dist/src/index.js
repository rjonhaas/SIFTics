#!/usr/bin/env node
// CLI entry. Parse flags → load skills → load directive → run period loop.
//
// In --dry-run mode, no Anthropic API call is made. Routing, COP isolation,
// audit log, period state, and inter-skill messaging are all exercised.
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdir, writeFile } from "node:fs/promises";
import { loadSkills, SkillRegistry } from "./skill_loader.js";
import { Router } from "./routing.js";
import { CopStore } from "./persistence/cop_store.js";
import { PeriodStateStore } from "./persistence/period_state.js";
import { AuditLog } from "./persistence/audit_log.js";
import { InterSkillMessageLog } from "./persistence/inter_skill_messages.js";
import { SafetyMirror, passThroughEvaluator } from "./safety/safety_mirror.js";
import { loadDirective } from "./directive_loader.js";
import { OperationalPeriodLoop, MAX_PERIODS } from "./operational_period.js";
import { AnthropicSubagentRunner } from "./subagent.js";
import { McpClient } from "./mcp_client.js";
function parseArgs(argv) {
    const out = { dryRun: false };
    for (let i = 2; i < argv.length; i++) {
        const a = argv[i];
        const eq = a.indexOf("=");
        const key = eq >= 0 ? a.slice(2, eq) : a.slice(2);
        const val = eq >= 0 ? a.slice(eq + 1) : argv[++i];
        switch (key) {
            case "directive":
                out.directive = val;
                break;
            case "evidence-mount":
                out.evidenceMount = val;
                break;
            case "case-dir":
                out.caseDir = val;
                break;
            case "resume-from":
                out.resumeFrom = Number(val);
                break;
            case "dry-run":
                out.dryRun = true;
                if (eq < 0)
                    i--;
                break;
            case "skills-root":
                out.skillsRoot = val;
                break;
            case "mcp-entry":
                out.mcpEntry = val;
                break;
            case "help":
                printUsage();
                process.exit(0);
            default: throw new Error(`Unknown flag --${key}`);
        }
    }
    if (!out.directive)
        throw new Error("missing --directive");
    if (!out.evidenceMount)
        throw new Error("missing --evidence-mount");
    if (!out.caseDir)
        throw new Error("missing --case-dir");
    return out;
}
function printUsage() {
    console.log(`Usage: protocol-sift --directive=<path> --evidence-mount=<dir> --case-dir=<dir> [options]

Required:
  --directive=<path>          Incident directive YAML or JSON
  --evidence-mount=<dir>      Read-only mount with evidence + manifest.json
  --case-dir=<dir>            Where COP, period state, audit log are written

Options:
  --resume-from=<period>      Resume from a given operational period
  --dry-run                   Run routing + persistence without LLM calls
  --skills-root=<dir>         Override path to the skills/ directory
  --mcp-entry=<path>          Override path to MCP server dist entry
  --help                      Show this message

Hard cap: ${MAX_PERIODS} operational periods per case (CLAUDE.md invariant).`);
}
async function main() {
    const args = parseArgs(process.argv);
    const here = dirname(fileURLToPath(import.meta.url));
    // here = orchestrator/dist/src ; project root is three levels up.
    const projectRoot = resolve(here, "..", "..", "..");
    const skillsRoot = args.skillsRoot ?? resolve(projectRoot, "skills");
    const mcpEntry = args.mcpEntry ?? resolve(projectRoot, "mcp-server", "dist", "src", "index.js");
    console.log(`[orchestrator] skills=${skillsRoot}`);
    console.log(`[orchestrator] mcp_entry=${mcpEntry}`);
    console.log(`[orchestrator] case_dir=${args.caseDir}`);
    console.log(`[orchestrator] dry_run=${args.dryRun}`);
    await mkdir(args.caseDir, { recursive: true });
    const skills = await loadSkills(skillsRoot);
    console.log(`[orchestrator] loaded ${skills.length} skills`);
    const registry = new SkillRegistry(skills);
    const router = new Router(registry);
    const auditLog = await AuditLog.open(join(args.caseDir, "audit_log.jsonl"));
    const periodStore = new PeriodStateStore(args.caseDir);
    const copStore = new CopStore(args.caseDir, router);
    const messages = await InterSkillMessageLog.open(join(args.caseDir, "inter_skill_messages.jsonl"));
    const safety = new SafetyMirror({ evaluator: passThroughEvaluator, auditLog });
    const directive = await loadDirective(args.directive);
    console.log(`[orchestrator] directive incident=${directive.incident_id} case=${directive.case_id} ` +
        `evidence=${directive.evidence_sources.length} priority=${directive.priority}`);
    let mcp = null;
    let runner = null;
    if (!args.dryRun) {
        if (!process.env.ANTHROPIC_API_KEY) {
            throw new Error("ANTHROPIC_API_KEY is required for live runs. Re-run with --dry-run to exercise routing only.");
        }
        mcp = new McpClient({
            serverEntry: mcpEntry,
            evidenceMount: args.evidenceMount,
            workingDir: process.env.WORKING_DIR ?? "/working",
        });
        await mcp.start();
        runner = new AnthropicSubagentRunner();
    }
    try {
        const loop = new OperationalPeriodLoop({
            skills: registry,
            router,
            copStore,
            periodStore,
            auditLog,
            messages,
            safety,
            mcp,
            runner,
        });
        const result = await loop.run(directive, args.dryRun);
        const summary = {
            incident_id: directive.incident_id,
            case_id: directive.case_id,
            periods_run: result.periods.length,
            close_reason: result.closeReason,
            active_branches_per_period: result.periods.map((p) => p.activeBranches),
            stand_down_per_period: result.periods.map((p) => p.standDownBranches),
            final_cop_findings: result.finalCop?.findings.length ?? 0,
        };
        await writeFile(join(args.caseDir, "summary.json"), JSON.stringify(summary, null, 2));
        console.log("[orchestrator] run complete:");
        console.log(JSON.stringify(summary, null, 2));
    }
    finally {
        if (mcp)
            await mcp.stop();
    }
}
main().catch((err) => {
    console.error("FATAL:", err instanceof Error ? err.stack ?? err.message : err);
    process.exit(1);
});
//# sourceMappingURL=index.js.map