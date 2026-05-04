#!/usr/bin/env node
// CLI entry. Parse flags → load skills → load directive → run period loop.
//
// In --dry-run mode, no Anthropic API call is made. Routing, COP isolation,
// audit log, period state, and inter-skill messaging are all exercised.

import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdir, readFile, writeFile, copyFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";

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
import { runDocumentationUnit } from "./swarm.js";

/** Look for an Anthropic API key. Order: env var → ~/Desktop/api.txt →
 *  ANTHROPIC_API_KEY_FILE (path) → null. Trims whitespace. */
async function resolveApiKey(): Promise<string | null> {
  if (process.env.ANTHROPIC_API_KEY) return process.env.ANTHROPIC_API_KEY;
  if (process.env.ANTHROPIC_API_KEY_FILE && existsSync(process.env.ANTHROPIC_API_KEY_FILE)) {
    return (await readFile(process.env.ANTHROPIC_API_KEY_FILE, "utf8")).trim() || null;
  }
  const desktopFile = join(homedir(), "Desktop", "api.txt");
  if (existsSync(desktopFile)) {
    const v = (await readFile(desktopFile, "utf8")).trim();
    if (v) return v;
  }
  return null;
}

interface Args {
  directive: string;
  evidenceMount: string;
  caseDir: string;
  resumeFrom?: number;
  dryRun: boolean;
  skillsRoot?: string;
  mcpEntry?: string;
  /** Comma-separated EVD-NNN ids the Evidence Store should make working
   *  copies of. Bound to keep working-copy disk usage small for demo runs. */
  prepareOnly?: string[];
  /** Comma-separated branch skill IDs to activate, overriding evidence-driven
   *  selection (e.g. "operations/memory-branch"). Used to focus demo runs. */
  branches?: string[];
}

function parseArgs(argv: string[]): Args {
  const out: Partial<Args> = { dryRun: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.indexOf("=");
    const key = eq >= 0 ? a.slice(2, eq) : a.slice(2);
    const val = eq >= 0 ? a.slice(eq + 1) : argv[++i];
    switch (key) {
      case "directive": out.directive = val; break;
      case "evidence-mount": out.evidenceMount = val; break;
      case "case-dir": out.caseDir = val; break;
      case "resume-from": out.resumeFrom = Number(val); break;
      case "dry-run": out.dryRun = true; if (eq < 0) i--; break;
      case "skills-root": out.skillsRoot = val; break;
      case "mcp-entry": out.mcpEntry = val; break;
      case "prepare-only":
        out.prepareOnly = val.split(",").map((s) => s.trim()).filter(Boolean);
        break;
      case "branches":
        out.branches = val.split(",").map((s) => s.trim()).filter(Boolean);
        break;
      case "help": printUsage(); process.exit(0);
      default: throw new Error(`Unknown flag --${key}`);
    }
  }
  if (!out.directive) throw new Error("missing --directive");
  if (!out.evidenceMount) throw new Error("missing --evidence-mount");
  if (!out.caseDir) throw new Error("missing --case-dir");
  return out as Args;
}

function printUsage(): void {
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
  --prepare-only=<ids>        Comma-separated EVD-NNN ids the Evidence Store
                              should make working copies of. Defaults to all.
                              Use this to bound demo disk usage.
  --help                      Show this message

Hard cap: ${MAX_PERIODS} operational periods per case (CLAUDE.md invariant).`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv);
  const here = dirname(fileURLToPath(import.meta.url));
  // here = orchestrator/dist/src ; project root is three levels up.
  const projectRoot = resolve(here, "..", "..", "..");

  const skillsRoot = args.skillsRoot ?? resolve(projectRoot, "skills");
  const mcpEntry =
    args.mcpEntry ?? resolve(projectRoot, "mcp-server", "dist", "src", "index.js");

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
  console.log(
    `[orchestrator] directive incident=${directive.incident_id} case=${directive.case_id} ` +
      `evidence=${directive.evidence_sources.length} priority=${directive.priority}`
  );

  let mcp: McpClient | null = null;
  let runner: AnthropicSubagentRunner | null = null;
  if (!args.dryRun) {
    const apiKey = await resolveApiKey();
    if (!apiKey) {
      throw new Error(
        "Anthropic API key not found. Set ANTHROPIC_API_KEY, point ANTHROPIC_API_KEY_FILE at a file, or place the key in ~/Desktop/api.txt. Re-run with --dry-run to exercise routing only."
      );
    }
    process.env.ANTHROPIC_API_KEY = apiKey; // surface to any downstream lib
    console.log(`[orchestrator] api_key=${apiKey.slice(0, 12)}… (${apiKey.length} chars)`);
    mcp = new McpClient({
      serverEntry: mcpEntry,
      evidenceMount: args.evidenceMount,
      workingDir: process.env.WORKING_DIR ?? "/working",
    });
    await mcp.start();
    runner = new AnthropicSubagentRunner(apiKey);
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
      prepareOnly: args.prepareOnly,
      branchesOverride: args.branches,
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
      total_story_findings: result.storyFindings.length,
    };
    await writeFile(join(args.caseDir, "summary.json"), JSON.stringify(summary, null, 2));

    // Story-view artifacts. Live runs invoke Documentation Unit for the
    // narrative final_report; dry-run produces a minimal stub so the JSON
    // contract still validates and the front-end can be exercised.
    if (!args.dryRun && runner) {
      console.log("[orchestrator] invoking Documentation Unit for final_report.json");
      const finalReport = await runDocumentationUnit(
        directive,
        result.periods,
        result.finalCop,
        result.storyFindings,
        {
          skills: registry,
          router,
          copStore,
          auditLog,
          messages,
          safety,
          mcp: mcp!,
          runner,
        }
      );
      await writeFile(join(args.caseDir, "final_report.json"), JSON.stringify(finalReport, null, 2));
      await writeFile(
        join(args.caseDir, "findings.json"),
        JSON.stringify({ findings: result.storyFindings }, null, 2)
      );
    } else {
      // Dry-run stub so the story-view contract is honored.
      const stub = {
        case_id: directive.case_id,
        generated_at: new Date().toISOString(),
        incident_summary: `[dry-run] No LLM calls were made. Selective activation chose ${
          result.periods[0]?.activeBranches.join(", ") ?? "(none)"
        }.`,
        primary_hosts: [...new Set(directive.evidence_sources.map((e) => e.host).filter(Boolean))],
        attack_narrative: [],
        iocs: { file_hashes: [], ip_addresses: [], domains: [], registry_keys: [], file_paths: [] },
        operational_periods_summary: result.periods.map((p) => ({
          period: p.period,
          objectives: [],
          active_branches: p.activeBranches.map((b) =>
            b.replace(/^operations\//, "").replace(/-branch$/, "")
          ),
          key_findings_added: [],
          ic_reasoning: p.icReasoning,
        })),
      };
      await writeFile(join(args.caseDir, "final_report.json"), JSON.stringify(stub, null, 2));
      await writeFile(join(args.caseDir, "findings.json"), JSON.stringify({ findings: [] }, null, 2));
    }

    // Top-level cop.json copy of the latest period COP for the story view.
    const latestCopPath = join(
      args.caseDir,
      `cop_period_${result.periods[result.periods.length - 1]?.period ?? 1}.json`
    );
    if (existsSync(latestCopPath)) {
      await copyFile(latestCopPath, join(args.caseDir, "cop.json"));
    }

    console.log("[orchestrator] run complete:");
    console.log(JSON.stringify(summary, null, 2));
  } finally {
    if (mcp) await mcp.stop();
  }
}

main().catch((err) => {
  console.error("FATAL:", err instanceof Error ? err.stack ?? err.message : err);
  process.exit(1);
});
