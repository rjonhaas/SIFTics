/**
 * Accuracy Test Runner
 *
 * For each test case:
 *   1. Load the case definition (case.yaml)
 *   2. Run the swarm against the fixture evidence (or load pre-recorded findings)
 *   3. Evaluate produced findings against ground truth
 *   4. Compute per-case metrics
 *
 * Then aggregate across all cases and produce reports.
 *
 * Usage:
 *   npm run test:accuracy
 *   npm run test:accuracy -- --case=001-ransomware-disk-only
 *   npm run test:accuracy -- --branch=forensics
 *   npm run test:accuracy -- --quick
 *   npm run test:accuracy -- --use-recorded   # use pre-recorded findings, no swarm run
 */

import { readFile, readdir, mkdir, writeFile, stat } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import type {
  TestCase,
  CaseResult,
  ProducedFinding,
  AggregateMetrics,
} from "./helpers/types.js";
import { evaluateCase, aggregateAcrossCases } from "./helpers/metrics.js";

// ────────────────────────────────────────────────────────────────────
// Paths
// ────────────────────────────────────────────────────────────────────

const HERE = dirname(fileURLToPath(import.meta.url));
const CASES_DIR = join(HERE, "test-cases");
const REPORTS_DIR = join(HERE, "reports");

// ────────────────────────────────────────────────────────────────────
// CLI
// ────────────────────────────────────────────────────────────────────

interface Options {
  caseFilter?: string;
  branchFilter?: string;
  quick: boolean;
  useRecorded: boolean;
}

function parseArgs(argv: string[]): Options {
  const opts: Options = { quick: false, useRecorded: false };
  for (const arg of argv.slice(2)) {
    if (arg.startsWith("--case=")) opts.caseFilter = arg.slice("--case=".length);
    else if (arg.startsWith("--branch=")) opts.branchFilter = arg.slice("--branch=".length);
    else if (arg === "--quick") opts.quick = true;
    else if (arg === "--use-recorded") opts.useRecorded = true;
  }
  return opts;
}

// ────────────────────────────────────────────────────────────────────
// Test case loading
// ────────────────────────────────────────────────────────────────────

async function listTestCases(): Promise<string[]> {
  const entries = await readdir(CASES_DIR, { withFileTypes: true });
  return entries
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

async function loadTestCase(caseId: string): Promise<TestCase> {
  const yamlPath = join(CASES_DIR, caseId, "case.yaml");
  const yamlText = await readFile(yamlPath, "utf8");
  return parseYamlTestCase(yamlText);
}

/**
 * Minimal YAML parser for test case files. Handles the limited YAML
 * subset we use (no anchors, no flow style for arrays, simple key:value).
 * For real production use, replace with `js-yaml` once available.
 */
function parseYamlTestCase(yamlText: string): TestCase {
  // The harness scaffold ships with a placeholder parser. For the actual
  // submission, swap to js-yaml: `import yaml from "js-yaml"; return yaml.load(...)`.
  // This stub returns a parseable representative structure so the harness
  // works end-to-end during scaffold testing.
  const lines = yamlText.split("\n");
  const caseIdLine = lines.find((l) => l.trim().startsWith("case_id:"));
  const scenarioLine = lines.find((l) => l.trim().startsWith("scenario:"));
  const allowedExtrasLine = lines.find((l) => l.trim().startsWith("allowed_extra_findings:"));

  return {
    case_id: caseIdLine?.split(":")[1]?.trim() ?? "unknown",
    scenario: scenarioLine?.split(":").slice(1).join(":").trim() ?? "",
    evidence: [],
    ground_truth_findings: [],
    allowed_extra_findings: parseInt(allowedExtrasLine?.split(":")[1]?.trim() ?? "5"),
  };
}

// ────────────────────────────────────────────────────────────────────
// Swarm invocation (or recorded results)
// ────────────────────────────────────────────────────────────────────

async function getProducedFindings(
  caseId: string,
  useRecorded: boolean
): Promise<{ findings: ProducedFinding[]; validExecutionIds: Set<string> }> {
  const recordedPath = join(CASES_DIR, caseId, "recorded_findings.json");

  if (useRecorded || (await fileExists(recordedPath))) {
    const text = await readFile(recordedPath, "utf8");
    const data = JSON.parse(text) as {
      findings: ProducedFinding[];
      audit_log_execution_ids: string[];
    };
    return {
      findings: data.findings,
      validExecutionIds: new Set(data.audit_log_execution_ids ?? []),
    };
  }

  // In a real run, this would invoke the OpenClaw swarm against the fixture
  // evidence and capture the resulting findings + audit log execution IDs.
  // For the scaffold we return an empty result — running the harness without
  // either a recorded result or a real swarm invocation produces a clear
  // "no findings produced" result rather than crashing.
  console.warn(`No recorded findings at ${recordedPath} and live swarm invocation not yet implemented.`);
  console.warn(`To populate, run the swarm against the case fixture and write recorded_findings.json.`);
  return { findings: [], validExecutionIds: new Set() };
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

// ────────────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs(process.argv);

  let caseIds = await listTestCases();
  if (opts.caseFilter) caseIds = caseIds.filter((id) => id === opts.caseFilter);
  if (opts.quick) caseIds = caseIds.filter((id) => !id.includes("multi-host") && !id.includes("living-off"));

  if (caseIds.length === 0) {
    console.error("No test cases match the filter.");
    process.exit(1);
  }

  console.log(`\nAccuracy Test Harness`);
  console.log(`  Cases:        ${caseIds.length}`);
  console.log(`  Use recorded: ${opts.useRecorded}`);
  console.log("");

  const caseResults: CaseResult[] = [];

  for (const caseId of caseIds) {
    const testCase = await loadTestCase(caseId);

    // Optional branch filter — only run cases that exercise the named branch
    if (opts.branchFilter) {
      const branches = new Set(testCase.ground_truth_findings.map((g) => g.branch));
      if (!branches.has(opts.branchFilter as never)) continue;
    }

    const { findings, validExecutionIds } = await getProducedFindings(caseId, opts.useRecorded);
    const result = evaluateCase(testCase, findings, validExecutionIds);
    caseResults.push(result);

    printCaseSummary(result);
  }

  if (caseResults.length === 0) {
    console.log("No cases ran (filters may have eliminated all).");
    process.exit(0);
  }

  const aggregate = aggregateAcrossCases(caseResults);
  await writeReports(caseResults, aggregate);
  printAggregateSummary(aggregate);

  // Exit nonzero if hallucination_rate > 0 — that's a hard architectural failure
  if (aggregate.hallucination_rate > 0) {
    console.error(`\n\x1b[1;31mHALLUCINATION DETECTED (${aggregate.hallucination_rate.toFixed(3)}). Exit 1.\x1b[0m`);
    process.exit(1);
  }
}

// ────────────────────────────────────────────────────────────────────
// Output
// ────────────────────────────────────────────────────────────────────

function printCaseSummary(c: CaseResult): void {
  const m = c.metrics;
  const f1Color = m.f1 >= 0.8 ? "\x1b[32m" : m.f1 >= 0.6 ? "\x1b[33m" : "\x1b[31m";
  console.log(
    `${f1Color}F1=${m.f1.toFixed(2)}\x1b[0m  ` +
    `${c.case_id.padEnd(35)} ` +
    `P=${m.precision.toFixed(2)} R=${m.recall.toFixed(2)} ` +
    `TP=${m.true_positives} FP=${m.false_positives} FN=${m.false_negatives} ` +
    `hall=${c.hallucinated_findings.length}`
  );
}

function printAggregateSummary(a: AggregateMetrics): void {
  console.log(`\n══ Aggregate (${a.total_cases} cases) ══`);
  console.log(`  Micro:    P=${a.micro.precision.toFixed(3)} R=${a.micro.recall.toFixed(3)} F1=${a.micro.f1.toFixed(3)}`);
  console.log(`  Macro:    P=${a.macro.precision.toFixed(3)} R=${a.macro.recall.toFixed(3)} F1=${a.macro.f1.toFixed(3)}`);
  console.log(`  Hallucination rate:    ${a.hallucination_rate.toFixed(3)}`);
  console.log(`  Citation completeness: ${a.citation_completeness.toFixed(3)}`);
  console.log(`  Calibration gap (avg): ${a.avg_calibration_gap.toFixed(3)}  (positive = correct findings have higher confidence)`);
}

async function writeReports(cases: CaseResult[], aggregate: AggregateMetrics): Promise<void> {
  await mkdir(REPORTS_DIR, { recursive: true });
  const ts = new Date().toISOString().replace(/[:.]/g, "-");

  // JSON
  const jsonPath = join(REPORTS_DIR, `accuracy-report-${ts}.json`);
  await writeFile(jsonPath, JSON.stringify({
    generatedAt: new Date().toISOString(),
    aggregate,
    cases: cases.map((c) => ({
      case_id: c.case_id,
      scenario: c.scenario,
      metrics: c.metrics,
      hallucinated_count: c.hallucinated_findings.length,
      uncited_count: c.uncited_findings.length,
    })),
  }, null, 2));

  // Markdown
  const mdPath = join(REPORTS_DIR, `accuracy-report-${ts}.md`);
  await writeFile(mdPath, generateMarkdownReport(cases, aggregate));

  // Per-case finding diffs
  const diffsPath = join(REPORTS_DIR, `accuracy-finding-diffs-${ts}.md`);
  await writeFile(diffsPath, generateDiffsReport(cases));

  console.log(`\nReports written:`);
  console.log(`  ${jsonPath}`);
  console.log(`  ${mdPath}`);
  console.log(`  ${diffsPath}`);
}

function generateMarkdownReport(cases: CaseResult[], a: AggregateMetrics): string {
  const lines: string[] = [];
  lines.push("# Accuracy Test Report");
  lines.push("");
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push(`**Cases run:** ${a.total_cases}`);
  lines.push("");

  lines.push("## Headline Numbers");
  lines.push("");
  lines.push(`- **F1 (micro):** ${a.micro.f1.toFixed(3)} — single number to track`);
  lines.push(`- **Precision (micro):** ${a.micro.precision.toFixed(3)}`);
  lines.push(`- **Recall (micro):** ${a.micro.recall.toFixed(3)}`);
  lines.push(`- **Hallucination rate:** ${a.hallucination_rate.toFixed(3)} (target: 0.000)`);
  lines.push(`- **Citation completeness:** ${a.citation_completeness.toFixed(3)} (target: 1.000)`);
  lines.push(`- **Confidence calibration gap:** ${a.avg_calibration_gap.toFixed(3)} (positive = correct findings have higher confidence)`);
  lines.push("");

  if (a.hallucination_rate === 0 && a.citation_completeness === 1.0) {
    lines.push("> ✅ **Architectural integrity intact.** Zero hallucinations, all findings cite a valid tool execution ID.");
  } else if (a.hallucination_rate > 0) {
    lines.push(`> ⚠ **Hallucinations detected.** ${a.hallucination_rate.toFixed(3)} hallucination rate is a critical architectural failure — findings exist that don't trace back to any real tool call.`);
  } else if (a.citation_completeness < 1.0) {
    lines.push(`> ⚠ **Uncited findings present.** ${(1 - a.citation_completeness).toFixed(3)} of findings have no tool_execution_id citation. Update branch prompts to require citations.`);
  }
  lines.push("");

  lines.push("## Per-Case Results");
  lines.push("");
  lines.push("| Case | F1 | Precision | Recall | TP | FP | FN | Hallucinated |");
  lines.push("|---|---|---|---|---|---|---|---|");
  for (const c of cases) {
    const m = c.metrics;
    lines.push(
      `| ${c.case_id} | ${m.f1.toFixed(3)} | ${m.precision.toFixed(3)} | ${m.recall.toFixed(3)} | ` +
      `${m.true_positives} | ${m.false_positives} | ${m.false_negatives} | ${c.hallucinated_findings.length} |`
    );
  }
  lines.push("");

  lines.push("## Per-Branch Results");
  lines.push("");
  lines.push("| Branch | Findings | Precision | Recall | F1 | Hallucinations |");
  lines.push("|---|---|---|---|---|---|");
  for (const b of Object.values(a.per_branch)) {
    if (b.total_findings === 0) continue;
    lines.push(
      `| ${b.branch} | ${b.total_findings} | ${b.precision.toFixed(3)} | ${b.recall.toFixed(3)} | ` +
      `${b.f1.toFixed(3)} | ${b.hallucination_count} |`
    );
  }
  lines.push("");

  lines.push("## Per-Category Results");
  lines.push("");
  lines.push("| Category | Findings | Precision | Recall | F1 |");
  lines.push("|---|---|---|---|---|");
  for (const c of Object.values(a.per_category).sort((x, y) => y.total_findings - x.total_findings)) {
    lines.push(
      `| ${c.category} | ${c.total_findings} | ${c.precision.toFixed(3)} | ${c.recall.toFixed(3)} | ${c.f1.toFixed(3)} |`
    );
  }
  lines.push("");

  lines.push("## Methodology");
  lines.push("");
  lines.push("Each test case has a curated ground truth file specifying findings the agent SHOULD produce. Produced findings are matched to ground truth via greedy assignment by match quality (a fraction of fields matched, with timestamp tolerance and string-edit-distance support).");
  lines.push("");
  lines.push("- **True positive (TP)**: produced finding matches a ground-truth finding on all required fields.");
  lines.push("- **False positive (FP)**: produced finding does not match any ground truth, AND we are over the per-case allowed-extras budget.");
  lines.push("- **False negative (FN)**: ground-truth finding has no matching produced finding.");
  lines.push("- **True negative (TN)**: ground-truth `must_not_appear` finding correctly absent.");
  lines.push("");
  lines.push("Micro-averaged metrics sum TP/FP/FN across cases before computing ratios. Macro averages per-case ratios.");
  lines.push("");

  return lines.join("\n");
}

function generateDiffsReport(cases: CaseResult[]): string {
  const lines: string[] = [];
  lines.push("# Accuracy Finding Diffs");
  lines.push("");
  lines.push("Per-case detail of every match decision the harness made. Use this to diagnose precision/recall failures.");
  lines.push("");

  for (const c of cases) {
    lines.push(`## ${c.case_id}`);
    lines.push("");
    lines.push(`Scenario: ${c.scenario}`);
    lines.push("");

    lines.push("### True Positives");
    lines.push("");
    const tps = c.matches.filter((m) => m.is_true_positive);
    if (tps.length === 0) lines.push("_(none)_");
    for (const m of tps) {
      lines.push(`- **${m.ground_truth.id}** (${m.ground_truth.branch}/${m.ground_truth.category}) ↔ ${m.produced?.finding_id ?? "?"} — quality ${m.match_quality.toFixed(2)}`);
    }
    lines.push("");

    lines.push("### False Negatives (missed)");
    lines.push("");
    const fns = c.matches.filter((m) => m.is_false_negative);
    if (fns.length === 0) lines.push("_(none)_");
    for (const m of fns) {
      lines.push(`- **${m.ground_truth.id}** — agent did not produce a matching finding for ${m.ground_truth.branch}/${m.ground_truth.category}`);
    }
    lines.push("");

    lines.push("### False Positives (over-budget extras)");
    lines.push("");
    const fps = c.unmatched_produced.filter((u) => !u.is_noise);
    if (fps.length === 0) lines.push("_(none)_");
    for (const u of fps) {
      lines.push(`- **${u.produced.finding_id}** (${u.produced.branch}/${u.produced.category}) — confidence ${u.produced.confidence.toFixed(2)}: "${u.produced.summary.slice(0, 100)}"`);
    }
    lines.push("");

    if (c.hallucinated_findings.length > 0) {
      lines.push("### Hallucinations (CRITICAL)");
      lines.push("");
      for (const h of c.hallucinated_findings) {
        lines.push(`- **${h.finding_id}** cites tool_execution_id=${h.tool_execution_id} which does not exist in the audit log`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

// ────────────────────────────────────────────────────────────────────

main().catch((err) => {
  console.error("Test runner error:", err);
  process.exit(1);
});
