/**
 * Metrics computation for the accuracy harness.
 *
 * Produces both per-case metrics and aggregate metrics across cases.
 * Includes DFIR-specific metrics (hallucination rate, citation completeness,
 * confidence calibration) in addition to standard classification metrics.
 */

import type {
  TestCase,
  ProducedFinding,
  FindingMatch,
  CaseResult,
  CaseMetrics,
  AggregateMetrics,
  Branch,
  BranchMetrics,
  CategoryMetrics,
} from "./types.js";
import { assignFindings } from "./matcher.js";

// ────────────────────────────────────────────────────────────────────
// Per-case metrics
// ────────────────────────────────────────────────────────────────────

export function evaluateCase(
  testCase: TestCase,
  produced: ProducedFinding[],
  validExecutionIds: Set<string>
): CaseResult {
  const { matches, unmatched_produced } = assignFindings(
    testCase.ground_truth_findings,
    produced
  );

  // Hallucination check: findings whose tool_execution_id is not in the audit log
  const hallucinated = produced.filter(
    (p) => p.tool_execution_id && !validExecutionIds.has(p.tool_execution_id)
  );

  // Citation check: findings missing tool_execution_id entirely
  const uncited = produced.filter((p) => !p.tool_execution_id);

  // Categorize unmatched produced findings as noise vs. false positive
  const allowedExtras = testCase.allowed_extra_findings;
  const overBudget = Math.max(0, unmatched_produced.length - allowedExtras);
  const unmatchedClassified = unmatched_produced.map((p, i) => ({
    produced: p,
    is_noise: i < allowedExtras,
  }));

  // Mark unmatched-but-over-budget findings as false positives in the metrics
  const tp = matches.filter((m) => m.is_true_positive).length;
  const tn = matches.filter((m) => m.is_true_negative).length;
  // FP = (over-budget extras) + (negative cases where a finding appeared)
  const fp = overBudget + matches.filter((m) => m.is_false_positive).length;
  const fn = matches.filter((m) => m.is_false_negative).length;

  const precision = tp + fp > 0 ? tp / (tp + fp) : 1.0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 1.0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  // Calibration: average confidence on correct vs. incorrect findings
  const correctConfs = matches
    .filter((m) => m.is_true_positive && m.produced)
    .map((m) => m.produced!.confidence);
  const incorrectConfs = [
    ...matches.filter((m) => m.produced && !m.is_true_positive).map((m) => m.produced!.confidence),
    ...unmatchedClassified.filter((u) => !u.is_noise).map((u) => u.produced.confidence),
  ];

  const avgConfCorrect = mean(correctConfs);
  const avgConfIncorrect = mean(incorrectConfs);
  // Positive gap = good calibration (correct > incorrect confidence)
  const calibrationGap = avgConfCorrect - avgConfIncorrect;

  const metrics: CaseMetrics = {
    total_ground_truth: testCase.ground_truth_findings.length,
    total_produced: produced.length,
    true_positives: tp,
    true_negatives: tn,
    false_positives: fp,
    false_negatives: fn,
    precision,
    recall,
    f1,
    hallucination_rate: produced.length > 0 ? hallucinated.length / produced.length : 0,
    citation_completeness: produced.length > 0 ? (produced.length - uncited.length) / produced.length : 1.0,
    avg_confidence_when_correct: avgConfCorrect,
    avg_confidence_when_incorrect: avgConfIncorrect,
    calibration_gap: calibrationGap,
  };

  return {
    case_id: testCase.case_id,
    scenario: testCase.scenario,
    matches,
    unmatched_produced: unmatchedClassified,
    hallucinated_findings: hallucinated,
    uncited_findings: uncited,
    metrics,
  };
}

// ────────────────────────────────────────────────────────────────────
// Aggregate across cases
// ────────────────────────────────────────────────────────────────────

export function aggregateAcrossCases(cases: CaseResult[]): AggregateMetrics {
  // Sum confusion matrix entries across cases for micro averaging
  let tpSum = 0, fpSum = 0, fnSum = 0;
  let totalGt = 0, totalProd = 0, totalHallucinated = 0, totalUncited = 0;
  const calibrationGaps: number[] = [];

  for (const c of cases) {
    tpSum += c.metrics.true_positives;
    fpSum += c.metrics.false_positives;
    fnSum += c.metrics.false_negatives;
    totalGt += c.metrics.total_ground_truth;
    totalProd += c.metrics.total_produced;
    totalHallucinated += c.hallucinated_findings.length;
    totalUncited += c.uncited_findings.length;
    if (!isNaN(c.metrics.calibration_gap)) calibrationGaps.push(c.metrics.calibration_gap);
  }

  const microPrecision = tpSum + fpSum > 0 ? tpSum / (tpSum + fpSum) : 1.0;
  const microRecall = tpSum + fnSum > 0 ? tpSum / (tpSum + fnSum) : 1.0;
  const microF1 = microPrecision + microRecall > 0
    ? (2 * microPrecision * microRecall) / (microPrecision + microRecall)
    : 0;

  // Macro: average per-case metrics
  const macroPrecision = mean(cases.map((c) => c.metrics.precision));
  const macroRecall = mean(cases.map((c) => c.metrics.recall));
  const macroF1 = mean(cases.map((c) => c.metrics.f1));

  // Per-branch and per-category breakdowns
  const perBranch = computePerBranch(cases);
  const perCategory = computePerCategory(cases);

  return {
    total_cases: cases.length,
    total_findings_expected: totalGt,
    total_findings_produced: totalProd,
    micro: { precision: microPrecision, recall: microRecall, f1: microF1 },
    macro: { precision: macroPrecision, recall: macroRecall, f1: macroF1 },
    hallucination_rate: totalProd > 0 ? totalHallucinated / totalProd : 0,
    citation_completeness: totalProd > 0 ? (totalProd - totalUncited) / totalProd : 1.0,
    avg_calibration_gap: mean(calibrationGaps),
    per_branch: perBranch,
    per_category: perCategory,
  };
}

function computePerBranch(cases: CaseResult[]): Record<Branch, BranchMetrics> {
  const branches: Branch[] = ["triage", "forensics", "memory", "network", "malware"];
  const result: Record<string, BranchMetrics> = {};

  for (const branch of branches) {
    let tp = 0, fp = 0, fn = 0, total = 0, hall = 0;

    for (const c of cases) {
      for (const m of c.matches) {
        if (m.ground_truth.branch !== branch) continue;
        total++;
        if (m.is_true_positive) tp++;
        if (m.is_false_positive) fp++;
        if (m.is_false_negative) fn++;
      }
      for (const u of c.unmatched_produced) {
        if (u.produced.branch !== branch) continue;
        if (!u.is_noise) fp++;
      }
      for (const h of c.hallucinated_findings) {
        if (h.branch !== branch) continue;
        hall++;
      }
    }

    const precision = tp + fp > 0 ? tp / (tp + fp) : 1.0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 1.0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

    result[branch] = {
      branch,
      total_findings: total,
      precision,
      recall,
      f1,
      hallucination_count: hall,
    };
  }

  return result as Record<Branch, BranchMetrics>;
}

function computePerCategory(cases: CaseResult[]): Record<string, CategoryMetrics> {
  const result: Record<string, CategoryMetrics> = {};

  for (const c of cases) {
    for (const m of c.matches) {
      const cat = m.ground_truth.category;
      if (!result[cat]) {
        result[cat] = { category: cat, total_findings: 0, precision: 0, recall: 0, f1: 0 };
      }
      result[cat].total_findings++;
    }
  }

  // Compute precision/recall per category
  for (const cat of Object.keys(result)) {
    let tp = 0, fp = 0, fn = 0;
    for (const c of cases) {
      for (const m of c.matches) {
        if (m.ground_truth.category !== cat) continue;
        if (m.is_true_positive) tp++;
        if (m.is_false_positive) fp++;
        if (m.is_false_negative) fn++;
      }
      for (const u of c.unmatched_produced) {
        if (u.produced.category !== cat || u.is_noise) continue;
        fp++;
      }
    }
    const precision = tp + fp > 0 ? tp / (tp + fp) : 1.0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 1.0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    result[cat].precision = precision;
    result[cat].recall = recall;
    result[cat].f1 = f1;
  }

  return result;
}

function mean(xs: number[]): number {
  if (xs.length === 0) return 0;
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}
