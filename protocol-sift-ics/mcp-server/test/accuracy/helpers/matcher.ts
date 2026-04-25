/**
 * Finding matcher with tolerance support.
 *
 * Compares a single produced finding against a single ground-truth finding,
 * returning a match quality score (0.0–1.0) and per-field diffs. The harness
 * uses this to assign produced findings to ground-truth findings via
 * Hungarian-style greedy matching: highest-quality matches first, then
 * remaining ground truths become false negatives and remaining produced
 * become extras (noise or false positives depending on the case budget).
 */

import type { GroundTruthFinding, ProducedFinding, ToleranceSpec, FindingMatch } from "./types.js";

// ────────────────────────────────────────────────────────────────────
// Single-pair matcher
// ────────────────────────────────────────────────────────────────────

export function matchPair(gt: GroundTruthFinding, prod: ProducedFinding): FindingMatch {
  const fieldDiffs: FindingMatch["field_diffs"] = [];
  let requiredFieldsMatched = 0;
  let requiredFieldsTotal = 0;
  let toleranceFieldsMatched = 0;
  let toleranceFieldsTotal = 0;

  // Branch and category must match — otherwise this is not a candidate at all
  if (gt.branch !== prod.branch || gt.category !== prod.category) {
    return {
      ground_truth: gt,
      produced: prod,
      match_quality: 0,
      field_diffs: [
        { field: "branch", expected: gt.branch, actual: prod.branch, matched: gt.branch === prod.branch },
        { field: "category", expected: gt.category, actual: prod.category, matched: gt.category === prod.category },
      ],
      is_true_positive: false,
      is_true_negative: false,
      is_false_positive: false,
      is_false_negative: false,
    };
  }

  // Exact-match required fields
  for (const [field, expected] of Object.entries(gt.must_have)) {
    requiredFieldsTotal++;
    const actual = prod.fields[field];
    const matched = exactMatch(expected, actual);
    if (matched) requiredFieldsMatched++;
    fieldDiffs.push({ field, expected, actual, matched });
  }

  // Tolerance fields
  if (gt.must_have_within_tolerance) {
    for (const [field, spec] of Object.entries(gt.must_have_within_tolerance)) {
      toleranceFieldsTotal++;
      const actual = prod.fields[field];
      const result = toleranceMatch(spec, actual);
      if (result.matched) toleranceFieldsMatched++;
      fieldDiffs.push({
        field,
        expected: spec.target,
        actual,
        matched: result.matched,
        note: result.note,
      });
    }
  }

  // Confidence floor check
  let confidenceOk = true;
  if (gt.confidence_floor !== undefined) {
    confidenceOk = prod.confidence >= gt.confidence_floor;
    fieldDiffs.push({
      field: "confidence",
      expected: `>= ${gt.confidence_floor}`,
      actual: prod.confidence,
      matched: confidenceOk,
      note: confidenceOk ? undefined : "below confidence_floor",
    });
  }

  // Match quality is the weighted fraction of fields that matched
  const totalFields = requiredFieldsTotal + toleranceFieldsTotal + (gt.confidence_floor !== undefined ? 1 : 0);
  const matchedFields = requiredFieldsMatched + toleranceFieldsMatched + (confidenceOk ? 1 : 0);
  const matchQuality = totalFields > 0 ? matchedFields / totalFields : 0;

  // True positive: ALL required fields match and confidence floor met
  const isTruePositive =
    requiredFieldsMatched === requiredFieldsTotal &&
    toleranceFieldsMatched === toleranceFieldsTotal &&
    confidenceOk;

  return {
    ground_truth: gt,
    produced: prod,
    match_quality: matchQuality,
    field_diffs: fieldDiffs,
    is_true_positive: isTruePositive,
    is_true_negative: false,
    is_false_positive: false,
    is_false_negative: false,
  };
}

// ────────────────────────────────────────────────────────────────────
// Field-level matchers
// ────────────────────────────────────────────────────────────────────

function exactMatch(expected: unknown, actual: unknown): boolean {
  if (expected === undefined || actual === undefined) return false;
  if (typeof expected === "string" && typeof actual === "string") {
    // Case-insensitive for paths and identifiers (Windows is case-insensitive)
    return expected.toLowerCase() === actual.toLowerCase();
  }
  return expected === actual;
}

function toleranceMatch(spec: ToleranceSpec, actual: unknown): { matched: boolean; note?: string } {
  if (actual === undefined || actual === null) {
    return { matched: false, note: "missing" };
  }

  // Timestamp tolerance
  if ("window_seconds" in spec && typeof spec.target === "string") {
    if (typeof actual !== "string") return { matched: false, note: "expected timestamp string" };
    const expectedMs = Date.parse(spec.target);
    const actualMs = Date.parse(actual);
    if (isNaN(expectedMs) || isNaN(actualMs)) {
      return { matched: false, note: "unparseable timestamp" };
    }
    const diffSec = Math.abs(actualMs - expectedMs) / 1000;
    return {
      matched: diffSec <= spec.window_seconds,
      note: `Δ ${diffSec.toFixed(1)}s (window: ±${spec.window_seconds}s)`,
    };
  }

  // Numeric relative-error tolerance
  if ("relative_error" in spec && typeof spec.target === "number") {
    if (typeof actual !== "number") return { matched: false, note: "expected number" };
    const error = Math.abs(actual - spec.target) / Math.max(Math.abs(spec.target), 1);
    return {
      matched: error <= spec.relative_error,
      note: `relative error ${(error * 100).toFixed(1)}%`,
    };
  }

  // String edit distance tolerance
  if ("edit_distance" in spec && typeof spec.target === "string") {
    if (typeof actual !== "string") return { matched: false, note: "expected string" };
    const dist = levenshtein(spec.target.toLowerCase(), actual.toLowerCase());
    return {
      matched: dist <= spec.edit_distance,
      note: `edit distance ${dist}`,
    };
  }

  return { matched: false, note: "unknown tolerance spec" };
}

function levenshtein(a: string, b: string): number {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const dp: number[][] = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));

  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }

  return dp[a.length][b.length];
}

// ────────────────────────────────────────────────────────────────────
// Greedy assignment
// ────────────────────────────────────────────────────────────────────

/**
 * Greedily assigns produced findings to ground-truth findings by match quality.
 * Returns matches (with possibly null produced for FNs), unmatched produced
 * findings, and a summary.
 */
export function assignFindings(
  groundTruth: GroundTruthFinding[],
  produced: ProducedFinding[]
): {
  matches: FindingMatch[];
  unmatched_produced: ProducedFinding[];
} {
  // Compute pairwise matches for all candidate pairs
  type Candidate = { gtIdx: number; prodIdx: number; match: FindingMatch };
  const candidates: Candidate[] = [];

  for (let i = 0; i < groundTruth.length; i++) {
    const gt = groundTruth[i];
    if (gt.must_not_appear) continue;  // negative cases handled separately

    for (let j = 0; j < produced.length; j++) {
      const m = matchPair(gt, produced[j]);
      if (m.match_quality > 0) {
        candidates.push({ gtIdx: i, prodIdx: j, match: m });
      }
    }
  }

  // Sort by quality desc; assign greedily without reusing either side
  candidates.sort((a, b) => b.match.match_quality - a.match.match_quality);

  const usedGt = new Set<number>();
  const usedProd = new Set<number>();
  const matches: FindingMatch[] = [];

  for (const c of candidates) {
    if (usedGt.has(c.gtIdx) || usedProd.has(c.prodIdx)) continue;
    matches.push(c.match);
    usedGt.add(c.gtIdx);
    usedProd.add(c.prodIdx);
  }

  // False negatives: ground truths that were not assigned
  for (let i = 0; i < groundTruth.length; i++) {
    const gt = groundTruth[i];
    if (gt.must_not_appear) {
      // Negative case: check none of the produced findings would have matched
      const wouldMatch = produced.some((p) => p.branch === gt.branch && p.category === gt.category);
      matches.push({
        ground_truth: gt,
        produced: null,
        match_quality: 0,
        field_diffs: [],
        is_true_positive: false,
        is_true_negative: !wouldMatch,
        is_false_positive: wouldMatch,
        is_false_negative: false,
      });
    } else if (!usedGt.has(i)) {
      matches.push({
        ground_truth: gt,
        produced: null,
        match_quality: 0,
        field_diffs: [],
        is_true_positive: false,
        is_true_negative: false,
        is_false_positive: false,
        is_false_negative: true,
      });
    }
  }

  // Unmatched produced findings (extras — possibly noise, possibly FP)
  const unmatchedProduced: ProducedFinding[] = [];
  for (let j = 0; j < produced.length; j++) {
    if (!usedProd.has(j)) unmatchedProduced.push(produced[j]);
  }

  return { matches, unmatched_produced: unmatchedProduced };
}
