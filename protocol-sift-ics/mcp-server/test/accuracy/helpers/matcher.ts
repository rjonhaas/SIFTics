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

  // Required fields — supports exact-match plus operator suffixes
  // (_in, _contains, _present, _in_cidrs). The base field name is the key
  // minus its operator suffix (or the key itself if no suffix is present).
  for (const [key, expected] of Object.entries(gt.must_have)) {
    requiredFieldsTotal++;
    const { fieldName, predicate } = resolveFieldExpectation(key, expected);
    const actual = prod.fields[fieldName];
    const result = predicate(actual);
    if (result.matched) requiredFieldsMatched++;
    fieldDiffs.push({
      field: key,
      expected: expected as unknown,
      actual,
      matched: result.matched,
      note: result.note,
    });
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
  const hasConfidenceFloor = gt.confidence_floor !== undefined;
  if (hasConfidenceFloor) {
    confidenceOk = prod.confidence >= (gt.confidence_floor as number);
    fieldDiffs.push({
      field: "confidence",
      expected: `>= ${gt.confidence_floor}`,
      actual: prod.confidence,
      matched: confidenceOk,
      note: confidenceOk ? undefined : "below confidence_floor",
    });
  }

  // Match quality is the weighted fraction of fields that matched.
  // The confidence check contributes to BOTH numerator and denominator only
  // when a floor is set; without a floor it contributes 0 to each. Earlier
  // versions added +1 to the numerator unconditionally (because confidenceOk
  // defaulted to true) while gating the +1 to the denominator on the floor
  // being set — biasing match_quality upward and allowing it to exceed 1.0
  // in some configurations.
  const confidenceContribTotal = hasConfidenceFloor ? 1 : 0;
  const confidenceContribMatched = hasConfidenceFloor && confidenceOk ? 1 : 0;
  const totalFields = requiredFieldsTotal + toleranceFieldsTotal + confidenceContribTotal;
  const matchedFields = requiredFieldsMatched + toleranceFieldsMatched + confidenceContribMatched;
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

// ────────────────────────────────────────────────────────────────────
// Operator suffix dispatch
// ────────────────────────────────────────────────────────────────────
//
// Suffixes are matched longest-first so `_in_cidrs` is not stolen by `_in`.

type FieldPredicate = (actual: unknown) => { matched: boolean; note?: string };

interface ResolvedExpectation {
  fieldName: string;          // base field on produced finding
  predicate: FieldPredicate;
}

const OPERATOR_SUFFIXES = [
  "_in_cidrs",
  "_contains",
  "_present",
  "_in",
] as const;

export function resolveFieldExpectation(
  key: string,
  expected: unknown
): ResolvedExpectation {
  for (const suffix of OPERATOR_SUFFIXES) {
    if (key.endsWith(suffix)) {
      const fieldName = key.slice(0, -suffix.length);
      switch (suffix) {
        case "_in_cidrs":
          return { fieldName, predicate: makeCidrPredicate(expected) };
        case "_contains":
          return { fieldName, predicate: makeContainsPredicate(expected) };
        case "_present":
          return { fieldName, predicate: makePresentPredicate(expected) };
        case "_in":
          return { fieldName, predicate: makeInListPredicate(expected) };
      }
    }
  }
  return {
    fieldName: key,
    predicate: (actual) => ({
      matched: exactMatch(expected, actual),
      note: undefined,
    }),
  };
}

function makeContainsPredicate(expected: unknown): FieldPredicate {
  if (typeof expected !== "string") {
    return () => ({ matched: false, note: "_contains expects a string" });
  }
  const needle = expected.toLowerCase();
  return (actual) => {
    if (typeof actual !== "string") {
      return { matched: false, note: actual === undefined ? "missing" : "expected string" };
    }
    const haystack = actual.toLowerCase();
    return {
      matched: haystack.includes(needle),
      note: haystack.includes(needle) ? undefined : `does not contain "${expected}"`,
    };
  };
}

function makePresentPredicate(expected: unknown): FieldPredicate {
  if (typeof expected !== "boolean") {
    return () => ({ matched: false, note: "_present expects a boolean" });
  }
  if (expected === true) {
    return (actual) => {
      const present = actual !== undefined && actual !== null && actual !== "";
      return {
        matched: present,
        note: present ? undefined : "expected field to be present and truthy",
      };
    };
  }
  // expected === false: field must be absent or falsy
  return (actual) => {
    const absent = actual === undefined || actual === null || actual === "";
    return {
      matched: absent,
      note: absent ? undefined : "expected field to be absent",
    };
  };
}

function makeInListPredicate(expected: unknown): FieldPredicate {
  if (!Array.isArray(expected)) {
    return () => ({ matched: false, note: "_in expects an array" });
  }
  if (expected.length === 0) {
    return () => ({ matched: false, note: "_in list is empty" });
  }
  return (actual) => {
    if (actual === undefined || actual === null) {
      return { matched: false, note: "missing" };
    }
    const matched = expected.some((item) => exactMatch(item, actual));
    return {
      matched,
      note: matched ? undefined : `not in [${expected.map(String).join(", ")}]`,
    };
  };
}

function makeCidrPredicate(expected: unknown): FieldPredicate {
  if (!Array.isArray(expected) || expected.length === 0) {
    return () => ({ matched: false, note: "_in_cidrs expects a non-empty CIDR list" });
  }
  const cidrs = expected.filter((c): c is string => typeof c === "string");
  if (cidrs.length === 0) {
    return () => ({ matched: false, note: "_in_cidrs list contained no strings" });
  }
  return (actual) => {
    if (typeof actual !== "string") {
      return { matched: false, note: actual === undefined ? "missing" : "expected IPv4 string" };
    }
    if (ipv4ToInt(actual) === null) {
      return { matched: false, note: `not a valid IPv4: "${actual}"` };
    }
    for (const cidr of cidrs) {
      if (ipv4InCidr(actual, cidr)) {
        return { matched: true, note: `in ${cidr}` };
      }
    }
    return { matched: false, note: `not in [${cidrs.join(", ")}]` };
  };
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    result = result * 256 + n;
  }
  return result >>> 0;
}

export function ipv4InCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf("/");
  if (slash === -1) return false;
  const base = cidr.slice(0, slash);
  const bits = Number(cidr.slice(slash + 1));
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;

  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;

  if (bits === 0) return true;
  // 32-bit mask. JS << has modulo-32 semantics, so handle bits === 32 as "all bits set".
  const mask = bits === 32 ? 0xFFFFFFFF : ((0xFFFFFFFF << (32 - bits)) >>> 0);
  return (ipInt & mask) === (baseInt & mask);
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
