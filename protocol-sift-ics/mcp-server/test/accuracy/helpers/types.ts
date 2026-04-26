/**
 * Type definitions for the accuracy harness.
 *
 * The core concept: ground truth findings (what the agent SHOULD produce) are
 * matched against actual findings (what the agent DID produce) using a
 * tolerant matcher that allows for fuzzy field comparisons. The output is
 * standard classification metrics — precision, recall, F1, plus DFIR-specific
 * concerns like hallucination rate and confidence calibration.
 */

// ────────────────────────────────────────────────────────────────────
// Ground truth definitions (loaded from test-cases/*.yaml)
// ────────────────────────────────────────────────────────────────────

export type Branch = "triage" | "forensics" | "memory" | "network" | "malware";

export type FindingCategory =
  | "initial_access"
  | "execution"
  | "persistence"
  | "privilege_escalation"
  | "defense_evasion"
  | "credential_access"
  | "discovery"
  | "lateral_movement"
  | "collection"
  | "command_and_control"
  | "exfiltration"
  | "impact"
  | "user_anomaly"
  | "anomalous_network"
  | "known_malware"
  | "suspicious_process";

/**
 * A single ground-truth finding — the spec for what the agent should produce.
 * The matcher compares produced findings against this spec using `must_have`
 * fields (exact match required), `must_have_within_tolerance` fields (fuzzy
 * match allowed), and `must_not_appear` (negative case).
 */
export interface GroundTruthFinding {
  id: string;
  branch: Branch;
  category: FindingCategory;
  /**
   * Fields the produced finding MUST match. Keys may carry an operator suffix
   * to relax exact-match semantics. The suffix selects the comparator and the
   * base field name (key minus the suffix) is what's looked up on the
   * produced finding.
   *
   *   foo:               exact match (default — case-insensitive for strings)
   *   foo_in:            value must be in the supplied list
   *   foo_contains:      produced field must contain expected substring (case-insensitive)
   *   foo_present:       boolean — true requires presence with truthy value, false requires absence/falsy
   *   foo_in_cidrs:      produced IPv4 must be in one of the supplied CIDR ranges
   */
  must_have: Record<
    string,
    string | number | boolean | string[] | number[] | boolean[]
  >;
  /** Fields the produced finding must match within a tolerance */
  must_have_within_tolerance?: Record<string, ToleranceSpec>;
  /** When true, the harness treats this as a negative case — no finding should match */
  must_not_appear?: boolean;
  /** When the finding should not appear, why */
  rationale?: string;
  /** Minimum confidence the produced finding must report */
  confidence_floor?: number;
}

export type ToleranceSpec =
  | { target: string; window_seconds: number }                  // for ISO timestamps
  | { target: number; relative_error: number }                  // for numbers
  | { target: string; edit_distance: number };                  // for strings

export interface TestCase {
  case_id: string;
  scenario: string;
  evidence: Array<{ id: string; type: string; path: string }>;
  ground_truth_findings: GroundTruthFinding[];
  /** How many extra findings (not in ground truth) are tolerated before counting as noise */
  allowed_extra_findings: number;
  /** Specific IOCs that must appear in the COP after this case runs */
  expected_iocs?: {
    hashes?: string[];
    ips?: string[];
    domains?: string[];
    registry_keys?: string[];
    file_paths?: string[];
  };
}

// ────────────────────────────────────────────────────────────────────
// Produced findings (from a real swarm run)
// ────────────────────────────────────────────────────────────────────

export interface ProducedFinding {
  finding_id: string;
  branch: Branch;
  category: FindingCategory;
  summary: string;
  confidence: number;
  /** Every finding must cite a tool execution ID — hallucination check */
  tool_execution_id: string;
  /** Field values extracted by the agent */
  fields: Record<string, string | number | boolean>;
}

// ────────────────────────────────────────────────────────────────────
// Match results
// ────────────────────────────────────────────────────────────────────

export interface FindingMatch {
  ground_truth: GroundTruthFinding;
  produced: ProducedFinding | null;   // null = no match found = false negative
  match_quality: number;              // 0.0 (no match) to 1.0 (perfect)
  field_diffs: Array<{
    field: string;
    expected: unknown;
    actual: unknown;
    matched: boolean;
    note?: string;
  }>;
  /** True if the match satisfies all required fields */
  is_true_positive: boolean;
  /** True if expected was must_not_appear and nothing matched (correct rejection) */
  is_true_negative: boolean;
  /** True if a finding appeared that should not have */
  is_false_positive: boolean;
  /** True if expected was a positive case but no matching produced finding */
  is_false_negative: boolean;
}

export interface UnmatchedProducedFinding {
  produced: ProducedFinding;
  /** Whether this counts as noise (allowed) or false positive (over-budget) */
  is_noise: boolean;
}

// ────────────────────────────────────────────────────────────────────
// Per-case results
// ────────────────────────────────────────────────────────────────────

export interface CaseResult {
  case_id: string;
  scenario: string;
  matches: FindingMatch[];
  unmatched_produced: UnmatchedProducedFinding[];
  /** Findings that cited a tool_execution_id not present in the audit log */
  hallucinated_findings: ProducedFinding[];
  /** Findings that did not cite any tool_execution_id at all */
  uncited_findings: ProducedFinding[];
  metrics: CaseMetrics;
}

export interface CaseMetrics {
  total_ground_truth: number;
  total_produced: number;
  true_positives: number;
  true_negatives: number;
  false_positives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1: number;
  hallucination_rate: number;
  citation_completeness: number;
  /** Average confidence reported on correct findings */
  avg_confidence_when_correct: number;
  /** Average confidence reported on incorrect findings */
  avg_confidence_when_incorrect: number;
  /** Calibration error: expected = correct findings should have higher confidence */
  calibration_gap: number;
}

// ────────────────────────────────────────────────────────────────────
// Aggregate results across all cases
// ────────────────────────────────────────────────────────────────────

export interface AggregateMetrics {
  total_cases: number;
  total_findings_expected: number;
  total_findings_produced: number;
  /** Micro-averaged: TP/FP/FN summed across cases, then ratios computed */
  micro: {
    precision: number;
    recall: number;
    f1: number;
  };
  /** Macro-averaged: per-case metrics averaged */
  macro: {
    precision: number;
    recall: number;
    f1: number;
  };
  hallucination_rate: number;
  citation_completeness: number;
  avg_calibration_gap: number;
  per_branch: Record<Branch, BranchMetrics>;
  per_category: Record<string, CategoryMetrics>;
}

export interface BranchMetrics {
  branch: Branch;
  total_findings: number;
  precision: number;
  recall: number;
  f1: number;
  hallucination_count: number;
}

export interface CategoryMetrics {
  category: string;
  total_findings: number;
  precision: number;
  recall: number;
  f1: number;
}
