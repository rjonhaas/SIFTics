# Accuracy Test Harness

**The third leg of the testing pyramid.** Spoliation tests prove evidence cannot be modified. Injection tests prove the LLM is not easily hijacked. This harness proves the swarm produces **correct findings** when neither attack vector applies — when it is just doing its job on clean evidence.

## What This Tests

For each test case in this harness:

1. A **fixture evidence source** is provided with **known ground truth** — what the agent SHOULD find
2. The swarm is run against the fixture
3. The findings are compared to ground truth using standard classification metrics

The output is precision, recall, F1, and false-positive/false-negative rates per artifact category.

## What Makes Accuracy Different from the Other Harnesses

| Harness | Failure mode | Pass/fail |
|---|---|---|
| Spoliation | Evidence was modified | Binary (hash changed or didn't) |
| Injection | LLM was hijacked into wrong action | Statistical (hijack rate) + graded severity |
| **Accuracy** | **Findings don't match ground truth** | **Statistical (precision/recall/F1) per category** |

Accuracy is the trickiest to measure because:

1. **Ground truth requires curation.** Each fixture must be either synthetic-with-known-truth or real-data-with-manually-verified-truth. There's no shortcut.
2. **"Correct" is fuzzy.** A finding can be partially correct — right artifact type, wrong timestamp; right host, wrong process. The harness needs to match findings to ground truth probabilistically, not just by string equality.
3. **Confidence scoring matters.** A correct finding with confidence 0.5 is different from a correct finding with confidence 0.95. The harness computes *calibration* — does the agent's stated confidence actually match its observed accuracy at that confidence?

## Test Case Anatomy

Each test case is a directory under `test-cases/` containing:

```
test-cases/
└── 001-ransomware-disk-only/
    ├── case.yaml                  # Test metadata: scenario, evidence sources, branches involved
    ├── ground_truth.yaml          # The findings the agent SHOULD produce
    ├── fixture/                   # The evidence the agent will analyze
    │   ├── disk_image.E01
    │   └── README.md              # Provenance and curation notes
    └── expected_iocs.yaml         # Specific IOCs that must appear in the COP
```

`ground_truth.yaml` schema:

```yaml
case_id: 001-ransomware-disk-only
scenario: BlackBasta-style ransomware on a Windows workstation
evidence:
  - id: EVID-001
    type: disk_image
    path: fixture/disk_image.E01

ground_truth_findings:
  - id: GT-001
    branch: forensics
    category: persistence
    must_have:
      artifact_type: scheduled_task
      task_name: "WindowsUpdateHelper"
      executable_path: "C:\\Users\\Public\\update.exe"
      created_at: "2026-04-22T14:35:11Z"
    must_have_within_tolerance:
      created_at:
        target: "2026-04-22T14:35:11Z"
        window_seconds: 5
    confidence_floor: 0.8

  - id: GT-002
    branch: forensics
    category: execution
    must_have:
      artifact_type: prefetch
      executable_name: "UPDATE.EXE-A1B2C3D4.pf"
      first_run: "2026-04-22T14:35:14Z"
    confidence_floor: 0.9

  - id: GT-003
    branch: forensics
    category: lateral_movement
    must_not_appear: true
    rationale: "This case is single-host. Any lateral-movement finding is a false positive."

allowed_extra_findings: 5  # Tolerance for benign extra findings before counting as FP noise
```

## Metrics Reported

For each test case, and rolled up across all cases:

| Metric | What It Tells You |
|---|---|
| **Precision** | Of findings the agent reported, what fraction were correct? `TP / (TP + FP)` |
| **Recall** | Of findings that should have been reported, what fraction were? `TP / (TP + FN)` |
| **F1** | Harmonic mean of precision and recall. The single number to track. |
| **False positive rate** | How many findings did the agent invent that don't match ground truth? |
| **False negative rate** | How many ground-truth findings did the agent miss entirely? |
| **Confidence calibration** | Average confidence on correct vs. incorrect findings. Well-calibrated = correct findings have higher confidence than incorrect ones. |
| **Hallucination rate** | Findings whose cited tool execution ID does not exist in the audit log. Zero is the only acceptable value. |
| **Citation completeness** | Fraction of findings that cite a tool execution ID at all. Should be 1.0. |

## Hallucination Rate Is the Most Important Metric

A finding without a valid `tool_execution_id` is a hallucination by definition — the agent claimed something but cannot point to where it came from. The architecture requires every finding to cite an execution ID, and the audit log makes those IDs verifiable.

If hallucination rate > 0, the architecture has a leak. The harness reports it prominently.

## How to Run

```bash
# Build first
npm run build

# Run all test cases
npm run test:accuracy

# Single test case
npm run test:accuracy -- --case=001-ransomware-disk-only

# Single branch (only run cases that test forensics)
npm run test:accuracy -- --branch=forensics

# Quick mode (skip slow cases for fast iteration)
npm run test:accuracy -- --quick
```

## Test Cases (initial set)

| Case ID | Scenario | Branches Tested | Difficulty |
|---|---|---|---|
| 001-ransomware-disk-only | BlackBasta-style ransomware, single Win10 workstation, disk only | Forensics | Easy |
| 002-insider-threat-disk-mem | Insider data theft, disk + memory, no network | Forensics, Memory | Medium |
| 003-c2-network-only | Cobalt Strike beacon, PCAP only, no host evidence | Network, Malware | Medium |
| 004-multi-host-lateral | RDP lateral movement across 3 hosts | Forensics, Memory, Network | Hard |
| 005-living-off-the-land | PowerShell + WMI, no malware binary | Forensics, Memory, Malware | Hard |
| 006-clean-baseline | Clean Win11 workstation, NO threats | All branches (negative case) | Critical |

The clean baseline is critical — it measures the false-positive rate on healthy systems. An agent that flags a clean system as compromised is more dangerous than one that misses some threats, because it wastes responder time and erodes trust.

## What This Harness Does NOT Test

- **Adversarial scenarios** — those are in `test/injection/`
- **Evidence integrity** — that is in `test/spoliation/`
- **End-to-end final report quality** — the harness measures findings, not narrative
- **IC reasoning quality across operational periods** — that requires human evaluation of the audit log

## Output Artifacts

```
reports/
  accuracy-report-{ts}.json           Per-case + aggregate metrics
  accuracy-report-{ts}.md             Judge-facing summary
  accuracy-finding-diffs-{ts}.md      For each case, diff of expected vs. produced findings
  accuracy-calibration-{ts}.json      Confidence calibration data for plotting
```

## Using the Report in Your Submission

The Accuracy Report should include a section like:

> Protocol SIFT ICS was tested against N curated DFIR test cases with manually-verified ground truth. Aggregate F1: 0.NN (precision 0.NN, recall 0.NN). Hallucination rate: 0.0 (every finding traces to a valid tool execution ID per the audit log). Confidence calibration: correct findings averaged confidence 0.NN, incorrect findings averaged 0.NN. Per-branch and per-case breakdowns at `test/accuracy/reports/`. Test fixtures and ground truth at `test/accuracy/test-cases/`. Reproducible: `npm run test:accuracy`.

Together with the spoliation and injection reports, this completes the three-leg testing story:

> **No spoliation. Defense-in-depth held against injection. Findings calibrated to ground truth.**

That's a defensible, quantitative claim across the three judging criteria most affected by your testing work — Constraint Implementation, IR Accuracy, and Audit Trail Quality.
