---
name: anti-forensics-review
description: Pre-close anti-forensics reviewer — generative reasoning over the attacker actions recorded in this specific case. NOT a rule-matcher. Loaded at the same checkpoint as case-completeness-review.
---

# Anti-Forensics Review

Anti-forensics is an **open-ended adversarial domain**. You cannot enumerate
its surface in a fixed checklist because the surface depends on what the
specific attacker in this case actually did. A rule that says "run
`analyzeMFT` and check `$SI` vs `$FN`" works against textbook cases and
fails the moment the attacker's evasion is something other than the textbook.

This skill exists because a rule-based completeness pass *cannot* catch the
shape of error we keep seeing: the agent runs the canonical anti-forensics
check on the *malware binary*, finds nothing, and concludes "no
anti-forensics was deployed." That conclusion is structurally wrong every
time the attacker used anti-forensics on *anything else* in the case.

Your job is to **read the case and reason about coverage** — not match
keywords.

## When to invoke

The Investigation Section Chief operating loop calls
`anti_forensics_review()` at the **same checkpoint** as
`case_completeness_check()` — before any final briefing, before
`case_set_motivation()`, before any ASR row transitions from
`pending_verification` to `safe`, whenever the IC asks "is the case ready?"

The two complement each other:

- `case_completeness_check` catches **bounded** gaps where the answer is
  yes/no by tool invocation — did `regripper -p timezone` run? did
  `secretsdump` run? These have clear right answers.
- `anti_forensics_review` is the **open-ended** companion. There is no
  fixed right answer; the persona's job is to reason about what *should*
  have been checked given what the attacker is recorded to have done.

## Method — three deliberate passes

### Pass 1: Enumerate attacker actions

Read every `finding_record`, every ASR row's `notes` and `how_determined`,
every briefing. Build a list of every distinct action the attacker is
recorded to have taken:

- Each persistence mechanism deployed
- Each lateral-movement hop
- Each credential operation
- Each file accessed, written, deleted, or moved (especially user-data files)
- Each log-emitting action the attacker performed
- Each network connection the attacker initiated
- Each privilege escalation
- Each timestamp the attacker controls (file writes, process starts, etc.)

Cite each action by the finding_record IDs and ASR serials that record it.

### Pass 2: Reason about plausible evasion

For **each** attacker action from Pass 1, ask:

> "If this attacker were trying to hide *this specific action* from a
> forensic investigator, what would they do?"

Generate the answer from general anti-forensics knowledge — not from a
rule table. Some categories to consider for each action:

- **Timestamp evasion** — would they timestomp the artifact? what
  comparison would surface it? (`$SI` vs `$FN`, but also: parent
  directory `$INDEX_ALLOCATION` mtime; filesystem mtime vs internal
  PE/document creation time; OS install date as lower bound)
- **Existence evasion** — would they delete + overwrite the artifact?
  what recovery would surface the original? (`$MFT` inactive entries,
  `$LogFile`, `$UsnJrnl`, `$Recycle.Bin`, unallocated free space carving)
- **Provenance evasion** — would they hide *who* did this? (cleared
  EVTX, rotated logs, paused auditing, used a service account, used
  LOLBins to hide tool identity)
- **Communication evasion** — would they hide *what* left the network?
  (encrypted C2, DNS tunneling, steganography, lawful-services abuse)
- **Tool identification evasion** — would they hide *what tool* they
  used? (renamed binaries, custom loaders, signed-but-malicious DLLs,
  living-off-the-land)
- **Anchor evasion** — would they alter the things forensic tools
  anchor on? (registry transaction log tampering, USN journal pruning,
  prefetch deletion)

The list of categories is a *starting point*, not a checklist. The persona's
job is to ask, for *this specific action*, what evasion the *attacker
demonstrated by other actions in this case* would plausibly extend to.

### Pass 3: Check coverage and surface gaps

For each (action, plausible evasion) pair from Pass 2, check whether the
case state shows the agent actually ran the appropriate detection — not
"mentioned the technique," but **ran the tool and recorded the output**.

- If the detection ran and produced a clean negative → confirmed-covered.
- If the detection ran and surfaced something → already a finding.
- If the detection did not run → **gap**. The persona surfaces it to the
  IC with: which action, which evasion was plausible, what tool would
  have detected it, what the gap means for the case narrative.

## Output schema

Call `anti_forensics_review()` with:

```python
{
  "action_hash": "<hash of case state at time of review>",
  "attacker_actions_enumerated": [
    {
      "action": "Attacker accessed and copied files from \\FileShare\\Secret\\",
      "source_finding_ids": ["F-012", "F-014"]
    },
    {
      "action": "Attacker installed coreupdater service on CITADEL-DC01",
      "source_finding_ids": ["F-014", "F-018"]
    },
    ...
  ],
  "coverage_assessment": [
    {
      "action_idx": 0,
      "plausible_evasions": [
        "timestomp staged exfil files to hide staging time",
        "delete the staged archive after exfil"
      ],
      "what_was_checked": [
        "MFT $SI vs $FN on coreupdater.exe only (F-016)"
      ],
      "gap": "User-data files in \\FileShare\\Secret\\ were not MFT-walked. The agent's claim 'no anti-forensic tooling was deployed' is not supported for this action.",
      "gap_severity": "high"
    },
    {
      "action_idx": 1,
      "plausible_evasions": ["..."],
      "what_was_checked": ["..."],
      "gap": null,
      "gap_severity": "none"
    }
  ],
  "summary": "Reviewed 7 attacker actions. 2 actions have uncovered plausible evasion (HIGH); 1 has partial coverage (MEDIUM); 4 are fully covered.",
  "reviewer_certainty": "high"
}
```

The tool validates the schema and writes an `anti_forensics_review_completed`
audit event with the full structured output.

## What this skill does NOT do

- **Does not pattern-match keywords.** No keyword list, no trigger string,
  no expected-evidence regex. If you find yourself thinking "I should check
  if the findings mention 'timestomp'," you're doing the wrong thing —
  enumerate actions, reason about evasion, check actual tool runs.
- **Does not produce a fixed checklist.** What you check depends entirely
  on what the attacker did in *this* case.
- **Does not block.** Like Finance Officer, this is *informational* — the
  IC decides whether to address each gap. Surfacing the gap is the role.

## Anti-patterns

- **Don't conflate "agent did this check" with "agent did this check on
  the right targets."** Same trap the old keyword rule fell into.
- **Don't trust agent self-assessment.** When the agent says "no
  anti-forensics observed," ask "across what scope?" If the scope is
  smaller than the attacker's attack surface, the claim is unsupported.
- **Don't accept "out of scope" without a SIFTics policy citation.**
  Same rule as the completeness critic.
- **Don't pretend certainty.** If you can't enumerate what the attacker
  did because the findings are thin, say so in `reviewer_certainty: low`
  and recommend more investigation before close.

## Cross-references

- `skills/anti-forensics-detection.md` — the detection methodology this
  reviewer evaluates coverage of (the *what* and *how*; this skill is
  the *did we apply it where it mattered*).
- `skills/case-completeness-review.md` — the bounded yes/no companion.
  Both run at the same checkpoint; gaps from either feed the IC's
  pre-close decision.
- `mcp_case.anti_forensics_review()` — the typed MCP tool that validates
  the structured output and writes the audit event.
