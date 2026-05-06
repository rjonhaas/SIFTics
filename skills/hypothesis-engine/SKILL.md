# Skill: Hypothesis Engine (Working-Theory Ledger)

## When to invoke

The Investigation Section Chief (ISC) invokes this skill **at every operational period
boundary**, as Step 5b of the Operational Period Structure (after the COP update, before
the cross-skill pivot check). It is also invoked at case start (Period 1) to seed the
initial hypothesis based on what the IC reported in the case CLAUDE.md.

This skill encodes the senior-analyst pattern of carrying 2–3 working theories at all
times, scoring each against new evidence as it arrives, and retiring hypotheses that
contradict the data. It is the structural counterpart to the Common Operating Picture
(COP): the COP records what the ISC has found, the hypothesis ledger records what the
ISC currently believes those findings mean.

---

## Why this exists

A junior analyst chases the first plausible explanation and updates their belief slowly.
A senior analyst maintains an explicit set of working theories, rates each against
incoming evidence, and is prepared to abandon a leading theory when the evidence pivots.

Without this skill, the agent risks anchoring bias — committing to the first hypothesis
that fits Phase 1's output and then under-weighting Phase 8's contradictory evidence. The
hypothesis ledger is an external memory of the agent's reasoning that survives the
operational period transitions and the LLM's context-window churn.

---

## Hard rules

- The hypothesis ledger is a JSONL file at `${CASE_ROOT}/analysis/hypotheses.jsonl`. It is
  append-only — never edit prior entries. New entries supersede prior ones with the same
  `id`.
- At the end of every operational period, the ISC must:
  1. Re-score every active hypothesis based on new COP findings since last update.
  2. Retire any hypothesis whose confidence falls below 0.2.
  3. Verify at least one active hypothesis has confidence ≥0.5. If none do, generate a new
     alternative hypothesis explaining the current evidence and add it to the ledger.
  4. If two or more hypotheses are confirmed (≥0.85) and they are mutually exclusive, this
     is a contradiction — surface it in the COP `Contradictions` table.
- Confidence is computed mechanically by `scripts/hypothesis_score.py`, not estimated by
  the LLM. The LLM provides the signals (text descriptions tied to COP findings); the
  script computes the score.

---

## JSONL schema

Each line is one hypothesis state at the time it was written. Fields:

```json
{
  "id": "H001",
  "period": 2,
  "hypothesis": "Initial access via ProxyShell on EXCH01 by external actor",
  "status": "active",
  "created_period": 1,
  "last_updated_utc": "2026-05-06T14:23:00Z",
  "signals_for": [
    {
      "source": "Phase 13 — webshell_inventory.csv",
      "finding": "aspxspy.aspx in C:/inetpub/wwwroot/aspnet_client",
      "weight": 0.4,
      "added_period": 1
    },
    {
      "source": "Phase 6 — hunting_timeline.csv",
      "finding": "EID 4624 type 3 from 192.0.2.4 → EXCH01 svc account",
      "weight": 0.3,
      "added_period": 2
    }
  ],
  "signals_against": [],
  "confidence": 0.7,
  "alternatives_considered": ["H002", "H003"]
}
```

### Field semantics

| Field | Meaning |
|---|---|
| `id` | Stable identifier (`H001`, `H002`, ...) — append-only ledger uses ID + period to track state changes |
| `period` | Operational period this row was written in |
| `hypothesis` | One-sentence theory. Specific enough to be falsifiable. |
| `status` | `active` / `confirmed` (≥0.85) / `retired` (<0.2) / `contradicted` (signal weight ≥0.5 against) |
| `created_period` | The period the hypothesis was first generated |
| `signals_for` | Array of evidence supporting the hypothesis. Each has source, finding, weight (0.0–1.0), period added |
| `signals_against` | Array of evidence contradicting the hypothesis. Same shape as `signals_for` |
| `confidence` | 0.0–1.0 — computed by `hypothesis_score.py`, not estimated by the LLM |
| `alternatives_considered` | IDs of competing hypotheses the ISC weighed against this one |

### Signal weighting guidance

- 0.5+ : direct, multi-source corroboration of a critical claim (e.g., webshell binary
  on disk + same hash in memory malfind + matching outbound connection in EVTX 5156)
- 0.3–0.5 : strong single-source confirmation (e.g., explicit logon entry, IIS access
  log of the exploit URL with 200 response)
- 0.1–0.3 : circumstantial — consistent with the hypothesis but other explanations exist
  (e.g., process executed under suspect account; could be benign)
- <0.1 : weak/atmospheric — note for completeness, doesn't materially move confidence

`signals_against` use the same weights but subtract from confidence.

---

## Scoring formula

Implemented by `scripts/hypothesis_score.py`:

```
confidence = clamp(0.0, 1.0,
    sum(signals_for[i].weight) - sum(signals_against[i].weight))
```

Two safety rules layered on top:
1. **Confirmation cap:** any hypothesis with at least one `signals_against` weight ≥0.5 is
   capped at status `contradicted` regardless of for-signal sum.
2. **Stale decay:** hypotheses not updated for 2 operational periods get their confidence
   multiplied by 0.7 each period (encourages active maintenance).

---

## Workflow

### At case start (Period 1, after COP initialization)

The ISC reads:
- `case_root/CLAUDE.md` — Investigator Context, Reported symptoms, Suspected threat actor
- `analysis/cop.md` — Phase 0 evidence inventory + temporal mapping

Then generates 1–3 initial hypotheses:

```bash
python3 ${SIFTICS_HOME:-/home/sansforensics/SIFTics}/scripts/hypothesis_score.py \
    add "$CASE_ROOT" \
    --hypothesis "Ransomware affiliate with valid VPN credential" \
    --period 1 \
    --signal-for "Phase 0 — case CLAUDE.md|Client reported file encryption|0.3"
```

### At every operational period boundary

```bash
# 1. Add new signals to existing hypotheses
python3 hypothesis_score.py signal "$CASE_ROOT" \
    --id H001 --period 2 --kind for \
    --source "Phase 6 — hunting_timeline.csv" \
    --finding "EID 4624 type 3 from 192.0.2.4 → EXCH01 svc account" \
    --weight 0.3

# 2. Re-score everything
python3 hypothesis_score.py score "$CASE_ROOT" --period 2

# 3. Print current ledger summary (gets injected into COP "Active Hypotheses" table)
python3 hypothesis_score.py report "$CASE_ROOT"
```

### Generating a new alternative (mid-case)

If `score` reports max confidence < 0.5, the ISC must add a new hypothesis explaining
the COP findings:

```bash
python3 hypothesis_score.py add "$CASE_ROOT" \
    --hypothesis "Insider with admin credential, not external compromise" \
    --period 3 \
    --signal-for "Phase 7 — credaccess_timeline.csv|DCSync from non-DC service account|0.4"
```

### Retiring at case closure

The closure checklist in the ISC skill includes:
> All hypotheses are `confirmed`, `retired`, or `contradicted`. No `active` hypotheses
> remain at case closure (or, if any do, the IC has been informed they could not be
> resolved with available evidence and they are documented in the report).

---

## Integration with the rest of the pipeline

- **Anomaly detector (Phase 18) → hypothesis ledger:** every HIGH-severity anomaly is
  added as a `signal_against` for any hypothesis it contradicts. Example: a
  `shimcache-mft-absent` anomaly is a strong signal_against any "no anti-forensics
  occurred" hypothesis.
- **Self-correction loop → hypothesis ledger:** when self-correction reduces HIGH
  anomalies, the resolved anomalies are removed from `signals_against` and the affected
  hypotheses are re-scored.
- **Investigation report skill:** reads `hypotheses.jsonl` and renders the final ledger
  state in Section 2 of the report ("How we arrived at this conclusion"). Confirmed
  hypotheses become the report's main narrative; retired hypotheses appear as
  "Alternative explanations considered and ruled out."

---

## Output paths

| Artifact | Path |
|----------|------|
| Hypothesis ledger | `./analysis/hypotheses.jsonl` |
| Current ledger snapshot (rendered) | `./analysis/hypotheses_current.md` |
