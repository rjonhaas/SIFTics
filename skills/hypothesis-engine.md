---
name: hypothesis-engine
description: Mechanical signal-weighted theory tracking. Avoids LLM-anchoring on the first plausible explanation.
---

# Hypothesis Engine

LLMs anchor. Without explicit guards, the agent latches onto the first plausible
explanation and discounts contrary evidence afterward. The Hypothesis Engine
is a deliberate counter-anchor: it forces every theory to be scored
*mechanically* by signal weights, not by LLM-estimated confidence.

## How it works

`hypothesis_score.py` is a JSONL ledger of hypotheses. Each hypothesis has:

- A unique ID (`hypothesis_id`)
- A natural-language statement ("the attacker established initial access via
  phishing of user X")
- A list of weighted signals (each with its own weight and direction +/-)
- An aggregate confidence (computed, *not* estimated)
- A status (`open`, `retired`, `confirmed`, `disconfirmed`)

The confidence is the *sum* of supporting-signal weights minus the sum of
contradicting-signal weights, divided by the total possible. **It is not an
LLM-estimated number.** You can compute it without calling a model.

## When to use it

You should:

- Open a hypothesis the moment you have a coherent story (even a weak one)
  about the incident. Don't wait for high confidence. Track all the stories
  in parallel.
- Add signals as evidence accrues. Each signal explicitly references the
  audit-log event ID that produced it.
- Add *negative* signals too. If you searched for something and it wasn't
  there, that is evidence — record it.
- Periodically retire hypotheses below 0.1 confidence after at least 5 signals
  have been weighed. Keep the ledger clean.

You should not:

- Pick a winning hypothesis until at least one has confidence > 0.7 *and*
  no competing hypothesis is above 0.3.
- Self-estimate the confidence number — let the math do it.
- Add the same signal twice to inflate confidence.

## CLI

```bash
hypothesis_score.py add  "<statement>"             # opens a new hypothesis, returns id
hypothesis_score.py signal <id> <weight> "<reason>" --audit-event <event_seq>
hypothesis_score.py score <id>                      # prints current confidence
hypothesis_score.py report                          # markdown table of all theories
hypothesis_score.py retire <id> --reason "..."     # closes a theory
```

## Signal-weight conventions

| Signal type | Typical weight |
|---|---|
| Direct evidence (matching IOC, hash, timeline) | 3–5 |
| Strong circumstantial (logs of a tool the actor uses) | 2–3 |
| Weak circumstantial (unusual but not unique) | 1–2 |
| Absence-of-evidence (looked for X, didn't find it — *only valid when the search was thorough*) | 0.5–1 |
| Contradicting evidence | negative of the corresponding positive weight |

If you find yourself wanting to use weight > 5 on a single signal, the signal
is probably a smoking gun and you should mark the hypothesis as `confirmed`
rather than just adding one big signal.

## Use during the IC briefing

When you post a briefing, include the top three open hypotheses and their
current confidence numbers. This gives the IC a snapshot of where you think
the investigation is *and* shows them the work behind your reasoning. ICs who
see the math behind your confidence trust the agent more than ICs who only
see the conclusion.

## Use during Authority Gate proposals

When you request an `execute_hunt_package` Authority Gate, include the
hypothesis you're testing in the gate summary. If the hypothesis has only
0.4 confidence, that's still a perfectly valid reason to propose a hunt —
hunts are how you confirm or disconfirm low-confidence theories. State that
explicitly: "I'm 0.4 on the credential-dumper theory; this hunt will tell us
whether other hosts show the imphash pattern, which would push the theory to
0.7+ or below 0.1."

ICs approve gates that say "this is what I'm testing." ICs hesitate on gates
that say "this is what I'm sure is true."
