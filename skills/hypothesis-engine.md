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

---

## Mandatory hypothesis coverage rules

These rules have teeth. They are not suggestions. Violating them is the
mechanical equivalent of anchoring, and anchoring is how agents misidentify
suspects.

### Rule 1 — Every distinct identity token gets at least one hypothesis (F-001)

An *identity token* is any artifact that could be the actor's true source:
an IP address, email address, username, device identifier, session cookie,
MAC address, or DHCP lease entry. The moment your evidence extraction
produces a new identity token — any new one — you must open a hypothesis
that names that token as the actor, even if you privately believe it is
noise.

**Trigger:** immediately after any phase script returns a result containing
an identity token not already the subject of an open hypothesis.

**Mechanics:**

```bash
# You just found that 192.168.15.4 / username "jcoach" appears in HTTP cookies.
# You already have a hypothesis for Jean / mylady.ixchel.
# You MUST now run:
hypothesis_score add "192.168.15.4 / jcoach is the true sender, distinct from the current primary suspect"
# The CLI prints the new ID (e.g., H-3f9a2c1d). Capture it.
hypothesis_score signal H-3f9a2c1d 2 "IP 192.168.15.4 and username jcoach appear in HTTP cookie fields" --audit-event <event_seq>
```

**The test you apply before moving on:** run `hypothesis_score report`
and confirm every identity token in your evidence appears as the named
subject in at least one open hypothesis. If the count of distinct identity
tokens exceeds the count of subject-distinct open hypotheses, stop and
open the missing ones before running the next phase.

This rule exists because the agent will feel the new token is "probably the
same person" or "probably irrelevant." That feeling is anchoring. The
hypothesis ledger is the mechanism that exposes whether the feeling is
justified.

### Rule 2 — Shared-medium cases require an attribution-uncertainty hypothesis at case open (F-005)

A *shared medium* is any network path where multiple physical actors could
be the true source of observed traffic: open WiFi, shared NAT, shared VLAN,
university or campus networks, hotel networks, residential gateways serving
multiple users, or any environment where the IP-to-person mapping is not
one-to-one.

**Trigger:** at case open, before running any HOT-path phase script or
answering ITQ questions beyond the scope category (ITQ-001..005), check
whether any network-origin evidence was collected from a shared medium. If
yes, open the attribution-uncertainty hypothesis immediately.

```bash
hypothesis_score add "An unknown actor used the shared network medium; the observed IP/account evidence cannot yet be attributed to a specific physical person or device"
# Capture the printed ID (e.g., H-7c3d9e1a).
hypothesis_score signal H-7c3d9e1a 2 "Evidence originates from a shared-medium network; physical attribution not yet established" --audit-event <event_seq>
```

**This hypothesis may only be retired — using an explicit retire call with
--reason — after BOTH of the following are satisfied:**

1. A device-binding record (DHCP binding with MAC, 802.11 association log,
   VPN cert, or equivalent) ties the IP to a specific physical device at
   the time of the event.
2. Evidence places a specific person at that device at that time.

Until both conditions are met, retirement is not permitted regardless of
how low the confidence score falls. This is retire-by-rule, not
retire-by-score.

**Nitroba example:**
```
Open at case start (IDs illustrative — use what the CLI returns):
  H-aa1bb2cc: "Jean / mylady.ixchel sent the harassing email"
  H-dd3ee4ff: "192.168.15.4 / jcoach is the true sender"
  H-ff5aa6bb: "Unknown actor used open WiFi; no physical attribution yet"

H-ff5aa6bb stays open until 802.11 association logs or DHCP binding records
tie a device to a specific person at 192.168.15.4 at the relevant timestamp.
```

### Hypothesis coverage checklist — run before every IC briefing

Before calling `briefing_post()`, confirm all of the following:

- [ ] `hypothesis_score report` shows at least one open hypothesis per
      distinct identity token extracted from evidence.
- [ ] If evidence is network-origin from a shared medium, the
      attribution-uncertainty hypothesis is still open OR has been retired
      with an explicit physical-attribution audit event cited.
- [ ] No hypothesis open for more than one phase cycle has zero signals.
- [ ] The briefing text names the top three open hypotheses by ID and
      confidence, not just the leading one.
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
