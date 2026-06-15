# Demo Video — Spoken Script (v2)

Built against the Find Evil! Judge Pack and Quick Reference. Replaces the
v1 script in `demo_video_script.md`; the old file is kept for comparison.

Hard cap **5:00**. Target **4:30**. One take if possible — the rules flag
jump cuts before results as the cheapest tell for staged content.

## Voice and posture

Flat, declarative, third-person about the agent ("the agent does X" — not
"watch as X" or "we show X"). No taglines, no manifestos, no music. The
PDFs are explicit: a slick edited video is the least trustworthy artifact
in the package. Every claim in the narration should be something a judge
can pull from `forensic_audit.jsonl` or the repo without your help.

## What the judge has to see, in order

1. **The attack.** Caldera launches the hunt_lab OT scenario live enough that
   the video proves provenance without spending a minute in Caldera.
2. **The alert.** ELK shows the detection that starts the response.
3. **The collection.** Velociraptor gathers the triage that becomes case
   evidence.
4. **The case.** A real one, on disk, with the answer key off the host.
5. **The IC briefing.** Goes in the new-case context box — the agent's
   initial hypothesis, not ground truth.
6. **A real tool failure and a real recovery.** Not the agent's own
   anomaly check landing on a clean contradiction. The Judge Pack calls
   that "self-correction theater."
7. **The three-claim trace.** Three on-screen findings, each pointed
   back to the JSONL entry that produced it. The QuickReference says
   non-negotiable; doing it on camera saves the judge the work.
8. **Fight-back handoff.** Findings become IOC publication, Velociraptor hunt,
   and containment/isolation proposals.
9. **A constraint refusing the wrong response, plus the code that makes
   refusal architectural.** Don't assert "schema-layer" — show the grep.
10. **Something the agent got wrong.** Tied to a specific line in the
   accuracy report. The asymmetry rule: an honest miss outranks a
   flawless-looking demo.

Marketing fluff (cold-open hooks, "AI speed," "architecturally impossible"
as a punchline) is gone. That language is exactly what the PDF flags as
polish bias.

---

## ACT 0 — The case, in one breath (0:00–0:40)

**VISUAL:** SIFT terminal, no slides. `ls ~/Desktop/cases/ot_brute_2026-06-13/`,
then `head -30 README.md`. The README header — collection time, hosts,
"Caldera Debrief is held separately on the analyst host and is not part
of this bundle" — should be readable on screen.

**NARRATION:**

> This is the SIFT Workstation. The case bundle in
> `~/Desktop/cases/ot_brute_2026-06-13/` is from a live exercise this week.
> A Caldera adversary scenario brute-forced SSH on a water-treatment
> HMI simulator from a Windows pivot host on the corporate network.
> Triage from both was pulled with Velociraptor. The Caldera Debrief —
> every step the attacker actually took — is held off the analyst host.
> The agent never sees it. That isolation is enforced by physical
> separation across devices.

**Why this beat:** establishes provenance the judge can verify (file
exists, README cites the isolation rule). No manifesto.

---

## ACT 1 — Hand the agent the case (0:40–1:20)

**VISUAL:** Browser at SIFTics `/new-case`. Case ID auto-fills. Cursor
into the **Initial briefing for the agent** textarea. Paste the SOC-style
hand-off (the OT-HMI + EDR alert paragraph) — not the attack chain, just
what an analyst would actually have on day one. Click **Create**.

**NARRATION:**

> A new case takes the SOC hand-off verbatim. This text is the IC's
> initial hypothesis — what the agent reads first. The Investigation
> Section Chief skill treats it as orientation, not ground truth. If
> the briefing turns out to be wrong, that's the most useful finding
> to surface, not a confirmation-bias trap.

**Why this beat:** demonstrates the feature shipped today (the context
field), and pre-empts a credibility question — the agent isn't being
fed the answer.

---

## ACT 2 — Agent works the case, including one real failure (1:20–2:40)

**VISUAL:** Dashboard, agent transcript scrolling live. Real tool calls
against the actual evidence. Walk through the agent picking up the
windows-artifacts skill on the pivot side and the iot-ot-artifacts skill
on the HMI side. Findings post as they're produced, each labeled
`confirmed` or `inferred`.

The critical beat: **one tool call genuinely fails.** Don't stage it —
record until it happens naturally and use that take. Realistic example
patterns to watch for:

- Parser returns 0 rows on `auth.log` because rsyslog truncated the
  header; agent re-reads the file, adjusts the regex, retries.
- Velociraptor artifact path off by one container-mount level; agent
  notices the empty result, corrects the path.
- Skill calls a tool the broker rejects (missing arg); agent reads the
  rejection, retries with the arg.

**NARRATION (deliver during the failure beat):**

> The agent just got an empty result on a call it expected to return
> hits. The next turn re-reads the input, adjusts, retries. That entire
> arc — failed call, error output, adjusted parameters, retry, success —
> is in `forensic_audit.jsonl` unchanged. The video is showing what the
> log already records. Nothing edited.

**Why this beat:** Criterion 1 (Autonomous Execution Quality) is judged
from the logs, not the video. The PDF defines a 5-star self-correction
as "the full arc visible in logs." Anchoring the narration on the JSONL
makes this verifiable on re-watch.

---

## ACT 3 — Three-claim trace, on screen (2:40–3:25)

**VISUAL:** Split window. Left: three finalized findings on the
dashboard (whatever the agent actually surfaced — fill in the IDs at
record time). Right: terminal tailing `forensic_audit.jsonl`. For each
finding, the cursor jumps to the matching JSONL entry. Tool name, input,
output excerpt all visible. Three findings, three traces.

**NARRATION:**

> Three findings, three traces. Finding `[F-001]` — `[short claim]` —
> comes from this audit event: the agent's `[tool_call]` against
> `[file_or_endpoint]`, the matching output is the line highlighted on
> the right. Finding `[F-002]` — `[claim]` — comes from this event.
> Finding `[F-003]` — `[claim]` — comes from this one. The audit chain
> is hash-chained. `audit_verify.sh` catches tampering; it's a five
> second run.

**Why this beat:** the Quick Reference makes the three-claim trace
non-negotiable. Doing it on camera with real IDs means a judge in a
hurry already has the JSONL line numbers.

---

## ACT 4 — Constraint refusal, with code proof (3:25–4:10)

**VISUAL:** Agent's transcript. The agent proposes a containment action
against the HMI host. Browser at `/gates`: Safety Officer card renders
with `personnel_safety: critical`. No **Approve** button is rendered.

Cut to terminal. Two commands:

```
grep -nE '^def (execute|isolate|contain)' mcp_response/server.py
```

…which returns no `execute_*` or `isolate_*` symbols, only
`propose_containment`. Then:

```
pytest tests/test_constraints.py -k "tool_surface" -v
```

…showing the test that asserts the destructive symbols are absent.

**NARRATION:**

> The agent proposes containment. The Safety Officer scores
> `personnel_safety` as critical — the target is a live water-treatment
> process. The gates page doesn't render an approve button because
> there is no `execute_containment` symbol on the response MCP server.
> The grep shows it. The constraint test asserts it. The boundary is
> in the surface, not in a prompt.

**Why this beat:** Criterion 4 (Constraint Implementation) explicitly
rewards architectural guardrails over prompt-based ones, and asks
"were boundaries tested for bypass?" Show both.

---

## ACT 5 — What the agent got wrong (4:10–4:40)

**VISUAL:** Open `docs/accuracy_report.md` in the SIFT VM's editor.
Scroll to the False Positives / Misses section. Highlight **one** real
entry — a finding the agent surfaced that turned out to be wrong, or a
known miss the team has documented.

**NARRATION:**

> The accuracy report is the team's own self-audit. This entry is
> something the agent got wrong in testing. We flagged it and left it
> in the report. The rules say honesty is valued over perfection. This
> is what that looks like.

**Why this beat:** the asymmetry the Judge Pack is explicit about. A
hallucination the team caught counts FOR the team; one a judge finds
unflagged counts heavily against. Putting this in the video, on screen,
in 30 seconds, is the cheapest insurance available.

---

## ACT 6 — Where to find it (4:40–5:00)

**VISUAL:** Plain title slide. Three lines, no animation, no music:

```
github.com/rjonhaas/SIFTics  —  MIT
docs/accuracy_report.md
forensic_audit.jsonl
```

**NARRATION:**

> Repo and license up top. The accuracy report is where to start.
> The audit log is where to verify. Thanks.

No tagline. No "thanks for watching." Just the three pointers.

---

## Time budget

| Act | Window | What carries it |
|---|---|---|
| 0 — case | 0:00–0:40 | terminal + README provenance |
| 1 — briefing | 0:40–1:20 | new-case UI + context box |
| 2 — work + failure | 1:20–2:40 | live transcript with a real recovery |
| 3 — three-claim trace | 2:40–3:25 | dashboard + JSONL split |
| 4 — refusal + proof | 3:25–4:10 | gates page + grep + pytest |
| 5 — honest miss | 4:10–4:40 | accuracy report scroll |
| 6 — pointers | 4:40–5:00 | static title |

5:00 hard cap. ~30 seconds of slack across Acts 0/1/6 if Act 2's failure
beat runs long (it will sometimes — that's the point of a real one).

## If a take runs long, cut here first

1. Act 6 narration — let the static slide carry it silently. Saves ~6s.
2. Act 0 README scroll — read fewer lines. Saves ~5s.
3. Act 5 — one sentence instead of two. Saves ~4s.

Do **not** cut Act 3 or Act 4. Those are the two beats that map directly
to non-negotiable judging requirements.

## Recording rules

- Record the agent run *once*, end to end. If the run is too long for a
  single take, record the segments back-to-back with no edits inside a
  segment. Jump cuts mid-segment are exactly the staging tell judges
  are coached to watch for.
- The agent must run against `~/Desktop/cases/ot_brute_2026-06-13/` on the SIFT
  VM. The Caldera Debrief stays on the host.
- No background music. The Stage One check explicitly looks for
  copyrighted music and treats absence as cleaner than presence.
- Mic + screen recorder + SIFT VM resolution should give legible
  terminal text at 1080p. Don't assume judges full-screen.
- Have a known-good `audit_verify.sh` pass run earlier the same day so
  you know the chain is intact going in.

## After upload

- Update `docs/demo_video.md` §1 (Submission link) with the YouTube URL.
- Update `README.md` Devpost compliance row #6 with the same link.
- Open the link in an incognito browser and confirm it plays without
  sign-in.

## What changed from v1, and why

Mapped to the Judge Pack:

| v1 pattern | Judge Pack flag | v2 fix |
|---|---|---|
| Cold-open manifesto ("Adversaries operate in seven-minute breakouts…") | "Polish bias: a slick, edited demo video is the least trustworthy artifact." | Open on `ls` of the case directory. |
| Phase 18 anomaly check as the self-correction beat | "Self-correction theater: a contrived error with an instant, suspiciously clean recovery." | A real tool failure during the run, narrated as "in the log unchanged." |
| No three-claim trace | "Non-negotiable. Pick three findings, locate the tool execution." | Act 3 does it on camera. |
| No acknowledged miss | "Honesty valued over perfection. Hallucinations the team caught count for them." | Act 5 reads one entry from the accuracy report. |
| "Schema-layer, not prompt-layer" asserted in narration | Criterion 4 wants architectural proof. | Act 4 grep + pytest of the absent symbol. |
| Tagline ending ("response at AI-speed - with the right guardrails") | "Watch for jump cuts right before results appear" and polish-bias warnings. | Plain three-line pointer slide. |
