# Demo Video — Spoken Script

Companion to [`docs/demo_video.md`](demo_video.md) (storyboard). This file is the word-for-word narration timed to the three-act arc. Hard cap: 5:00. Target: 4:30 with breathing room.

**Read-aloud pace:** ~150 words per minute. The script is ~570 words → ~3:50 of narration + ~40s of silent visual transitions = ~4:30 total. If you hit beats faster than this, you have margin.

**Voice direction:** conversational, like you're explaining to a peer — not a sales voice, not a robot. Every act has one beat that should be slowed for impact (called out in the per-act notes).

---

## ACT 0 — Cold open (0:00–0:25, ~22s)

**VISUAL:** Black slate fades into SIFTics `/dashboard` at idle (no case loaded yet, just the title bar).

**NARRATION:**

> Adversaries operate in seven-minute breakouts. Defenders take hours. That gap isn't a model problem — it's an authorisation problem. Authority can't be delegated to a model, but it can be exercised at AI speed. SIFTics is how. Three things in four and a half minutes: standalone analysis on real evidence, a live hunt firing in under a minute, and the Safety Officer refusing the wrong response.

**Pacing note:** slow down on "*authority can't be delegated to a model*" — that's the thesis. Let it land before "*but it can be exercised at AI speed*."

---

## ACT 1.1 — Standalone install (0:25–0:45, ~17s)

**VISUAL:** Fresh SIFT terminal. Type `./setup.sh`. The URL prints in green. Click it → browser opens at `/new-case` with case ID `2026-06-12-01` pre-filled. Click **Create**.

**NARRATION:**

> Fresh SIFT VM. One command. The case ID auto-generates from today's date. The MCP broker defaults to mock mode — no external infrastructure to configure. This is what a judge sees the first time they grade the submission.

---

## ACT 1.2 — HOT layer + multi-signal finding (0:45–1:25, ~28s + 12s visual)

**VISUAL:** Browser at `/dashboard`. Agent transcript scrolls. Agent calls `case_get_header`, `asr_open`, `itq_unanswered`, then `fast_persistence_scan`. Output shows the hit on `lsass_helper.exe` in `C:\Users\Public`. `mcp_baseline`, `mcp_cti`, and `mcp_rag` calls fire one after the other. Finding F-001 posts with `confidence: high`.

**NARRATION:**

> The Investigation Section Chief reads the Common Operating Picture, walks the Initial Triage Questionnaire, picks a persistence scan. Hit on lsass_helper.exe in C-Users-Public. Four signals fuse in five hundred milliseconds — path off the Rathbun baseline, imphash matches mimikatz family, capa says credential dumper, the forensic RAG aligns to ATT&CK T1003. Every claim traces to artifact, tool, command, and output excerpt.

**Pacing note:** the "four signals fuse" sentence is dense. Pause briefly between each signal so the viewer sees each `mcp_*` call land in the transcript.

---

## ACT 1.3 — Phase 18 self-correction (1:25–1:55, ~20s + 10s visual)

**VISUAL:** Phase 18 anomaly check runs. Terminal output shows a contradiction line (something like *"F-001 says compromise window 03:24; F-003 says 03:21"*). `run_self_correct.sh` fires. Finding F-001 v2 supersedes the original; both versions visible in `/findings`.

**NARRATION:**

> Phase 18 — anomaly detection across all findings. It finds a contradiction: same host, two different compromise timestamps. The agent re-runs the upstream phase, reconciles. Original finding superseded. Both versions stay in the chain. This is the tiebreaker — explicit machinery, not emergent behaviour.

**Pacing note:** the self-correction beat is one of the judging criteria. Linger on the moment the contradiction appears on screen.

---

## ACT 2.1 — Posture switch Standalone → Connected (1:55–2:10, ~14s)

**VISUAL:** Browser at `/setup`. Click the **Connected** radio under Response Posture. Click **Save**. Dashboard banner refreshes: *"Response posture: Connected."*

**NARRATION:**

> Same agent. Same audit chain. Now we flip the response posture from Standalone to Connected. The agent's response tools start talking to a real Velociraptor server. No code change, no restart — schema-layer flag, takes effect on the next message.

---

## ACT 2.2 — Authority Gate + HMAC sign (2:10–2:40, ~23s + 7s visual)

**VISUAL:** Split screen: terminal on the left showing the agent proposing a hunt package targeting the lsass_helper imphash; browser on the right at `/gates`. Safety Officer card renders (verdict: `caution`). Legal Officer card renders (verdict: `caution`). Pending request appears with the HMAC stamp. IC types the passphrase, clicks **Approve**. Audit log scrolls.

**NARRATION:**

> The agent proposes a fleet hunt for the lsass_helper imphash. Before the IC even sees it, the Safety Officer scores five dimensions. Legal Officer scores five more. Both clear with caveats. The IC reviews, types their passphrase, signs with HMAC. There is no execute_unapproved function on the agent's tool surface. The boundary is architectural, not exhortative.

**Pacing note:** "*architectural, not exhortative*" — slow down. This is the differentiator vs every prompt-based agent product.

---

## ACT 2.3 — Hunt fires across the lab (2:40–3:10, ~18s + 12s visual)

**VISUAL:** Velociraptor UI on a second monitor or split. Hunt enqueued at 0s. Fanout to three enrolled clients. First hit comes back at 26s. Finding card on the SIFTics dashboard updates with the matched `client_id` and evidence path.

**NARRATION:**

> Approved at zero. Fired at three seconds. First result back at twenty-six. Sixty seconds, end to end, from approval to evidence. That's what fighting back at AI speed actually looks like — and it only works because the IC stayed in the loop the whole way.

---

## ACT 3 — OT refusal: Safety Officer hard-stop (3:10–3:50, ~32s + 8s visual)

**VISUAL:** Switch case to the OT bundle (`2026-06-12-02`). Agent surfaces the SSH brute-force pivot to `ot-hmi-water-01` plus the SCADA config dump showing chlorination setpoint references. Agent proposes `containment_action` to isolate the host. `/gates` page renders a **RED banner**: *"Safety hard-stop: personnel_safety critical — water-treatment dosing HMI."* No approve button is rendered at all.

**NARRATION:**

> Now the OT scenario. Same agent. It surfaces the brute-force pivot to the water-treatment HMI, dumps the SCADA config showing chlorination setpoints. Proposes isolating the host. The Safety Officer scores personnel safety: critical. The schema rejects any other verdict. Watch the gates page. There is no approve button. The function the agent would need to override doesn't exist on its tool surface. This is what schema-layer guardrails actually mean. Not "be careful in the prompt." Architecturally impossible.

**Pacing note:** **THIS IS THE MOMENT THE VIDEO IS BUILT AROUND.** Pause on the empty gates page. "*No approve button*" — say it slowly. "*Architecturally impossible*" — let it sit.

---

## ACT 4 — Trust artefacts (3:50–4:25, ~22s + 13s visual)

**VISUAL:** Terminal. `audit_verify.sh` → green tick. `pytest tests/test_constraints.py -v` → 14 green dots flash. Briefly: cursor pastes `notes="ISOLATION (iso_fake123)"` into the agent's chat → the MCP tool returns a ValueError naming `iso_fake123`. The terminal shows the error.

**NARRATION:**

> Trust artefacts. The audit chain verifies — every finding traces through cryptographically-chained tool executions. Fourteen architectural guardrails tested for bypass; all pass. And the anti-fabrication guard — write a fake gate reference into the case state, the MCP tool rejects it. Schema-layer, not prompt-layer. The agent literally cannot lie about an action it didn't take.

---

## ACT 5 — Compliance map (4:25–4:50, ~12s + 13s visual)

**VISUAL:** Open `README.md`. Cursor walks the Devpost compliance table top-to-bottom highlighting each row.

**NARRATION:**

> Every Devpost deliverable maps to a file path. License at the root. Architecture, accuracy, evidence datasets, agent execution logs — all linked in the table. Repo is public.

**Pacing note:** let the cursor lead. The narration is short on purpose; the visual carries this beat.

---

## ACT 6 — Sign-off (4:50–5:00, ~8s)

**VISUAL:** Black slate: **github.com/rjonhaas/SIFTics — MIT**

**NARRATION:**

> Detection got AI-speed years ago. SIFTics is response at AI-speed — with the right guardrails. Thank you.

---

## Pacing budget at a glance

| Act | Window | Words | At 150 wpm | Visual breathing room |
|---|---|---|---|---|
| 0 — Cold open | 0:00–0:25 | 70 | 0:28 | -0:03 (slow down) |
| 1.1 — Install | 0:25–0:45 | 42 | 0:17 | +0:03 |
| 1.2 — HOT layer | 0:45–1:25 | 60 | 0:24 | +0:16 |
| 1.3 — Phase 18 | 1:25–1:55 | 50 | 0:20 | +0:10 |
| 2.1 — Posture switch | 1:55–2:10 | 35 | 0:14 | +0:01 |
| 2.2 — Gate + sign | 2:10–2:40 | 60 | 0:24 | +0:06 |
| 2.3 — Hunt fires | 2:40–3:10 | 45 | 0:18 | +0:12 |
| 3 — OT refusal | 3:10–3:50 | 88 | 0:35 | +0:05 |
| 4 — Trust | 3:50–4:25 | 55 | 0:22 | +0:13 |
| 5 — Compliance | 4:25–4:50 | 30 | 0:12 | +0:13 |
| 6 — Sign-off | 4:50–5:00 | 20 | 0:08 | +0:02 |
| **Total** | **5:00** | **~555** | **3:42 spoken** | **~78s breathing** |

About 4:30 wall-clock with comfortable pauses, leaving 30 seconds of headroom against the 5-minute cap.

---

## If you're running long — what to cut first

In order of cuttability:

1. **Act 2.3 (Hunt fires)** — cut the "Approved at zero. Fired at three seconds. First result at twenty-six" line. The visual of the hunt firing carries the moment; the words save 18 seconds. ⇒ saves ~18s.
2. **Act 5 (Compliance map)** — cut the cursor walk; let the README appear and dissolve. ⇒ saves ~12s.
3. **Act 1.2 (HOT layer)** — cut "capa says credential dumper" — the other three signals carry. ⇒ saves ~4s.

If you're running short:

- Add a beat in Act 2.2 after "*The boundary is architectural*" — name one of the audit fields: *"Every Claude tool call is hash-chained into forensic_audit-dot-jsonl. Tamper with it, the next verify catches it."*

---

## Filming notes for the recording day

- **Don't read in the same room your face-cam is in** if you're showing yourself. The mic picks up paper rustle.
- **Practice the Act 3 hard-stop beat alone three times** before take 1 — that's the line that has to feel inevitable, not rehearsed.
- **Have the OT case pre-staged** with the ot_brute bundle already at `~/Desktop/cases/2026-06-XX-02/`. Switching cases mid-take eats 10–15 seconds you don't have.
- **Stopwatch the takes.** If take 1 hits 4:45, you have a take 2 to tighten. If take 1 hits 5:15, you have a structural cut to make (use the "if running long" list above).

---

## After upload

- Update [`docs/demo_video.md`](demo_video.md) §1 (Submission link) with the YouTube URL
- Update [`README.md`](../README.md) Devpost compliance row #6 with the same link
- Verify the link works in an incognito browser (not just signed in to your YouTube account)
- Upload to Vimeo as backup with the same unlisted policy
