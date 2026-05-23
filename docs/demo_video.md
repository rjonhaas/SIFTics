# Demo Video — Storyboard, Script, and Submission Link

Devpost submission item #6.

> **Hackathon rules:** *"≤ 5 min; live terminal execution with audio narration; not slides; not marketing videos. Show the agent working against real evidence, including at least one self-correction sequence."*

---

## 1. Submission link

**YouTube (unlisted, public-link-shareable):** *TBD — filled in 2026-06-14 after final recording.*

Backup: Vimeo *TBD*.

---

## 2. Storyboard (5:00 hard cap; aiming for 4:30)

| Time | Content | What's on screen | Spoken narration cue |
|---|---|---|---|
| 0:00 – 0:15 | **Cold open + thesis** | SIFTics dashboard at idle; case header reads "Acme Corp — Caldera mimikatz scenario" | *"Adversaries operate in 7 minutes. Defenders take hours. SIFTics is how we close that gap. Custom MCP Server architecture, NIMS ICS doctrine."* |
| 0:15 – 0:40 | **30-sec install proof** | Fresh SIFT VM terminal: `git clone … && pip install -e . && sift-case-init …` | *"From git clone to first finding in 30 seconds. Same install path works on the OVA and on WSL-SIFT."* |
| 0:40 – 1:00 | **Setup wizard cutaway** | Browser at `/setup` — 5 LLM backend cards (Claude Code, Anthropic API, Ollama detected, OpenAI, Codex) | *"SIFTics runs on whatever LLM you have. Tonight I'm using Claude Code — the hackathon's preferred path. Same investigation runs unchanged on local Ollama."* |
| 1:00 – 1:30 | **Agent kicks off** | Terminal: `claude` → `/investigation-section-chief` against `~/cases/demo_2026/`; agent calls `case_get_header`, `itq_unanswered`, `asr_open` | *"Investigation Section Chief reads the COP, walks the unanswered triage questionnaire. Universal IR-doctrine questions sourced from NIMS ICS and NIST 800-61."* |
| 1:30 – 2:15 | **HOT layer + multi-signal classify_binary** | Terminal output: agent calls `fast_persistence_scan`, finds `lsass_helper.exe`, classifies via Rathbun baseline + imphash + capa + RAG | *"Four signals fused in 500 milliseconds: path doesn't match baseline, imphash matches mimikatz family, capa says credential dumper, RAG aligns to ATT&CK T1003. High confidence."* |
| 2:15 – 2:55 | **Hunt-package primitive + IC Authority Gate** | Split-screen: terminal proposes hunt package; browser at `/gates` shows pending request card. IC types passphrase, clicks approve. Audit log scrolls. | *"Agent cannot fire fleet actions. It proposes a typed hunt package; IC reviews and signs with HMAC. This boundary is architectural — there is no `execute_unapproved` function in the MCP surface."* |
| 2:55 – 3:30 | **Self-correction (tiebreaker)** | Phase 18 catches a contradiction between WARM finding and HOT scan. `run_self_correct.sh` re-runs upstream phase. New finding aligns. | *"Phase 18 detects cross-artifact contradiction. Self-correction loop re-runs upstream phase. This is the tiebreaker criterion, and it's not emergent — it's explicit machinery."* |
| 3:30 – 4:00 | **Audit chain + verify** | Terminal: `audit_verify.sh` — green tick. Browser at `/audit` — click verify button — green. Walk one finding back through the chain. | *"Every finding traces back through cryptographically-chained tool executions. Tampering would be detected at the first verify step."* |
| 4:00 – 4:25 | **Bypass test harness** | Terminal: `pytest tests/test_constraints.py -v` — 14 lines of green flash on screen | *"Constraints aren't claimed. They're measured. Fourteen architectural guardrails tested for bypass; all pass."* |
| 4:25 – 4:50 | **Compliance map + sign-off** | README compliance table; cursor highlights each row | *"Every Devpost deliverable mapped to a file path. No hunting through the repo. The license is at the root."* |
| 4:50 – 5:00 | **Tagline + repo URL** | Black slate: "github.com/rjonhaas/SIFTics — MIT" | *"Valhuntir answers what happened here. SIFTics answers what happened, where else is it, and is it still happening. Repo's open source. Thank you."* |

---

## 3. Filming checklist

### Hardware / software

- [ ] Headphones with mic (no laptop mic — judges will dock for bad audio)
- [ ] OBS Studio configured: 1080p, 30fps, audio normalised
- [ ] Two terminal windows pre-arranged (avoid fumbling)
- [ ] Browser bookmark bar hidden; fresh profile
- [ ] System notifications disabled
- [ ] `htop` / activity monitors closed

### Pre-flight

- [ ] Fresh SIFT VM snapshot — install path tested today
- [ ] `examples/run_2026-XX-XX/` case directory ready with seed data
- [ ] IC passphrase memorized; no on-screen typing of credentials beyond the obscured passphrase box
- [ ] Anthropic API key set; `pytest` green; budget set to $5
- [ ] hunt_lab VMs running; Caldera attack ability ready to fire if needed for live demo
- [ ] All MCP servers loaded; quick `/dashboard` smoke test
- [ ] Demo script printed (or on a second screen) for narration

### Recording

- [ ] Two takes minimum; pick the better one
- [ ] Watch for: dead-air > 3 seconds, terminal-output flooding the screen, accidental NSFW notifications
- [ ] Cut anything beyond 5:00 — judges aren't required to watch past 5 (and not past 10)

### Post-production

- [ ] No background music (Devpost rules on third-party copyright)
- [ ] Captions / subtitles (accessibility)
- [ ] Upload to YouTube as **Unlisted** with publicly-shareable link
- [ ] Add link to this file and to the main README compliance table
- [ ] Backup to Vimeo with the same link policy

---

## 4. Talking points to weave in (if natural)

These are bonus phrases that map to specific judging criteria — sprinkle them where they fit organically; don't force.

- **Criterion 1 (Autonomous):** *"explicit machinery, not emergent property"*, *"three-iteration self-correction loop"*
- **Criterion 2 (IR Accuracy):** *"measured against public CTFs"*, *"five independent signals fused"*, *"hash-chained provenance"*
- **Criterion 3 (Breadth/Depth):** *"twenty phases, depth-on-demand"*, *"HOT, WARM, COLD"*
- **Criterion 4 (Constraints):** *"architectural, not prompt-based"*, *"bypass tested"*, *"there is no `execute_unapproved`"*
- **Criterion 5 (Audit Trail):** *"every finding traces back"*, *"tamper-evident"*, *"per-finding cost traceability"*
- **Criterion 6 (Usability):** *"thirty seconds from clone to first finding"*, *"works on OVA and on WSL"*, *"five LLM backends including fully-local"*

---

## 5. What we will *not* show in the video

Honest pre-decisions to keep the runtime tight and to set expectations:

- **No GUI tools beyond Flask + terminal.** Plaso, EvtxECmd, etc. run silently. The video is about the agent's behaviour, not the underlying parsers.
- **No deep KAPE bundle traversal.** That's a benchmark-doc concern.
- **No multi-host attack-path graph.** That's already shown elsewhere; one short cutaway in the audit-chain segment if time allows.
- **No multi-examiner / Portal-style** UI. Valhuntir has that; SIFTics v1 doesn't. We win on substance, not polish.

---

## 6. Backup plan if Anthropic API fails mid-recording

If the API has an outage during the take:

1. Hit `/setup`, swap to Ollama.
2. Re-narrate: *"And here's the same investigation running on a local Llama via Ollama — same MCP surface, same audit chain, zero cost."*
3. Continue from where we were.

This contingency is itself part of the demo's strength (criterion #6).

---

## 7. Final upload checklist

- [ ] YouTube unlisted link works in incognito browser (not just our own login)
- [ ] Vimeo backup uploaded with same URL policy
- [ ] Link pasted into Devpost submission form
- [ ] Link added to this file
- [ ] Link added to README §1 (compliance map row #6)
- [ ] Final `pytest` run; all 14 still pass
- [ ] Submission button hit before 2026-06-15 23:45 EDT (we aim for **24 h** earlier as buffer)
