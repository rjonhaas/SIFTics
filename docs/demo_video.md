# Demo Video - Storyboard, Script, and Submission Link

Devpost submission item #6.

> **Hackathon rules:** *"≤ 5 min; live terminal execution with audio narration; not slides; not marketing videos. Show the agent working against real evidence, including at least one self-correction sequence."*

---

## 1. Submission link

**YouTube (unlisted, public-link-shareable):** *TBD - add after final recording.*

Backup: Vimeo *TBD*.

---

## 2. Recommended storyboard - hunt_lab OT fight-back loop

This is the strongest demo path because it shows the full incident loop rather
than another analysis-only agent: **Caldera attack -> ELK alert -> Velociraptor
triage -> SIFTics investigation -> controlled response**.

Keep the story to one OT incident. Do not turn the recording into a tour of
Caldera, ELK, Velociraptor, and SIFTics. Each external tool gets one short proof
beat, then SIFTics owns the rest of the video.

| Beat | Time | Content | What's on screen | Spoken narration cue |
|---|---|---|---|---|
| **Attack** | 0:00 - 0:30 | Caldera launches the hunt_lab OT adversary profile | Caldera operation or terminal starting the scenario | *"This is not a canned prompt. Caldera is launching an OT intrusion from hunt_lab: recon, SSH brute force, HMI config access, and setpoint tamper."* |
| **Alert** | 0:30 - 0:55 | ELK receives the detection | Kibana alert for OT-HMI brute force / config tamper | *"The SOC sees the alert first. SIFTics starts from the same handoff a human responder would get, not the answer key."* |
| **Collect** | 0:55 - 1:20 | Velociraptor triage collection completes | Velociraptor collection or completed artifact bundle | *"Velociraptor gathers triage from the Windows pivot and OT HMI. The collection becomes the case evidence."* |
| **Investigate** | 1:20 - 2:35 | SIFTics runs the case | COP dashboard with Agent Workbench, Evidence Ledger, ASR, Lines of Inquiry | *"The Investigation Section Chief builds the Common Operating Picture from real artifacts. Chat is not the record. Findings, ASR rows, gates, and audit events are."* |
| **Trace** | 2:35 - 3:15 | Three findings traced back to evidence | Findings tab + audit/event references | *"Three claims are traceable: brute-force source, successful OT login, and config/setpoint tamper. Each one has a tool output behind it."* |
| **Fight back** | 3:15 - 4:20 | SIFTics turns findings into actions | IOC draft, Velociraptor hunt proposal, containment/isolation proposal, `/gates` | *"Most agents stop at the report. SIFTics prepares the response: publish IOCs, push hunts, and propose isolation. The IC controls execution."* |
| **Safety stop** | 4:20 - 4:45 | OT isolation is blocked or escalated | Red Safety Officer hard-stop / no approve button | *"This is the point: it can fight back, but it cannot bypass safety. Water-treatment isolation is not a normal endpoint action."* |
| **Proof** | 4:45 - 5:00 | Verification | `pytest`, `audit.verify_chain()`, submission docs | *"The behavior is in the logs and tests, not just in the video."* |

---

## 3. Previous three-act storyboard

| Act | Time | Content | What's on screen | Spoken narration cue |
|---|---|---|---|---|
| **Cold open** | 0:00 – 0:25 | **The asymmetry** | Black slate → SIFTics `/dashboard` at idle | *"Adversaries operate in seven-minute breakouts. Defenders take hours. That gap isn't a model problem - it's an authorisation problem. SIFTics closes it. Three things in four minutes: standalone analysis on real evidence, a live hunt firing in under a minute, and the Safety Officer refusing the wrong response."* |
| **1. Standalone** | 0:25 – 0:45 | **30-sec install + open Szechuan Sauce case** | Fresh SIFT terminal: `./setup.sh` → URL appears → browser at `/new-case` pre-filled `2026-06-XX-01` → click Create | *"Fresh SIFT VM. One command. Case ID auto-generated. The MCP broker is in mock mode - there is no infrastructure to configure. This is what a judge sees."* |
| **1. Standalone** | 0:45 – 1:25 | **HOT layer + multi-signal classification** | Terminal: agent calls `fast_persistence_scan` → finds `lsass_helper.exe` → classifies via Rathbun baseline + imphash + capa + RAG | *"The evidence proves the binary exists and executed. Baseline says the path is off-reference, MalwareBazaar and capa add behavior signals, and local RAG explains the ATT&CK context. RAG is classification support, not proof."* |
| **1. Standalone** | 1:25 – 1:55 | **Phase 18 self-correction** | Phase 18 catches a contradiction between a WARM finding and the HOT scan; `run_self_correct.sh` re-runs upstream phase; revised finding aligns | *"Phase 18 detects cross-artefact contradiction and re-runs upstream. This is the tiebreaker - explicit machinery, not emergent behaviour."* |
| **2. Connected** | 1:55 – 2:10 | **Posture switch** | Browser at `/setup` → flip "Response Targets" radio from **Mock** to **Live** → Velociraptor URL + cert paths populate from earlier config → Save | *"Same agent, same audit chain - now connected to a real Velociraptor server. The reference deployment is the sister hunt_lab repo; in production, this is your environment."* |
| **2. Connected** | 2:10 – 2:40 | **Hunt-package proposal + Incident Commander (IC) Authority Gate** | Split-screen: terminal proposes hunt package targeting the lsass_helper imphash across all hosts; browser at `/gates` shows the pending HMAC-signed request card; IC types passphrase, clicks approve | *"The agent cannot fire fleet actions. It proposes a typed hunt package. The Incident Commander reviews and signs with HMAC. This boundary is architectural - there is no `execute_unapproved` function on the MCP surface for the agent to call."* |
| **2. Connected** | 2:40 – 3:10 | **Hunt fires; results come back** | Velociraptor UI on a second monitor (or split) shows hunt enqueued → fanout across 3 enrolled clients → 1 hit in under 30 seconds → finding card updates with the matched client_id and evidence path | *"Approved at zero. Fired at three seconds. First result at twenty-six. Sixty seconds end to end. That is what 'fighting back at AI-speed' actually looks like - and it only works because the IC stayed in the loop the whole way."* |
| **3. Refusal** | 3:10 – 3:50 | **OT scenario - Safety Officer architectural hard-stop** | Switch case to the `ot_brute` triage bundle from hunt_lab; agent surfaces failed-then-accepted SSH on `ot-hmi-water-01` + SCADA config dump; proposes containment_action (isolate host); `/gates` page shows a **red banner**: *"Safety hard-stop: personnel_safety critical - water-treatment dosing HMI"*; no signable approval object is ever rendered | *"Now the same agent on the OT scenario. It surfaces the brute-force pivot correctly. It proposes containment. The Safety Officer scores personnel-safety as critical because the dumped config references a chlorination HMI. And then - watch - there is no approve button. The function to override doesn't exist on the agent's tool surface. This is the difference between 'be careful in the prompt' and architectural enforcement."* |
| **Trust artefacts** | 3:50 – 4:25 | **Audit chain verify + bypass tests** | Terminal: `audit_verify.sh` → green tick; `pytest tests/test_constraints.py -v` → 14 green lines flash; browser at `/audit` → walk one finding back to its originating tool call | *"Every finding traces back through cryptographically-chained tool executions. Fourteen architectural guardrails tested for bypass - all pass. Constraints aren't claimed; they're measured."* |
| **Compliance map** | 4:25 – 4:50 | **Devpost rubric walkthrough** | README compliance table; cursor highlights each row in order | *"Every Devpost deliverable mapped to a file path. No hunting through the repo. License at the root."* |
| **Sign-off** | 4:50 – 5:00 | **Tagline + URL** | Black slate: "github.com/rjonhaas/SIFTics - MIT" | *"Detection got AI-speed years ago. SIFTics is response at AI-speed - with the right guardrails. Repo's open. Thank you."* |

---

## 4. Filming checklist

### Hardware / software

- [ ] Headphones with mic (no laptop mic - judges will dock for bad audio)
- [ ] OBS Studio configured: 1080p, 30fps, audio normalised
- [ ] Two terminal windows pre-arranged (avoid fumbling)
- [ ] Browser bookmark bar hidden; fresh profile
- [ ] System notifications disabled
- [ ] `htop` / activity monitors closed

### Pre-flight

**Standalone half (Acts 0–1):**
- [ ] Fresh SIFT VM snapshot - install path tested today
- [ ] Szechuan Sauce evidence copied to `~/Desktop/cases/szechuan_sauce/evidence/` (host answer key NOT present in the VM)
- [ ] Anthropic API key set OR `claude login` OAuth detected; `pytest` green; budget set to $5
- [ ] All MCP servers loaded; quick `/dashboard` smoke test
- [ ] IC passphrase memorised; no on-screen typing of credentials beyond the obscured passphrase box

**Connected half (Act 2):**
- [ ] hunt_lab fully up: `vagrant status` clean, 4 VMs running, 3 sandcat agents enrolled in Caldera group `red`, 3 Velociraptor clients enrolled
- [ ] Velociraptor mTLS client cert + key + CA bundle already configured in `/setup` → Response Targets → Velociraptor; **Mock/Live radio set to Mock** for the recording start
- [ ] RansomHub-13-Step-2026 case bundle prepared so the `lsass_helper.exe` hit lands deterministically
- [ ] Velociraptor UI tab open on second monitor at the Hunt Manager view

**Refusal half (Act 3):**
- [ ] `ot_brute` triage bundle staged as a separate case under `~/Desktop/cases/2026-06-XX-02/` ready to switch into
- [ ] OT-HMI container running (`docker ps | grep ot-hmi`) so the dumped SCADA config in the case header is actually current
- [ ] `/gates` UI verified to render the red Safety banner correctly (the case has been replayed once today)

**Pacing:**
- [ ] Demo script printed (or on a second screen) for narration
- [ ] Stopwatch visible for each act's wall-clock budget

### Recording

- [ ] Two takes minimum; pick the better one
- [ ] Watch for: dead-air > 3 seconds, terminal-output flooding the screen, accidental NSFW notifications
- [ ] Cut anything beyond 5:00 - judges aren't required to watch past 5 (and not past 10)

### Post-production

- [ ] No background music (Devpost rules on third-party copyright)
- [ ] Captions / subtitles (accessibility)
- [ ] Upload to YouTube as **Unlisted** with publicly-shareable link
- [ ] Add link to this file and to the main README compliance table
- [ ] Backup to Vimeo with the same link policy

---

## 5. Talking points to weave in (if natural)

These are bonus phrases that map to specific judging criteria - sprinkle them where they fit organically; don't force.

- **Criterion 1 (Autonomous):** *"explicit machinery, not emergent property"*, *"three-iteration self-correction loop"*
- **Criterion 2 (IR Accuracy):** *"measured against public CTFs"*, *"five independent signals fused"*, *"hash-chained provenance"*
- **Criterion 3 (Breadth/Depth):** *"twenty phases, depth-on-demand"*, *"HOT, WARM, COLD"*
- **Criterion 4 (Constraints):** *"architectural, not prompt-based"*, *"bypass tested"*, *"there is no `execute_unapproved`"*, *"the function to override doesn't exist on the agent's tool surface"*
- **Criterion 5 (Audit Trail):** *"every finding traces back"*, *"tamper-evident"*, *"per-finding cost traceability"*
- **Criterion 6 (Usability):** *"setup.sh idempotent; works on a fresh SIFT VM"*, *"Claude Code with API key OR claude login OAuth"*
- **Layer separation (new framing):** *"standalone for the judges; connected for the demo"*, *"mock mode returns generic placeholders, real mode talks to whatever Velociraptor you give it"*, *"hunt_lab is the reference deployment, not a dependency"*
- **Sign-off frame:** *"fight back at the speed of AI - with the right guardrails"*

---

## 6. What we will *not* show in the video

Honest pre-decisions to keep the runtime tight and to set expectations:

- **No GUI tools beyond Flask + terminal.** Plaso, EvtxECmd, etc. run silently. The video is about the agent's behaviour, not the underlying parsers.
- **No deep KAPE bundle traversal.** That's a benchmark-doc concern.
- **No multi-host attack-path graph.** That's already shown elsewhere; one short cutaway in the audit-chain segment if time allows.
- **No multi-examiner / Portal-style** UI. Valhuntir has that; SIFTics v1 doesn't. We win on substance, not polish.

---

## 7. Backup plan if Anthropic API fails mid-recording

If the API has an outage during the take:

1. Hit `/setup`, swap to Ollama.
2. Re-narrate: *"And here's the same investigation running on a local Llama via Ollama - same MCP surface, same audit chain, zero cost."*
3. Continue from where we were.

This contingency is itself part of the demo's strength (criterion #6).

---

## 8. Final upload checklist

- [ ] YouTube unlisted link works in incognito browser (not just our own login)
- [ ] Vimeo backup uploaded with same URL policy
- [ ] Link pasted into Devpost submission form
- [ ] Link added to this file
- [ ] Link added to README §1 (compliance map row #6)
- [ ] Final `pytest` run; all 14 still pass
- [ ] Submission button hit before 2026-06-15 23:45 EDT (we aim for **24 h** earlier as buffer)
