# Skill: Triage Methodology (Phase Sequencing & Decision Engine)

## When to invoke

The Investigation Section Chief (ISC) invokes this skill **at the start of Period 1**, after Phase 0
(intake hashes, mount verification, Common Operating Picture (COP) initialization) is complete and the evidence
inventory shows at least one Windows KAPE collection, raw disk image, Linux partition, PCAP,
memory image, or PST/OST present.

This skill is the field operations manual that drives the SIFTics phase scripts. It replaces
the deleted `run_all.sh` orchestrator. The ISC still owns the COP, finding taxonomy,
hypotheses, and cross-skill pivots — this skill owns the **what to run, in what order, and
why**.

The agent reads this skill, decides which phases apply to the evidence in scope, sequences
them, and invokes them one (or several in parallel — see §Parallel Execution) at a time.
Between phases, the agent updates the COP and re-evaluates the next move based on what was
just found. **The agent does not blindly walk the default sequence — it reasons.**

---

## Hard Rules

- Each phase script is a black-box tool. The agent invokes it via `bash <script> "${CASE_ROOT}"`,
  reads the resulting CSVs from `${CASE_ROOT}/analysis/`, and decides what to do next.
- A phase is considered **done** when its completion-signal file (per the Phase Catalog
  below) exists with at least one data row. The agent checks the signal before invoking
  any phase.
- A phase that finds zero evidence of its target artifact class is still **done** — empty
  output is a valid finding. Do not re-run the same phase hoping for different output.
- Never invoke a phase whose preconditions are not yet satisfied (e.g., do not run
  Phase 6 Hunting before Phase 3 Event Logs has produced CSVs).
- Every phase invocation is logged to `analysis/forensic_audit.jsonl` automatically by the
  per-script `audit_log.sh` source — the agent does not log manually.
- After every phase, update the COP `Completed Analysis Phases` section with the phase
  number, runtime, and one-line outcome (e.g., "Phase 8 — 3 log-clearing events confirmed").
- **Break conditions override the default sequence.** When a phase produces a finding listed
  in the Break Conditions section below, the agent jumps to the indicated next phase,
  records the deviation in COP `Next Actions`, and resumes the default sequence after the
  out-of-order phase completes.

---

## Phase Catalog

Each phase below is one bash script in `${SIFTICS_HOME}/scripts/`. The contract is fixed —
the agent does not need to read the script source. To invoke:

```bash
bash "${SIFTICS_HOME}/scripts/<script>.sh" "${CASE_ROOT}"
```

> `${SIFTICS_HOME}` = the SIFTics repo root. Resolve it as
> `${SIFTICS_HOME:-$(dirname "$(readlink -f "$0")")/..}` or read from the case CLAUDE.md.

| # | Script | Domain | Depends on | Completion signal (per machine) | Cross-machine output |
|---|---|---|---|---|---|
| 1 | `run_ntfs.sh` | windows_filesystem | none | `analysis/<MACHINE>/<MACHINE>_*_MFT.csv` | — |
| 2 | `run_registry.sh` | windows_registry | none | `analysis/<MACHINE>/Registry/**/*.csv` | — |
| 3 | `run_eventlogs.sh` | windows_event_logs | none | `analysis/<MACHINE>/EventLogs/*_evtx*.csv` | — |
| 4 | `run_artifacts.sh` | windows_artifacts | none | `analysis/<MACHINE>/Artifacts/**/*.csv` | — |
| 5 | `run_execution.sh` | windows_execution | none | `analysis/<MACHINE>/Execution/**/*.csv` | — |
| 6 | `run_hunting.sh` | windows_hunting | 1, 2, 3 | `analysis/<MACHINE>/Hunting/*.csv` | `analysis/hunting_timeline.csv` |
| 7 | `run_credaccess.sh` | windows_credential_access | 1, 3 | `analysis/<MACHINE>/CredAccess/*.csv` | `analysis/credaccess_timeline.csv` |
| 8 | `run_antiforensics.sh` | windows_anti_forensics | 2, 3, 4 | `analysis/<MACHINE>/AntiForensics/*.csv` | `analysis/antiforensics_timeline.csv` |
| 9 | `run_ioc_extract.sh` | ioc_aggregation | 1–8, 11–15 | `analysis/ioc_master.csv` | `analysis/ioc_summary.txt` |
| 10 | `run_c2_beacon.sh` | c2_beacon | 5 (or raw IIS) | `analysis/<MACHINE>/Execution/IIS/c2_beacon.csv` | — |
| 11 | `run_browser.sh` | browser | 1 (for ADS) | `analysis/<MACHINE>/Browser/*.csv` | — |
| 12 | `run_ransomware.sh` | ransomware | 1 | `analysis/<MACHINE>/Ransomware/*.csv` | `analysis/ransomware_summary.txt` |
| 13 | `run_webserver.sh` | web_server_logs | 5 (or raw IIS) | `analysis/<MACHINE>/WebServer/injection_attempts.csv` | `analysis/webserver_summary.txt` |
| 14 | `run_email.sh` | email | none (uses raw PST/OST/mbox) | `analysis/<MACHINE>/Email/*_E_*_Email_Messages.csv` | — |
| 15 | `run_linux.sh` | linux_host | none (mounts ext4 partition) | `analysis/<LINUX_MACHINE>/Linux/*_L_bash_history.csv` | — |
| 16 | `run_cve_attribution.sh` | intel_cve | report + COP complete | `analysis/cve_attribution.md` | — |
| 17 | `run_attack_path.sh` | lateral_movement | 3, 6, 7 | `analysis/attack_path.csv` | `analysis/attack_path_summary.md`, `.mermaid` |
| 18 | `run_anomaly_check.sh` | cross_artifact_anomaly | 1–8, 11–13 | `analysis/anomalies.csv` | `analysis/anomaly_summary.txt` |
| 19 | `run_memory.sh` | windows_memory | none (uses raw `*.mem`/`*.raw`/`*.dmp`/`*.vmem`) | `analysis/<MACHINE>/Memory/psscan.csv` + `memory_anomalies.csv` | — |
| 20 | `run_pcap.sh` | network_capture | none (uses raw `*.pcap`/`*.pcapng`) | `analysis/<MACHINE>/Network/pcap_anomalies.csv` | — |
| — | `run_self_correct.sh` | self_correction_loop | 18 | `analysis/self_correction.jsonl` | `analysis/self_correction_report.md` |
| — | `run_detect_hunt_loop.sh` | velociraptor_detect_hunt | 9 (or any IOC source) | `analysis/cross_host_findings.csv` + `analysis/hunt_artifacts/manifest.json` | `analysis/hunt_results/*.json` |

### Skip rules (when a phase does not apply)

| Phase | Skip if |
|---|---|
| 1 NTFS | No `$MFT` found anywhere under `${CASE_ROOT}` (this also means no Windows machines — most subsequent phases also skip) |
| 2 Registry | No registry hives present (no `SOFTWARE`, `SYSTEM`, `NTUSER.DAT` under any drive root) |
| 3 EventLogs | No `*.evtx` under any `<drive_root>/Windows/System32/winevt/Logs` |
| 4 Artifacts | No `Recent`, `Prefetch`, `AutomaticDestinations`, or `ActivitiesCache.db` present |
| 5 Execution | No `inetpub/logs/LogFiles/W3SVC*`, no `ConsoleHost_history.txt`, no `Tasks/*.xml` |
| 6 Hunting | Phase 3 produced no EVTX CSVs (precondition unmet) |
| 7 CredAccess | Phase 3 produced no EVTX CSVs AND no MFT CSVs from Phase 1 |
| 8 AntiForensics | Phase 3 produced no EVTX CSVs (most signals are EID-based) |
| 9 IOC Extract | No prior phase produced any output (no input to consolidate) |
| 10 C2 Beacon | No IIS access logs found (raw `*.log` or Phase 5 IIS CSV) |
| 11 Browser | No browser SQLite DBs and no Zone.Identifier ADS in MFT |
| 12 Ransomware | Phase 1 produced no MFT CSVs |
| 13 WebServer | No IIS logs found AND no `inetpub/wwwroot/` |
| 14 Email | No `*.pst`, `*.ost`, or `*.mbox` under `${CASE_ROOT}` |
| 15 Linux | No mountable ext4 partition discovered — leave for Daedalus to handle if user has mounted manually |
| 16 CVE Attribution | `reports/investigation_report.md` does not exist yet (this is run after report generation) |
| 17 Attack Path | Neither `hunting_timeline.csv` nor `credaccess_timeline.csv` produced rows (no lateral movement to graph) |
| 18 Anomaly Check | No machine subdirectories exist under `analysis/` (no upstream phase output to cross-check) |
| 19 Memory | No memory image (`*.mem`/`*.raw`/`*.dmp`/`*.vmem`/`*.lime` ≥10MB) under `${CASE_ROOT}` |
| 20 PCAP | No `*.pcap`/`*.pcapng`/`*.cap` under `${CASE_ROOT}` |

If the agent skips a phase, it must record the skip in COP `Completed Analysis Phases` with
the reason — e.g., "Phase 14 — SKIPPED (no PST/OST/mbox in evidence inventory)". A skip is
not a failure and does not block downstream phases.

---

## Default Sequence (apply when no break conditions trigger)

This is the order to run when intake is straightforward: a Windows KAPE collection
(possibly with PST/OST/mbox or a Linux partition alongside). On evidence that doesn't fit
this profile, see "Sequencing for non-Windows-KAPE evidence" below.

The sequence is grouped into 5 layers. Within a layer, phases are independent and parallel-safe
(see §Parallel Execution for the gate). Across layers, every phase in layer N must complete
before any phase in layer N+1 starts.

### Layer 1 — Foundation (parallel-safe)

| Phase | Why it runs first |
|---|---|
| 1 NTFS | The MFT timeline anchors every later correlation. `$STANDARD_INFO` vs `$FILE_NAME` is the timestomping baseline. The USN journal is the only artifact that recovers names of deleted files. Start here so every subsequent finding can be timeline-anchored. |
| 2 Registry | Account context (SAM), software install timeline (SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, Amcache), persistence keys (Run/RunOnce/Services), shimcache execution evidence, and ShellBags folder traversal. Without registry context you cannot read 4624 events correctly because you don't know which SIDs are real. |
| 3 EventLogs | Hunting, CredAccess, AntiForensics, and AttackPath all read the EvtxECmd CSVs produced here. Run early. EvtxECmd with the full Maps library is the single most expensive parser in the pipeline — start it as soon as parallel I/O capacity exists. |
| 4 Artifacts | LNK + Jump Lists + Prefetch + Timeline give you user execution intent before you start hunting; Recycle Bin tells you what the user *thought* they deleted. |
| 5 Execution | IIS access logs (initial access vector), HTTPERR (probing), PowerShell history (interactive ops), Scheduled Tasks (persistence). Server-class artifacts that don't have prefetch coverage. |
| 19 Memory | Run **before Layer 1** if the memory capture timestamp falls inside the active attack window (per ISC Phase 0C temporal mapping). Live C2 connections, in-memory creds, and active implants take priority. Otherwise (memory predates attack or is for context only) run alongside Layer 1 disk parsers — it is independent. |
| 20 PCAP | Run alongside Layer 1 disk parsers — independent I/O path, different bottleneck. Network capture anchors timelines as well as MFT does, especially for attacks that left no on-disk artifact (in-memory only payloads, evasion of EDR). |

### Layer 2 — Domain analysis (parallel-safe within layer)

| Phase | Why it runs after Layer 1 |
|---|---|
| 6 Hunting | Reads Layer 1 EVTX CSVs to surface privesc + lateral movement events. Output (`hunting_timeline.csv`) is the lateral-movement seed for Phase 17. |
| 7 CredAccess | Reads Layer 1 EVTX + MFT CSVs to detect DCSync, LSASS access, Kerberoasting, and timestomping. Output (`credaccess_timeline.csv`) is the credential-theft seed for Phase 17. |
| 8 AntiForensics | Reads Layer 1 EVTX + Prefetch + Registry CSVs to detect log clearing, VSS deletion, Defender tampering. Run *after* hunting + credaccess so the agent can reason about which evidence the attacker tried to wipe in the same window as the malicious activity it covers. |
| 11 Browser | Reads Layer 1 MFT (for Zone.Identifier ADS) plus user profile SQLite DBs. Independent of hunting/credaccess outputs, but logically grouped here. |
| 12 Ransomware | Reads Layer 1 MFT CSVs to flag archive staging, ransom notes, and suspicious extensions. Independent of other Layer 2 phases. |
| 13 WebServer | Parses raw IIS W3C logs (or Phase 5 IIS CSVs) for injection attempts, LOLBin downloads, operator sessions, and webshells. The webshell inventory is the most common initial-access pivot. |

### Layer 2′ — Independent evidence types (run any time after Layer 1 starts)

These have no dependency on the Windows phases and can run as soon as the orchestrator
has spare CPU/disk capacity. They are grouped in Layer 2′ purely for readability.

| Phase | Notes |
|---|---|
| 14 Email | PST/OST → mbox via readpst → Python message + attachment parser. No deps on other phases. |
| 15 Linux | Mounts the Linux ext4 partition (losetup + mount -o ro,noload) and parses bash history, auth logs, cron, SSH keys. No deps on other phases. |

### Layer 3 — Consolidation

| Phase | Why it runs after Layer 2 |
|---|---|
| 10 C2 Beacon | Best run after IOC denylist is in scope (Phase 9 produces the master IOC list, but the denylist itself comes from `config/ioc_denylist.json` which is loaded at script time). Beacon scoring is more accurate when the IIS CSV is fully populated. |
| 9 IOC Extract | Reads **every** `analysis/**/*.csv` produced by phases 1–8 + 11–15. Run after all parsers are done so it consolidates a complete picture. |

> Note on ordering inside Layer 3: Phase 9 reads everything, so it must come last in this
> layer. Phase 10 only needs Phase 5 output (and the static denylist) and could technically
> run earlier, but running it after 9 lets the agent cross-reference beacon destinations
> against the just-built IOC master in the next decision step.

### Layer 4 — Synthesis

| Phase | Why it runs last |
|---|---|
| 17 Attack Path | Reads `hunting_timeline.csv` (Phase 6) + `credaccess_timeline.csv` (Phase 7) + per-machine Hunting CSVs + EID 4624 type 3/10 / EID 4648 from EventLogs. Produces the cross-machine attack graph (CSV + Markdown + Mermaid). |
| 18 Anomaly Check | Reads CSVs produced by Phases 1–13 + 19 + 20. Surfaces **contradictions between artifact sources** (Shimcache present + MFT absent → wipe; EVTX gap during attack window → log clearing; memory netscan IP not in disk EVTX → captured live; PCAP beacon not in IOC master → C2 only at network layer). Output `anomalies.csv` is the input to the self-correction loop. The most important "doesn't add up" detector in the pipeline. |

### Layer 5 — Self-Correction (optional but strongly recommended)

| Driver | Why it runs after Layer 4 |
|---|---|
| `run_self_correct.sh` | Reads `anomalies.csv` from Phase 18; for each HIGH-severity anomaly, picks a corrective action (re-run the upstream phase that should have caught it, with adjusted scope), executes it, re-runs anomaly detection, and verifies the count decreased. Hard cap of 3 iterations. Logs every iteration to `self_correction.jsonl` for the audit trail. This is the demonstrable "agent self-corrects in real time" mechanism. |

### Post-report — Intel ICS

| Phase | Why it runs after the report |
|---|---|
| 16 CVE Attribution | Reads `reports/investigation_report.md` + `analysis/cop.md`, calls the `claude` CLI with a focused CVE attribution prompt, and writes `analysis/cve_attribution.md`. After it completes, the ISC re-invokes `investigation-report` to integrate Section 3B. |

---

## Sequencing for non-Windows-KAPE evidence

If the evidence inventory does not match the Layer-1 Windows-KAPE profile, ignore the
default sequence and apply the appropriate sub-sequence.

### Linux-only evidence
Run **15** (Linux). Then **9** (IOC Extract — operates on Linux CSVs too). Skip 1–8, 10–13, 17. If a Linux web service log was collected (apache/nginx), the ISC may invoke the `linux-host` skill for deeper analysis after Phase 15.

### PST/OST/mbox-only evidence
Run **14** (Email). Then **9** (IOC Extract). Skip Windows phases. The ISC may invoke the `windows-artifacts` skill for header reasoning if the email artifact suggests host compromise.

### PCAP-only evidence
Run **20** (PCAP). Then **9** (IOC Extract — picks up beacon/DNS IOCs). Skip Windows
disk phases. The `network-analysis` skill is available for deeper protocol-level
investigation if Phase 20's output suggests a need.

### Memory-only evidence
Run **19** (Memory). Then **9** (IOC Extract — picks up netscan IPs and process names).
Skip Windows disk phases. If memory predates the attack window per ISC Phase 0C, treat
output as baseline only — do not weight in-memory state for live C2 inferences.

### Velociraptor offline-collection input

A Velociraptor offline collector zip is functionally equivalent to a KAPE collection —
both are zips of structured Windows artifacts. Drop the zip into
`<case_root>/incoming/<host>/collection.zip`, then either:

- **Manual unpack:** unzip into `<case_root>/<host>_Kape/` matching the KAPE directory
  layout (so SIFTics phase scripts find `$MFT`, `Windows/System32/winevt/Logs/*.evtx`,
  registry hives, etc.)
- **MCP-broker pull:** if a Velociraptor server is configured, the ISC may invoke
  `mcp_broker.tools.velociraptor.pull_offline_collection(client_id, output_path)` to
  retrieve the zip directly into `<case_root>/incoming/<host>/`. The
  `run_detect_hunt_loop.sh` orchestrator handles this.

After ingestion, run the standard Layer 1–4 phases on the unpacked collection.

### Cloud-only evidence (CloudTrail/GuardDuty/S3 logs)
No SIFTics phase script. Invoke `cloud-forensics` skill directly. Then **9** (IOC Extract)
if the cloud skill produces CSVs in `analysis/`.

### Mixed evidence
Run the Windows-KAPE default sequence and the independent evidence-type phases (14, 15)
in parallel where the Parallel Execution gate allows. Synthesize into the COP after all
parsers complete.

---

## Break Conditions (reorder when these findings appear)

A break condition is a finding from one phase that should change which phase runs next.
When a break triggers, the agent:
1. Records the deviation in COP `Next Actions` ("Break: [trigger] — running [phase] next").
2. Invokes the indicated next phase out of default order.
3. Resumes the default sequence after the out-of-order phase completes (do not skip the
   phase that would have run by default — defer it).

Below is the seed list. **[ANALYST EXTEND HERE]** marks where the analyst should add
break conditions from their own mental model — these reflect senior-analyst tells that
should never be hard-coded by an outsider.

### Layer 1 break conditions

| Trigger (found in phase) | Jump to | Reason |
|---|---|---|
| Phase 1 — `_F_Timestomping.csv` has any HIGH-confidence rows (set by `run_credaccess.sh` Section F when it runs against MFT) | Phase 7 CredAccess (run early, then continue Layer 1 phases that haven't run) | Timestomping is one of the most reliable indicators of attacker presence. If MFT shows HIGH-confidence timestomping in Layer 1 output, prioritize the credential-access investigation that frames the timestomp window. |
| Phase 1 — USN Journal (`*_J.csv`) shows attack-window-period mass file deletions (>500 deletes in <60s) | Phase 12 Ransomware (run early to characterize) | Mass deletes are the classic ransomware-or-wiper signal. Confirm before proceeding to slower phases. |
| Phase 2 — RegBack hives diverge from current SYSTEM/SOFTWARE hives in the attack window | Phase 8 AntiForensics (run early) | RegBack divergence often correlates with persistence-key tampering — anti-forensics phase will catch the EID 1102 / Defender tampering that usually accompanies it. |
| Phase 3 — EVTX shows EID 1102 (Security log cleared) within the attack window | Phase 8 AntiForensics (run immediately) | Log clearing is a hostile act. Run AntiForensics now to characterize the gap and what the attacker tried to hide. |
| Phase 4 — Prefetch shows known anti-forensic tool names (sdelete, cipher /w, eraser, ccleaner) | Phase 8 AntiForensics (run immediately) | Same logic as above — characterize wipe scope before continuing. |
| Phase 5 — IIS logs show known exploit signatures (Log4Shell, ProxyLogon, ProxyShell, CVE-2017-5638) | Phase 13 WebServer + Phase 10 C2 Beacon (run both early) | Initial access vector is now likely IIS-borne. Webserver phase finds the webshell; beacon phase finds the C2 callback. Pivot before continuing the default sequence. |
| Phase 5 — PowerShell history shows base64-encoded commands or `IEX` against a remote URL | Pivot to `yara-hunting` skill on the decoded payload, then continue | Encoded PS is high-signal for hands-on-keyboard ops. Confirm classification before broader hunting. |
| **[ANALYST EXTEND HERE]** | | |

### Layer 2 break conditions

| Trigger | Jump to | Reason |
|---|---|---|
| Phase 6 — `hunting_timeline.csv` shows lateral movement to a machine NOT in evidence inventory | ISC scope-expansion review | Add the new machine to COP `Possible scope expansion` (or in-scope if evidence is present), per ISC Scope Management section. |
| Phase 7 — DCSync detected on a non-Domain-Controller account | ISC review + Phase 17 Attack Path early | Non-DC DCSync = privilege escalation against the domain. Run attack path now to map who held the credentials before they were used. |
| Phase 7 — LSASS access by a non-system process | Pivot to `memory-analysis` skill if a memory image exists for that machine in the same window | The dump may still be in memory; live evidence beats reconstruction. |
| Phase 8 — VSS deletion + ransom-note pattern from Phase 12 | Treat as ransomware case; prioritize Phase 12 + Phase 9 IOC Extract for note hash-set | The COP severity should be elevated immediately. |
| Phase 11 — MotW stripped from a binary present in Prefetch | Flag in COP; pivot to `yara-hunting` on that binary | Stripped MotW + execution is a classic delivery-chain marker. |
| Phase 13 — Webshell inventory has any rows | ISC pivot per Cross-Skill Pivot Protocol (`webshell confirmed`) — check Sysmon EID 1 for `w3wp.exe` children + cross-ref `lolbin_downloads.csv` | This is the most common initial-access pivot in IIS cases. |
| **[ANALYST EXTEND HERE]** | | |

### Layer 3 / 4 break conditions

| Trigger | Jump to | Reason |
|---|---|---|
| Phase 9 — `ioc_master.csv` contains any IP that resolves into a known C2 family (compare to threat intel feeds the analyst has loaded) | ISC pivot to `yara-hunting` for matching family rules | Family-level attribution before report. |
| Phase 10 — Any IP scored BEACON_LIKELY (score ≥ 70) and not in denylist | ISC pivot per Cross-Skill Pivot Protocol (`new external IP`) | Cross-ref with EVTX EID 5156 / Sysmon EID 3 for matching outbound connections; record as CONFIRMED if found. |
| Phase 17 — Attack path graph shows lateral movement to a machine without Layer 1 phases run | Loop back to Layer 1 for the new machine | Scope expanded mid-pipeline; do not close the case until the new machine is triaged. |
| **[ANALYST EXTEND HERE]** | | |

### Re-run conditions

A phase may be re-run when its inputs have changed. The phase script's own self-skip
guard (completion-signal check) will block a no-op re-run, so the agent must explicitly
delete the completion signal or pass a force flag.

| Phase | Re-run when | How |
|---|---|---|
| 9 IOC Extract | A later phase produced new analysis CSVs that weren't in `analysis/` when 9 first ran | `rm "${CASE_ROOT}/analysis/ioc_master.csv"` then re-invoke |
| 10 C2 Beacon | Denylist (`config/ioc_denylist.json`) was updated mid-case to add infrastructure, OR `--no-denylist` is needed for a follow-up scan | Re-invoke with `--no-denylist` flag, write to a separate output |
| 17 Attack Path | A new machine was added to scope (Layer 2 break), and Phases 6/7 re-ran for it | `rm "${CASE_ROOT}/analysis/attack_path.csv"` then re-invoke |
| 16 CVE Attribution | The investigation report was regenerated after Section 3B integration | `rm "${CASE_ROOT}/analysis/cve_attribution.md"` then re-invoke |

---

## Pivot Triggers

Pivot triggers are findings that cause the ISC to invoke a **domain skill** (not another
SIFTics phase). They are documented in full in `investigation-section-chief/SKILL.md` under
`Cross-Skill Pivot Protocol` — this skill will not duplicate that table. The agent
applies that table after each phase's COP update.

The most common between-phase pivots:

| Phase output | Pivot to skill |
|---|---|
| Phase 7 LSASS access confirmed | `memory-analysis` (if memory image exists in same window) |
| Phase 8 PE/MZ binary recovered from suspicious path | `malware-analysis` then `yara-hunting` |
| Phase 9 IOC master populated with unfamiliar hashes | `yara-hunting` against the hash list |
| Phase 13 Webshell confirmed | `windows-artifacts` (Sysmon EID 1 for w3wp.exe children) |
| Phase 17 Cross-machine path includes a host with no KAPE | `edr-telemetry` or `sleuthkit` if any disk image exists |

---

## Parallel Execution

Default behavior is **sequential** — one phase at a time. The default sequence is
already tuned to overlap I/O-bound phases with CPU-bound phases at the layer level, so
sequential execution is not a major performance loss.

Run multiple phases in parallel **only** when all of the following hold:
1. Both phases are in the same layer (no inter-phase dependency).
2. Total disk I/O is not saturated. SIFTics evidence is typically on a single ESXi-style
   disk image — disk seek contention is the bottleneck. Two parallel parsers reading the
   same physical drive will rarely beat one parser at a time.
3. The two phases write to different output subdirectories (no `analysis/<MACHINE>/` write
   collision). The Phase Catalog confirms this for all in-layer pairs.
4. The agent has explicit budget to monitor both — running 5 phases in parallel and ignoring
   their output until they all finish is anti-pattern. Pair phases at most.

When the conditions hold, invoke with bash backgrounding and `wait`:

```bash
bash "${SIFTICS_HOME}/scripts/run_eventlogs.sh" "${CASE_ROOT}" &
bash "${SIFTICS_HOME}/scripts/run_artifacts.sh" "${CASE_ROOT}" &
wait
```

Pairs that benefit most from parallelism:
- **Phase 3 (EventLogs) + Phase 1 (NTFS):** EvtxECmd is CPU-bound after the first read; MFTECmd is I/O-bound. Different bottlenecks, modest speedup.
- **Phase 14 (Email) + any Layer 1:** PST parsing is independent of Windows phases.
- **Phase 15 (Linux) + any Layer 1:** Linux partition mount + parsing is on a separate filesystem from the Windows drive roots.

Pairs that should NOT run in parallel:
- Two Windows-phase parsers reading the same KAPE drive root simultaneously.
- Phase 9 (IOC Extract) with anything — it reads `analysis/**/*.csv` and may race with
  another phase's writes.
- Phase 17 (Attack Path) with anything — it consolidates and should run alone.

---

## Progress Tracking

The agent tracks progress through three sources:

1. **The completion signal** for each phase (Phase Catalog table). This is authoritative —
   if the file exists with data, the phase is done.
2. **`analysis/forensic_audit.jsonl`** — every command logged by every phase script. Use
   `bash "${SIFTICS_HOME}/scripts/audit_query.sh" --tool <script_name>` to find prior runs.
3. **The COP `Completed Analysis Phases` section** — narrative summary of what each phase
   produced. The agent updates this after each phase completes.

If a phase script exits non-zero but its completion signal file exists with data, treat
the phase as **done with errors** — log the exit code in COP and continue. Do not retry
unless the completion signal is missing or empty.

If a phase script exits zero but the completion signal file is absent, treat the phase as
**inconclusive** — likely the phase had no input (matches a Skip rule) but the script
didn't recognize it. Manually evaluate whether the Skip rule applies and record in COP.

---

## How this skill replaces `run_all.sh`

`run_all.sh` did three things:
1. Discover machines and check completion signals → now done by the agent reading the
   Phase Catalog above and probing the filesystem.
2. Sequence phases in a fixed order → now done by the agent applying the Default
   Sequence + Break Conditions in this skill.
3. Tee a run log and tally per-phase status → now done by `analysis/forensic_audit.jsonl`
   (per-command granularity) plus COP `Completed Analysis Phases` (per-phase narrative).

There is no `run_all.sh` anymore. The agent **is** the orchestrator. This skill is its
playbook.

For deterministic re-execution (benchmark scenarios where the agent should not deviate
from the fixed sequence), invoke each phase script directly in numerical order from the
Phase Catalog. The phase scripts' self-skip guards make this idempotent — re-running on
a fully-analyzed case is a no-op.

---

## Output Paths

| Artifact | Path |
|---|---|
| Per-phase audit log | `${CASE_ROOT}/analysis/forensic_audit.jsonl` |
| Per-phase plaintext log (legacy) | `${CASE_ROOT}/analysis/commands.txt` |
| Cross-machine timelines | `${CASE_ROOT}/analysis/{hunting,credaccess,antiforensics}_timeline.csv` |
| IOC master | `${CASE_ROOT}/analysis/ioc_master.csv` |
| Attack path graph | `${CASE_ROOT}/analysis/attack_path.{csv,md,mermaid}` |
| CVE attribution | `${CASE_ROOT}/analysis/cve_attribution.md` |
| Common Operating Picture | `${CASE_ROOT}/analysis/cop.md` |
