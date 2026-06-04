---
name: triage-methodology
description: Phase sequencing + decision engine. Replaces a static run_all.sh with ITQ-driven phase selection.
---

# Triage Methodology

The classic "run all phases in order" approach (`run_all.sh`) is wrong for IR.
Cases differ wildly — a ransomware incident needs different phases first than a
credential-dumping incident or a webshell. This skill encodes which phase to
run, when, based on the Initial Triage Questionnaire (ITQ).

## The map — ITQ category → phase script

| ITQ category (questions) | Phase scripts in priority order |
|---|---|
| `scope` (ITQ-001..005) | answered by IC; agent records into case header |
| `platform` (ITQ-010..016) | (no script — derived from evidence file types and case header) |
| `logs` (ITQ-020..026) | `run_eventlogs.sh` · `run_anti_forensics.sh` (specifically for log clearing) |
| `ownership` (ITQ-030..035) | IC-driven |
| `tooling` (ITQ-040..043) | agent surveys what's installed; reports gaps |
| `business_impact` (ITQ-050..053) | informed by ASR / CET findings as the case progresses |
| `containment` (ITQ-060..064) | `run_artifacts.sh` · `run_execution.sh` · `run_credaccess.sh` |
| `communication` (ITQ-070..074) | IC-driven |

**Note — network/pcap evidence:** When the evidence set contains pcap, pcapng,
or network flow files, see the **Network/pcap evidence** section below. The
network hot-path runs before Windows host phases when both evidence types are
present.

## Hot-path-first ordering

When you start a case:

1. **`fast_evtx_attack_filter`** (HOT) — < 30 s for the last 24h of EVTX.
   Identifies obvious attack indicators (process creation, service install,
   credential access).
2. **`fast_persistence_scan`** (HOT) — < 10 s. Diff registry persistence
   keys + services + scheduled tasks against `mcp_baseline`. Anything not in
   baseline becomes a candidate.
3. **`fast_execution_timeline`** (HOT) — last 4 hours of MFT + Prefetch +
   Amcache + Sysmon-1 events, deduplicated.
4. **`classify_binary` fan-out** on each surface binary — Rathbun baseline,
   imphash via abuse.ch MalwareBazaar, capa behavioural tags, RAG matches to
   ATT&CK.

Only after HOT findings stabilise should you reach for WARM (targeted EZ
Tools usage) or COLD (full Plaso super-timeline, Volatility full image).

## Escalation rules — when to move from HOT → WARM → COLD

- HOT confirms persistence + execution → WARM on identified hosts: pull
  full process tree, full PowerShell transcripts, registry hive snapshot.
- WARM disagrees with HOT (e.g., Sysmon shows a process, but MFT doesn't
  show the binary on disk) → **automatic Phase 18 escalation**. Run
  `run_anomaly_check.sh`; if contradictions remain, surface to IC.
- IC declares "legal hold" or "regulatory hold" → COLD on every affected
  host regardless. Document the declaration in the case header.

## When to propose an Authority Gate

You should request IC approval (`ic_request_approval`) when you reach one
of these decision points:

1. **Fleet-wide hunt for IOCs you found locally.** This is the
   `execute_hunt_package` gate. The IC's question is: "do you have enough
   confidence to ask 50+ other hosts about these IOCs?"
2. **Cold-path on a specific host.** This is the `escalate_to_cold` gate.
   The IC's question is: "is this host important enough to spend hours of
   compute on?"
3. **Network isolation of a host.** This is the `isolate_host` gate. The
   IC's question is: "are we sure enough to interrupt user activity?"

When in doubt, **propose the gate**. The cost of an over-cautious
proposal is one extra IC click. The cost of an over-bold action is
unbounded.

## When to stop

You stop a case when one of these is true:

- All ITQ questions are answered (`itq_progress()['answered'] == total`)
  AND no ASR row is `not_safe` AND no CET row is `pending`.
- The IC explicitly says "close" via `case_update_header({"status": "closed"})`.
- The Hypothesis Engine reports `confidence > 0.9` on a single theory AND
  all related ITQ questions are answered.

Do not stop just because findings have plateaued for 30 minutes. The Hypothesis
Engine's signal scoring should drive that decision — not the absence of new
findings, which often just means you're not looking in the right place yet.

---

## Network/pcap evidence — hot-path, identity-token extraction, and victim identification

This section applies when the evidence set contains any pcap, pcapng, or
network flow file (NFCAP, Zeek conn.log, Suricata eve.json). It has equal
standing with the Windows host-artifact hot-path above.

### Extended ITQ category table — network row

| ITQ category | Phase action |
|---|---|
| `network` — evidence enumeration | Enumerate all pcap/flow files; record in case header scope (ITQ-080 equivalent). |
| `network` — identity extraction | Extract all session-layer identity tokens before any hypothesis is opened. |
| `network` — anonymous services | Check whether any flow contacted a known anonymous email/communication service. |
| `network` — HTTP POST bodies | Carve POST bodies when trigger conditions below are met. |
| `network` — victim identification | Identify victim from RCPT TO, POST body destination, or carved message content. |

The network category is **not optional** when pcap is present. It runs before
any hypothesis is opened. Reason: session-layer identifiers (cookies, POST
bodies, SMTP headers) are the cheapest evidence to collect and the easiest
to miss if a working theory forms first.

### Network hot-path ordering

When pcap or network flow files are present, run these steps **before**
`fast_evtx_attack_filter` (or as the entire hot-path if no Windows host
artifacts exist):

**Step N-1 — identity-token extraction (MANDATORY, HOT)**

Before calling `hypothesis_score add` for the first time, perform an
exhaustive pass over all session-layer identifiers in the pcap. Extract and
record every distinct value found in:

- HTTP `Cookie:` and `Set-Cookie:` headers (full cookie string)
- HTTP form POST bodies — all field names and values
- SMTP `MAIL FROM:`, `RCPT TO:`, `X-Originating-IP:` headers
- DNS PTR/A responses (map every layer-3 IP to its resolved hostname)
- Any header containing an email address or username token

Write every token as a finding note in the ASR or case notes before
proceeding. Do not filter or deduplicate before recording — deduplication
happens at analysis time.

**This step must complete before the Hypothesis Engine is called.** This
overrides the hypothesis-engine.md directive "open a hypothesis the moment
you have a coherent story" — for network cases, token extraction takes
precedence over early hypothesis opening.

*Nitroba example:* `jcoach@gmail.com` in HTTP Cookie fields and
`badguy@hotmail.com` in HTTP POST bodies are both identity tokens. Both
must be recorded before any theory about sender identity is scored.

**Step N-2 — flow summary (HOT)**

Summarise all flows (src_ip, dst_ip, dst_port, bytes, timestamps). Flag any
IP that contacted a known anonymisation service (Tor exit nodes via mcp_cti,
or anonymous email services such as Guerrilla Mail, Mailinator, 10minutemail,
AnonEmail). Note: `mcp_rag/anon_email_providers.json` is aspirational — if
absent, use mcp_cti for Tor and manually note any anonymous email services
observed in DNS queries or HTTP Host headers.

**Step N-3 — HTTP POST body carving (HOT when triggered)**

Run HTTP POST body carving when **any one** of these triggers fires:

| Trigger | Action |
|---|---|
| Any flow contacted a known anonymous email service | Carve all HTTP streams in that flow's 30-minute window |
| Any identity token is a cookie containing an email domain not matching the organisation's own domain | Carve all streams sharing that src_ip |
| Case involves threat, harassment, extortion, or anonymous communication | Carve as mandatory step N-3 (not optional) |
| Any SMTP flow is present | Carve and extract SMTP MAIL FROM / RCPT TO / message body |

Carving must extract: full POST body, destination URL, Content-Type, and
any email addresses or free-text message content found in the body.

**Note on tooling:** `run_identity_token_extract.sh`, `run_http_carve.sh`,
and `run_flow_summary.sh` are not yet implemented in `phases/`. Until they
exist, perform these steps manually using tshark, Wireshark, or equivalent
tools already on the SIFT workstation. Document each command run and its
output in the case notes so the audit trail is preserved.

### Mandatory victim/target identification (Rule PCAP-3)

**Victim identity is a prerequisite gate.** No case phase may be marked
complete and no Authority Gate for external reporting may be proposed until
the victim has been identified or explicitly declared unrecoverable.

Answer this before any external-reporting Authority Gate:
```
itq_answer("ITQ-085", "<victim identity or 'unknown — sources consulted: RCPT TO, POST body, carved content'>", source="agent")
```

If ITQ-085 does not exist in the seeded grid (it may not in older cases),
record the victim identity in a briefing with the heading **VICTIM IDENTITY:**
and note it as an open item in the case header until it can be formally added.

Typical evidence sources: SMTP `RCPT TO:`, HTTP POST body destination fields
(`to=`, `recipient=`, `email=`), free-text in carved POST bodies.

Do not declare victim unknown until steps N-1 through N-3 above have all run.

### Shared-medium null hypothesis (required for all network cases)

Before the first `hypothesis_score add` call, assess whether the network
origin is a shared medium (open WiFi, campus network, NAT gateway, hotel WiFi,
or any environment where the IP does not map one-to-one to a physical person).

If yes: open the attribution-uncertainty hypothesis as required by
hypothesis-engine.md Rule 2 before scoring any other hypothesis.

This is not optional. The open WiFi / shared NAT scenario is the most common
defence against IP-based attribution and must be addressed explicitly in the
hypothesis ledger, not assumed away.
