# CLAUDE.md — [CASE NAME]

> **How to use:** Copy this file to the case root directory (`/cases/<case_name>/CLAUDE.md`).
> Fill in every field you know at case start. Partial information is fine — leave unknowns
> blank rather than guessing. Claude reads this file automatically when working in the case
> directory and uses it to ground all analysis decisions.

---

## Roles (NIMS ICS)

**You — the analyst named below — are the Incident Commander (IC).** You hold authority
over scope, resource allocation, chain-of-custody calls, threat-actor attribution,
customer deliverables, and case closure.

**The agent operates as your Investigation Section Chief (ISC)** — the role NIMS defines
for the section that conducts the investigation under the IC's authority. The ISC has
significant tactical autonomy: it sequences phases, picks which skills to invoke, and
synthesizes findings without check-ins. It does **not** unilaterally decide:

- Whether to escalate to a forensic-track engagement when intake hashes mismatch
  (in IR, the ISC notes the gap and continues — this is not criminal forensics)
- Scope expansion to a machine outside this brief
- Case closure
- Operational period extension beyond 4 periods
- Threat-actor naming in the report
- Customer-facing deliverable approval

These are recorded in the COP under "Decisions Pending IC Review" for your ratification at
each operational period boundary. The ISC does not pause analysis waiting for your input —
it logs the recommendation and continues.

See `~/.claude/skills/investigation-section-chief/SKILL.md` for the full Authority Gates
table.

---

## Case Identification

| Field | Value |
|-------|-------|
| Case ID / Name | |
| Case Type | (ransomware / APT / BEC / insider / web compromise / cloud / other) |
| Client / Organization | |
| Reported (UTC) | |
| Analyst | |
| Case Root | `/cases/<case_name>` |

---

## Attack Window

The most important temporal anchor for all analysis. Be as specific as possible.

| Boundary | UTC Timestamp | Confidence | Source |
|----------|--------------|-----------|--------|
| Earliest known compromise | | (High / Med / Low) | |
| Latest known attacker activity | | (High / Med / Low) | |
| Detection / containment | | | |

**How reported / detected:** [Brief description — e.g. "EDR alert on LSASS dump", "user reported encrypted files", "SOC flagged unusual outbound traffic"]

---

## Machines in Scope

| Hostname | Role | OS | Evidence Path | Evidence Type | Status |
|----------|------|----|--------------|---------------|--------|
| | | | `/cases/<case_name>/` | KAPE / memory / disk image | Not analyzed |

**Possible scope expansion (not yet confirmed):** [Any machines lateral movement may have touched but evidence not yet collected]

---

## Known IOCs (going in)

Seed IOCs the investigator knows before analysis starts. Claude will use these as pivot anchors.

| Type | Value | Confidence | Source |
|------|-------|-----------|--------|
| IP | | | |
| Domain | | | |
| File hash (SHA256) | | | |
| File name / path | | | |
| User account | | | |
| Email address | | | |

---

## Investigator Context

Information the human investigator has that may not appear in artifacts. Fill in as much as you know.

**Reported symptoms:**
- [What the client described — e.g. "files encrypted on file server", "admin account locked out", "unusual scheduled task found by sysadmin"]

**Suspected threat actor / campaign:**
- [If known — e.g. "suspected Akira ransomware affiliate", "possible nation-state", "unknown"]

**Affected services / business impact:**
- [e.g. "ERP system down", "domain controllers unreachable", "customer data potentially exfiltrated"]

**Prior IR history:**
- [Any previous incidents, related alerts, or relevant security posture — e.g. "no EDR on workstations", "MFA not enforced for VPN"]

**What containment has already occurred:**
- [e.g. "DC01 isolated from network", "compromised account password reset", "nothing yet"]

---

## Evidence Integrity — Intake Hashes

The collecting party should provide SHA256 hashes at intake when available. If no intake hashes are available or a hash mismatches, document the gap — the ISC records it in the Common Operating Picture (COP) and tags downstream findings on the affected evidence with `coc_gap=true`. **This is IR, not criminal forensics — the ISC does not halt analysis on a hash mismatch.** Speed against the attacker outweighs prosecution-grade rigor; if the case needs to escalate to a forensic-track investigation, the IC makes that call.

| File | SHA256 (from collector) | Verified by analyst |
|------|------------------------|---------------------|
| | | ☐ |
| | | ☐ |

---

## Evidence Inventory

| Source | Type | Path | Captured (UTC) | SHA256 |
|--------|------|------|---------------|--------|
| | KAPE | | | |
| | Memory image | | | |
| | PCAP | | | |
| | Cloud logs | | | |

---

## Analysis Notes

[Running notes the investigator wants Claude to keep in mind throughout the case — hypotheses, dead ends, stakeholder constraints, anything not captured above]
