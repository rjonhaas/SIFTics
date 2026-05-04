# CLAUDE.md — [CASE NAME]

> **How to use:** Copy this file to the case root directory (`/cases/<case_name>/CLAUDE.md`).
> Fill in every field you know at case start. Partial information is fine — leave unknowns
> blank rather than guessing. Claude reads this file automatically when working in the case
> directory and uses it to ground all analysis decisions.

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

The collecting party must provide SHA256 hashes at intake. If no intake hashes are available, document this gap explicitly — the IC skill will record a chain-of-custody warning in the COP.

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
