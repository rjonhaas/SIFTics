---
name: reporting-conventions
description: What makes a complete ITQ answer, briefing standards, MITRE mapping conventions, and final report structure
---

# Reporting Conventions

This skill defines what "done" looks like for every output the ISC produces:
ITQ answers, briefings, and the final report. Consistent, complete outputs
are what allow the IC and future reviewers to trust and act on the findings.

---

## ITQ answer completeness

An ITQ answer is complete when it meets all three criteria:

1. **Answers the question directly.** The first sentence states the answer,
   not the method. "The earliest observed activity was 2015-09-02T08:50Z" is
   complete. "I ran the Apache access log analysis and found..." is not.

2. **Cites the artifact.** Every factual claim includes its source.
   "Apache access.log confirms first SQLi attempt at 08:50Z" is citable.
   "The investigation found the attack started in September" is not.

3. **States confidence.** When the answer is based on incomplete evidence or
   indirect inference, say so explicitly:
  - *High confidence* - directly evidenced by two or more independent artifacts
  - *Medium confidence* - one artifact, corroborated by circumstantial evidence
  - *Low confidence* - inference from indirect evidence; single source; or the
     primary source has tamper risk

**For N/A answers:** A training exercise, offline case, or inapplicable question
still needs a reason. "N/A - offline forensic case; no live EDR applicable" is
complete. "N/A" alone is not.

**For unanswerable questions:** "Cannot determine from available evidence - 
sources consulted: Security.evtx (cleared), Prefetch (absent on Server SKU),
memory (not available)" is complete. Stating what was checked and came up empty
is forensically meaningful.

---

## Briefing standards

### When to post a briefing

- After every 2–3 phases of investigation
- Immediately after any material finding (new attack vector, confirmed
  exfiltration, attacker identity)
- When the investigation is paused for IC direction (authority gate pending)
- At the end of each evidence category (disk triage complete, log analysis
  complete, memory analysis complete)
- As the final case summary before closure

### Briefing structure

Every briefing should contain these sections, in order:

```markdown
# [Briefing title] - [case name]

**Posted:** [UTC timestamp] | **Author:** Investigation Section Chief
**Phase:** [what phase of the investigation this covers]

---

## Summary
One paragraph. What was done, what was found, what it means. Written for an
IC who has not read the previous briefing. Do not assume prior context.

## Key findings
Bullet list. Each bullet: [finding_id if applicable] - one sentence claim - 
confidence level.

## MITRE ATT&CK
Table mapping confirmed techniques to evidence. Only include what is evidenced.

## Outstanding questions / next steps
What remains unanswered and what evidence would answer it.
```

### What does NOT belong in a briefing

- Raw tool output - that belongs in `finding_record()` output_excerpt
- Speculation without labeling it as such
- Summaries of previous briefings (the IC has those)
- Hedging language that obscures the finding ("it appears that perhaps...")

---

## MITRE ATT&CK mapping conventions

Map to the most specific technique available. Prefer sub-techniques over parent
techniques when evidence supports it.

**Map what you have evidence for, not what is plausible.** If you found sqlmap
in the UA and `INTO OUTFILE` in the log, map T1190 and T1505.001. Do not also
add T1059 without evidence of direct command execution via that vector.

**Format for MITRE entries in a briefing:**

| Technique | Sub-technique | Evidence | Confidence |
|---|---|---|---|
| T1190 | - | sqlmap UA in access log; `UNION SELECT` payloads in URI | High |
| T1505 | T1505.003 Web Shell | phpshell.php, c99.php found in web root | High |
| T1136 | T1136.001 Local Account | cmdscan: `net user <name> <pass> /add` | High |

**Common technique reference:**

| Technique ID | Name | Typical evidence |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Web server logs, error logs, SQLi payloads |
| T1059 | Command and Scripting Interpreter | cmd.exe, PowerShell, bash, python in logs/memory |
| T1059.006 | Python | python/urllib in UA, `.py` scripts on disk |
| T1505.003 | Web Shell | PHP/ASPX files in web root with exec functions |
| T1505.001 | SQL Stored Procedures | `INTO OUTFILE` in DB logs or web logs |
| T1136.001 | Create Local Account | `net user /add` in cmdscan, SAM hive new entries |
| T1021.001 | Remote Desktop Protocol | `netsh` RDP rule, RDP EVTX events, Security Group add |
| T1562.004 | Disable or Modify System Firewall | `netsh firewall` or `netsh advfirewall` in command history |
| T1070 | Indicator Removal | Log clearing EIDs, secure deletion tools, wevtutil |
| T1070.006 | Timestomp | SI/FN timestamp divergence |
| T1070.001 | Clear Windows Event Logs | EID 1102/104, RecordID reset |
| T1048 | Exfiltration Over Alternative Protocol | USB, optical media, cloud storage |
| T1567 | Exfiltration Over Web Service | Google Drive, Dropbox, OneDrive |
| T1078 | Valid Accounts | Attacker used legitimate credentials |

---

## finding_record vs briefing vs ITQ answer

| Content type | Where it goes |
|---|---|
| Raw tool output, exact artifact path, exact command | `finding_record()` |
| Factual claim answering a specific triage question | `itq_answer()` (cites finding_id) |
| Narrative explaining how findings fit together | `briefing_post()` |
| IOC suitable for detection or sharing | `generate_ioc()` |
| Structural case metadata (scope, impact, status) | `case_update_header()` |

A finding does not need to appear in all four places. A `finding_record()` and
an `itq_answer()` that cites it is sufficient for most facts. Only promote
findings to a briefing when they require narrative context to be meaningful.

---

## Final report quality checklist

Before marking a case complete, verify:

**Coverage:**
- [ ] All 43 ITQ questions answered (check `itq_progress()`)
- [ ] Every confirmed attack phase has at least one `finding_record()` with
  artifact, tool, command, and output
- [ ] Every MITRE technique is evidenced by at least one finding_record
- [ ] No ASR row is `not_safe` without a documented reason
- [ ] Anti-forensics activity (if any) is documented with tool, time, account

**Accuracy:**
- [ ] All timestamps are in UTC
- [ ] All email addresses, IPs, and account names are cited to a specific artifact
- [ ] Confidence levels are assigned to every factual claim
- [ ] Null hypothesis explicitly addressed and either confirmed or refuted

**Completeness:**
- [ ] Outstanding evidence gaps documented (what you couldn't determine and why)
- [ ] Legal actions required (subpoenas, preservation letters) identified
- [ ] Recommended eradication steps documented
- [ ] MITRE ATT&CK table covers the full kill chain from initial access through objective

---

## Confidence labeling guide

Use consistent language across all outputs:

| Label | Meaning | Use when |
|---|---|---|
| **Confirmed** | Two or more independent artifact sources agree | Hash in baseline AND Prefetch; two EVTX events for same action |
| **High confidence** | One strong artifact source, not easily manipulated | FN timestamp; kernel-written log entry; memory string with full context |
| **Medium confidence** | One artifact source with some tamper risk, or indirect inference | SI timestamp; single EVTX entry; access log entry (can be spoofed) |
| **Low confidence** | Circumstantial; one weak source; inference chain with multiple steps | Absence of evidence; user-writable log; behavioral inference |
| **Unconfirmed** | Hypothesis without direct artifact support - clearly labeled as such | "Suspected but not evidenced in available artifacts" |

Never present a low-confidence finding as confirmed. If the IC needs to act on
a low-confidence finding, label it clearly so they understand the risk.
