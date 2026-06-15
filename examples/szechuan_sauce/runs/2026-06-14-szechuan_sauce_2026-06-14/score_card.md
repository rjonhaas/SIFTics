# DFIR Madness Stolen Szechuan Sauce - Score Card

Run: `2026-06-14-szechuan_sauce_2026-06-14`
Case directory in SIFT VM: `/cases/szechuan_sauce_2026-06-14`
Model: `claude-sonnet-4-6`
Run window: `2026-06-14T23:16:15Z` to `2026-06-15T00:40:39Z`
Answer key used for post-run scoring only: host-side answer-key directory
outside the SIFT VM

The answer key was not copied into the SIFT VM. The agent analyzed only real
evidence artifacts under the case `evidence/` directory.

## Run Artifacts

| Artifact | Path |
|---|---|
| Hash-chained execution log | `forensic_audit.jsonl` |
| Evidence findings | `findings.jsonl` |
| Affected Systems Register | `suit.jsonl` |
| Lines of Inquiry storage | `grid.jsonl` |
| IOC drafts | `intel.jsonl` |
| Evidence manifest | `evidence_manifest.json` |
| Evidence quicklook | `evidence_quicklook.md` |
| Briefings | `briefings/` |

Audit-chain verification on the copied run: `PASS`.

## Output Counts

| Output | Count |
|---|---:|
| Evidence findings | 18 |
| ASR writes | 3 |
| ASR current rows | 2 |
| Lines of Inquiry checks | 43 |
| Resolved inquiry checks | 7 |
| Briefings | 2 |
| Draft IOCs | 4 |
| Pending Authority Gates | 1 |
| Audit events | 61 |
| LLM calls recorded | 1 |
| Recorded Sonnet 4.6 cost | $6.944945 |
| Output tokens | 9,602 |
| Cached read tokens | 28,556,178 |
| Cached creation tokens | 809,725 |

## Accuracy Summary

This score card compares the final durable SIFTics output against the DFIR
Madness public answer key.

| Category | Count |
|---|---:|
| Answer-key checks reviewed | 29 |
| Hits | 15 |
| Partials | 7 |
| Misses | 7 |
| Corrected false positives | 1 |
| Uncorrected false positives in final COP | 0 |
| Uncorrected hallucinations in reviewed findings | 0 |

Exact-hit recall: 15 / 29 = 51.7%
Hit-or-partial coverage: 22 / 29 = 75.9%

The major self-correction was F-017, which superseded F-011. The agent first
misread a large OneDrive flow as exfiltration, then corrected it with directional
PCAP analysis: the 36 MB flow was inbound to DESKTOP-SDN1RPT, not an upload.
ASR-2 was then updated by operator review so the Common Operating Picture no
longer repeats the corrected claim.

## Ground Truth Comparison

| Answer-key check | SIFTics output | Score | Notes |
|---|---|---|---|
| Server OS is Windows Server 2012 | ITQ-010, ASR-1 | Hit | Identified CITADEL-DC01 as Windows Server 2012 R2. |
| Desktop OS is Windows 10 | ITQ-010, ASR-2 | Hit | Identified DESKTOP-SDN1RPT as Windows 10 x64. |
| Server local time / timezone issue | Not resolved | Miss | Time-offset issue was not fully characterized. |
| Breach occurred | ASR-1, ASR-2, briefings | Hit | Two compromised systems recorded as critical/not_safe. |
| Initial entry vector: external RDP brute force | F-001 | Partial | External RDP from 194.61.24.102 found; Hydra/brute-force detail not fully proven in finding. |
| Malware used | F-005, F-006, F-007, F-012, F-013 | Hit | coreupdater service, Meterpreter getsystem, PowerShell stager, and C2 recorded. |
| Malicious DC process: coreupdater/spoolsv migration | F-005, F-006, F-007 | Partial | coreupdater and Meterpreter service activity found; spoolsv migration not conclusively recorded. |
| Payload delivered by 194.61.24.102 | F-002, F-004 | Hit | HTTP GETs for coreupdater.exe from 194.61.24.102 on both hosts. |
| Malware calls to 203.78.103.109 | F-012, F-018 | Hit | PCAP and memory socket artifacts recorded. |
| Malware path on disk | F-005, F-006 | Hit | `C:\Windows\System32\coreupdater.exe`. |
| Malware moved from Downloads to System32 | Not resolved | Miss | Final output did not reconstruct move path. |
| Persistence installed | F-005, F-007 | Partial | Service persistence found; registry persistence on both hosts not fully enumerated. |
| Malicious IPs 194.61.24.102 and 203.78.103.109 | F-001, F-002, F-004, F-012 | Hit | Both roles identified. |
| Known adversary infrastructure | CTI lookups, F-012 | Partial | CTI lookups were performed, but public hostile-history context was not confirmed. |
| Lateral movement to Desktop-SDN1RPT by RDP | F-010 | Hit | DC01 to DESKTOP RDP at 02:35:54 UTC. |
| Data stolen or accessed | F-003, F-014, ITQ-050, ITQ-051 | Partial | DCSync and file access confirmed; secret.zip/loot.zip exfil-deletion sequence not fully recovered. |
| Victim network layout | ITQ-010, ASR-1, ASR-2 | Hit | DC `10.42.85.10`, workstation `10.42.85.115`. |
| Immediate architecture improvement: remove public RDP / VPN | Briefings mention containment actions but not architecture recommendation | Miss | Not stated as a direct prevention recommendation. |
| Szechuan sauce stolen/accessed around 02:30 UTC | F-014 | Partial | Sensitive file access found via LNK artifacts; precise theft time not proven. |
| Beth secret manipulation / file deletion | F-014 | Partial | `Beth_Secret.txt` found in secret directory; original deletion/recreation not recovered. |
| Beth secret timestomp | Not resolved | Miss | Timestomped file not identified. |
| Secret_Beth original content | Not resolved | Miss | Original content not recovered. |
| Morty or other sensitive files exposed | ITQ-050, briefing 2 | Partial | Morty SSN-at-risk and sensitive DC files noted; answer-key file list not complete. |
| Last known attacker contact / active threat | F-018, ITQ-063 | Hit | Memory showed active C2 socket artifacts and SMB session at acquisition. |
| Users logged onto DC/Desktop | F-008, F-009, F-015, F-016, briefings | Partial | Created/used accounts captured; full logon inventory not complete. |
| Domain passwords recovered | Not resolved | Miss | No password recovery from hashes. |
| ricksanchez privilege escalation | F-015 | Hit | Added to Domain Admins and BUILTIN Administrators, later removed. |
| birdman backdoor account | F-016 | Hit | Creation attempts and lack of group membership recorded. |
| DCSync / KRBTGT compromise | F-003, ITQ-050, ITQ-051 | Hit | DRSUAPI replication and credential exposure documented. |

## Corrected Finding

| Finding | Original issue | Correction | Audit evidence |
|---|---|---|---|
| F-011 | Claimed 39 MB exfiltration from DESKTOP to OneDrive | F-017 showed the flow was inbound to DESKTOP; no bulk OneDrive exfil is supported | F-017, ASR-2 v2, audit seq 53 and 61 |

## Miss Themes

1. The agent did not fully recover the answer-key file manipulation sequence
   around `Secret_Beth.txt`, `Beth_Secret.txt`, `secret.zip`, and `loot.zip`.
2. The agent did not recover domain passwords from account hashes.
3. The agent did not fully characterize the victim timezone/local-time mismatch.
4. The agent found service persistence but did not complete all registry
   persistence details before the run stopped.

## Three-Claim Trace

Judges are instructed to pick three findings and trace them to tool output. These
three claims are intentionally diverse: network delivery, lateral movement, and
self-correction.

### Claim 1: Payload Delivery to DC01

Finding: F-002
Claim: DC01 downloaded `coreupdater.exe` from `194.61.24.102` at
`2020-09-19 02:24:06 UTC` using Internet Explorer 11.

Trace:

- Evidence source: `case001-pcap.zip`
- Artifact path: `case001.pcap`
- Tool: `tshark`
- Command:

```bash
tshark -r case001.pcap -Y "ip.addr==194.61.24.102 && http" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e http.request.method -e http.request.uri -e http.user_agent
```

Supporting excerpt:

```text
Sep 19, 2020 02:24:06.939239000 UTC  10.42.85.10  194.61.24.102  GET  /coreupdater.exe  Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko
```

### Claim 2: Lateral RDP from DC01 to Desktop

Finding: F-010
Claim: DC01 initiated an RDP session to DESKTOP-SDN1RPT at
`2020-09-19 02:35:54 UTC`.

Trace:

- Evidence source: `case001-pcap.zip`
- Artifact path: `case001.pcap`
- Tool: `tshark`
- Command:

```bash
tshark -r case001.pcap -q -z conv,tcp | grep "10.42.85.10.*10.42.85.115:3389"
```

Supporting excerpt:

```text
10.42.85.10:62514 <-> 10.42.85.115:3389  6139 452kB  9414 875kB  15553 1328kB  16667.815017000  979.2016
```

### Claim 3: OneDrive Exfiltration Correction

Finding: F-017
Claim: F-011 was wrong; the 36 MB OneDrive flow was inbound to the victim, not an
upload from DESKTOP.

Trace:

- Evidence source: `case001-pcap.zip`
- Artifact path: `case001.pcap`
- Tool: `tshark`
- Command:

```bash
tshark -r case001.pcap -Y "ip.addr==104.119.185.124" \
  -T fields -e ip.src -e ip.dst -e tcp.len |
awk '{if($2=="104.119.185.124")up+=int($3); else down+=int($3)}
END{printf "DESKTOP to OneDrive: %.3f MB\nOneDrive to DESKTOP: %.3f MB\n",up/1048576,down/1048576}'
```

Supporting excerpt:

```text
DESKTOP to OneDrive (upload): 0.003 MB
OneDrive to DESKTOP (download): 36.268 MB
```

## Evidence Integrity Notes

- Real evidence files were placed in the VM case `evidence/` directory.
- The answer key stayed on the host and was used only after the run.
- `evidence_manifest.json` hashes and inventories five source evidence files.
- Controlled extraction placed high-value PCAP/text in `work/ingest/` and did
  not replace source evidence as the ground truth.
- The copied run does not include source evidence, private IC key material, or
  answer keys.
