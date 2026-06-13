---
name: triage-methodology
description: Phase sequencing + decision engine. Replaces a static run_all.sh with ITQ-driven phase selection.
---

# Triage Methodology

The classic "run all phases in order" approach (`run_all.sh`) is wrong for IR.
Cases differ wildly - a ransomware incident needs different phases first than a
credential-dumping incident or a webshell. This skill encodes which phase to
run, when, based on the Initial Triage Questionnaire (ITQ).

## The map - ITQ category → phase script

| ITQ category (questions) | Phase scripts in priority order |
|---|---|
| `scope` (ITQ-001..005) | answered by IC; agent records into case header |
| `platform` (ITQ-010..016) | (no script - derived from evidence file types and case header) |
| `logs` (ITQ-020..026) | `run_eventlogs.sh` · `run_anti_forensics.sh` (specifically for log clearing) |
| `ownership` (ITQ-030..035) | IC-driven |
| `tooling` (ITQ-040..043) | agent surveys what's installed; reports gaps |
| `business_impact` (ITQ-050..053) | informed by ASR / CET findings as the case progresses |
| `containment` (ITQ-060..064) | `run_artifacts.sh` · `run_execution.sh` · `run_credaccess.sh` |
| `communication` (ITQ-070..074) | IC-driven |

**Note - network/pcap evidence:** When the evidence set contains pcap, pcapng,
or network flow files, see the **Network/pcap evidence** section below. The
network hot-path runs before Windows host phases when both evidence types are
present.

## Exhibit intake - chain of custody (MANDATORY, FIRST STEP)

**Before any analysis runs, every exhibit gets recorded with its hash.** This is
not a CTF-only nicety - it is the chain-of-custody anchor that every later
finding will reference. Skip this and your findings cannot be defended in court,
in a peer review, or in a hackathon ground-truth comparison.

For each file under `evidence/` and each archive listed in the case:

```bash
# 1. Hash every raw exhibit (image, archive, memory dump, pcap)
sha1sum   <path> | tee -a chain_of_custody.txt
sha256sum <path> | tee -a chain_of_custody.txt

# 2. For E01/Ex01 forensic images - read metadata from the header
ewfinfo <path>      # examiner, evidence number, acquisition date, hash
# or:
mmls    <path>      # partition table
fsstat  <path>      # filesystem stats including volume serial, label

# 3. For VMware/VirtualBox/QCOW2 - record format + size + parent chain
qemu-img info <path>
```

Record each exhibit as a `finding_record()` with `claim` of the form
*"Exhibit X has SHA-256 …; examiner='…'; acquisition_date='…'."* - these are the
foundational findings; every later finding's `artifact_source` field traces back
to one of them. Without this you cannot prove which image you actually analysed.

**Also extract metadata visible to forensic tools but invisible to file hashes:**
- E01 examiner name, evidence number, case number, description, acquisition date
- VMDK descriptor file parent chain
- Memory image acquisition tool signature (FTK Imager vs DumpIt vs WinPMEM)
- Photo/disk acquisition timestamp from MFT $STANDARD_INFORMATION on the image file

These metadata items often **are themselves** the answers to early ITQ questions
(who acquired this, when, with what tool, did the hash chain hold).

## Hot-path-first ordering

When you start a case:

1. **`fast_evtx_attack_filter`** (HOT) - < 30 s for the last 24h of EVTX.
   Identifies obvious attack indicators (process creation, service install,
   credential access).
2. **`fast_persistence_scan`** (HOT) - < 10 s. Diff registry persistence
   keys + services + scheduled tasks against `mcp_baseline`. Anything not in
   baseline becomes a candidate.
3. **`fast_execution_timeline`** (HOT) - last 4 hours of MFT + Prefetch +
   Amcache + Sysmon-1 events, deduplicated.
4. **`classify_binary` fan-out** on each surface binary - Rathbun baseline,
   imphash via abuse.ch MalwareBazaar, capa behavioural tags, RAG matches to
   ATT&CK.

Only after HOT findings stabilise should you reach for WARM (targeted EZ
Tools usage) or COLD (full Plaso super-timeline, Volatility full image).

## Escalation rules - when to move from HOT → WARM → COLD

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
Engine's signal scoring should drive that decision - not the absence of new
findings, which often just means you're not looking in the right place yet.

---

## Network/pcap evidence - hot-path, identity-token extraction, and victim identification

This section applies when the evidence set contains any pcap, pcapng, or
network flow file (NFCAP, Zeek conn.log, Suricata eve.json). It has equal
standing with the Windows host-artifact hot-path above.

### Extended ITQ category table - network row

| ITQ category | Phase action |
|---|---|
| `network` - evidence enumeration | Enumerate all pcap/flow files; record in case header scope (ITQ-080 equivalent). |
| `network` - identity extraction | Extract all session-layer identity tokens before any hypothesis is opened. |
| `network` - anonymous services | Check whether any flow contacted a known anonymous email/communication service. |
| `network` - HTTP POST bodies | Carve POST bodies when trigger conditions below are met. |
| `network` - victim identification | Identify victim from RCPT TO, POST body destination, or carved message content. |

The network category is **not optional** when pcap is present. It runs before
any hypothesis is opened. Reason: session-layer identifiers (cookies, POST
bodies, SMTP headers) are the cheapest evidence to collect and the easiest
to miss if a working theory forms first.

### Network hot-path ordering

When pcap or network flow files are present, run these steps **before**
`fast_evtx_attack_filter` (or as the entire hot-path if no Windows host
artifacts exist):

**Step N-1 - identity-token extraction (MANDATORY, HOT)**

Before calling `hypothesis_score add` for the first time, perform an
exhaustive pass over all session-layer identifiers in the pcap. Extract and
record every distinct value found in:

- HTTP `Cookie:` and `Set-Cookie:` headers (full cookie string)
- HTTP form POST bodies - all field names and values
- SMTP `MAIL FROM:`, `RCPT TO:`, `X-Originating-IP:` headers
- DNS PTR/A responses (map every layer-3 IP to its resolved hostname)
- Any header containing an email address or username token

Write every token as a finding note in the ASR or case notes before
proceeding. Do not filter or deduplicate before recording - deduplication
happens at analysis time.

**This step must complete before the Hypothesis Engine is called.** This
overrides the hypothesis-engine.md directive "open a hypothesis the moment
you have a coherent story" - for network cases, token extraction takes
precedence over early hypothesis opening.

A Gmail `gmailchat=` cookie value is an identity token. An SMTP `RCPT TO:`
address is an identity token. A POST body field named `to=` or `email=` is
an identity token. Record all of them before forming any theory about sender
identity.

**Step N-2 - flow summary (HOT)**

Summarise all flows (src_ip, dst_ip, dst_port, bytes, timestamps). Flag any
IP that contacted a known anonymisation service (Tor exit nodes via mcp_cti,
or anonymous email services such as Guerrilla Mail, Mailinator, 10minutemail,
AnonEmail). Note: `mcp_rag/anon_email_providers.json` is aspirational - if
absent, use mcp_cti for Tor and manually note any anonymous email services
observed in DNS queries or HTTP Host headers.

**Step N-3 - HTTP POST body carving (HOT when triggered)**

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
itq_answer("ITQ-085", "<victim identity or 'unknown - sources consulted: RCPT TO, POST body, carved content'>", source="agent")
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

---

## Web server access log evidence

This section applies when the evidence set contains `access.log`, `access_log`,
IIS logs, Nginx logs, or any HTTP server log file.

**Rule: UA histogram before IP analysis. Always.**

Grouping by IP first is the most common access log mistake - it misses automated
tooling that runs from a single IP but is unmistakable from its User-Agent.
A UA histogram takes 10 seconds and surfaces sqlmap, nikto, Metasploit, curl,
and Python-urllib in the first line of output.

### Step W-1 - User-Agent histogram (MANDATORY, first action on any access log)

```bash
awk '{print $12}' access.log | sort | uniq -c | sort -rn | head -30
# If $12 is quoted multi-word UA: use awk -F'"' '{print $6}' access.log
```

Record every anomalous UA as a finding_record() before any further analysis.
Anomalous = automated tool name (sqlmap, nikto, nmap, curl, python, wget),
known exploit framework UA, or UA inconsistent with the platform (e.g. Linux UA
on a Windows-only internal app).

**sqlmap identification:** `sqlmap/1.*` in UA means automated SQL injection.
Map to T1190. The requests associated with that UA are your attack timeline - 
read them in order to reconstruct injection payloads, extracted data, and
file-write operations (`SELECT INTO OUTFILE`).

### Step W-2 - IP + UA joint frequency table

```bash
awk '{print $1, $12}' access.log | sort | uniq -c | sort -rn | head -30
```

This separates tool-driven traffic (one IP, one UA, high frequency) from
browser-driven traffic (one IP, mixed UAs).

### Step W-3 - HTTP status code distribution

```bash
awk '{print $9}' access.log | sort | uniq -c | sort -rn
```

High 500-count from a single IP = injection/exploitation. High 404-count = scanning.

### Step W-4 - POST requests with body size > 0

```bash
grep '"POST ' access.log | awk '$10 > 100 {print}' | sort -k10 -rn | head -20
```

Large POST bodies to unexpected paths = file upload. POST to a `.php` file
in an upload directory = webshell activation.

### Web-case MITRE mapping

| Observation | MITRE technique |
|---|---|
| sqlmap UA + SQLi payloads in URI | T1190 - Exploit Public-Facing Application |
| `SELECT INTO OUTFILE` in URI | T1505.001 - SQL Stored Procedures (file write via DB) |
| PHP webshell POST execution | T1505.003 - Web Shell |
| Python-urllib or curl POST to .php | T1059.006/T1059.004 - command execution via webshell |

---

## Memory image evidence - Volatility minimum checklist

This section applies when a memory image (`.mem`, `.dmp`, `.raw`, `.vmem`) is
in the evidence set. **Running only pslist/pstree/netscan is not sufficient.**
The checklist below is the minimum - run all tiers before drawing conclusions.

### Tier 1 - always run (< 10 min total)

Run these unconditionally on every memory image:

```bash
vol -f image.mem windows.info         # OS version, build, capture time, KDBG offset
vol -f image.mem windows.pslist       # process inventory with PID/PPID/create time
vol -f image.mem windows.pstree       # parent-child tree
vol -f image.mem windows.netscan      # active + recently closed connections
vol -f image.mem windows.cmdline      # command line for every process
vol -f image.mem windows.dlllist      # DLLs loaded per process (catches VCRUNTIME / dropped DLLs)
vol -f image.mem windows.consoles     # IN-MEMORY console history from conhost.exe
vol -f image.mem windows.cmdscan      # IN-MEMORY command history from csrss.exe
vol -f image.mem windows.hivelist     # registry hive addresses (prereq for hashdump/printkey)
vol -f image.mem windows.hashdump     # NTLM hashes from in-memory SAM
vol -f image.mem windows.mftparser    # MFT records still in memory cache
vol -f image.mem windows.malfind      # injected code / suspicious VAD regions
```

**Why `consoles` and `cmdscan` are mandatory:**
Command history lives in `csrss.exe` / `conhost.exe` memory, not in cmd.exe's
argument list. A cmd.exe that appears entirely clean in pstree - normal parent,
no suspicious args - can still have a full attacker command history recoverable
from `consoles`/`cmdscan`. This is where `net user`, `netsh`, and `net localgroup`
commands show up. If you skip these plugins you will miss account creation and
firewall modification evidence even when the process tree looks innocent.

**Why `hashdump` and `dlllist` are Tier 1, not Tier 2:**
They cost almost nothing and frequently answer ITQ questions about local accounts
(hash dump) and dropped/sideloaded DLLs (e.g. an OfficeClickToRun process pulling
in VCRUNTIME140.dll is a classic side-loading pattern). Cheap to run unconditionally.

**Why `mftparser` is Tier 1:**
The MFT records cached in memory cover the most recent file activity - often
including files the on-disk MFT entries have already overwritten or that were
created and deleted within the volatile window. It is a different time slice
of the filesystem than `$MFT` on disk.

### Tier 2 - run when initial access or RCE is confirmed

```bash
vol -f image.mem windows.printkey --key "SAM\Domains\Account\Users\Names"
vol -f image.mem windows.printkey --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
vol -f image.mem windows.svcscan       # services with full image paths
vol -f image.mem windows.shimcachemem  # Shimcache from in-memory hive
vol -f image.mem windows.userassist    # UserAssist (GUI program execution)
```

### Tier 3 - run when specific evidence warrants

```bash
vol -f image.mem windows.handles --pid <PID>    # open handles (files, registry, sockets)
vol -f image.mem windows.memmap --pid <PID> --dump  # dump process memory for strings
vol -f image.mem windows.vadinfo --pid <PID>    # VAD protections (PAGE_READONLY, etc.)
vol -f image.mem windows.procdump --pid <PID> --dump  # dump executable image of process
```

### Suspicious-binary dump-and-hash rule

Whenever Tier 1 surfaces a suspicious process (unusual parent, no signer, name
that mimics a system binary, child of wscript/cscript/powershell, network
activity to an unfamiliar IP), **immediately procdump it and hash the result**:

```bash
vol -f image.mem windows.procdump --pid <PID> --dump -o /tmp/dumps/
sha256sum /tmp/dumps/*.exe
md5sum    /tmp/dumps/*.exe
```

Record the hashes in a `finding_record()`. These hashes are the IOCs that the
agent should then submit to `mcp_cti.enrich()` for VirusTotal / MalwareBazaar /
ThreatFox lookups. Skipping this step means later threat-intel queries have
nothing to ask about.

---

## Post-exploitation persistence pivot (mandatory after RCE confirmation)

**Rule: the instant you confirm code execution - webshell, RCE, LFI→RCE,
Meterpreter session - stop web log analysis and run the persistence pivot
before doing anything else.**

Attackers create accounts and modify firewall rules within minutes of getting
a shell. These are the most operationally dangerous findings and the most
commonly missed because analysts stay in the "initial access" evidence stream
instead of pivoting to "what did the attacker do with that access?"

### Account creation pivot (run in this order)

**1. cmdscan / consoles against csrss.exe** (if memory is available):
```bash
vol -f image.mem windows.cmdscan    # look for: net user, net localgroup
vol -f image.mem windows.consoles   # same - conhost.exe view
```

**2. SAM hive - on-disk local account list**:
```bash
# Mount image, then:
python3 -c "
from impacket.examples.secretsdump import LocalOperations, SAMHashes
ops = LocalOperations('/mnt/img/Windows/System32/config/SYSTEM')
boot_key = ops.getBootKey()
sam = SAMHashes('/mnt/img/Windows/System32/config/SAM', boot_key, isRemote=False)
sam.dump()
"
# Or: reg.py / secretsdump.py / samdump2
```

Record every non-default local account as a finding_record(). Note SID, creation
time, group membership.

**3. Security.evtx - account events**:
```bash
# EID 4720 = account created, EID 4732 = user added to security group
python3 -m evtx /mnt/img/Windows/System32/winevt/Logs/Security.evtx \
  | grep -E "EventID.4720|EventID.4732" -A 20
```

### Firewall / RDP pivot

**1. cmdscan / consoles** (look for `netsh` and `net localgroup`):
```
netsh firewall set service type=remotedesktop mode=enable scope=subnet
netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=TCP localport=3389
net localgroup "Remote Desktop Users" <username> /add
```

**2. Registry - Windows Firewall rules** (on-disk or in-memory via printkey):
```bash
vol -f image.mem windows.printkey \
  --key "SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
```

**3. Map to MITRE:**

| Evidence | MITRE |
|---|---|
| `net user <name> <pass> /add` | T1136.001 - Create Local Account |
| `net localgroup "Remote Desktop Users" <user> /add` | T1021.001 - Remote Desktop Protocol |
| `netsh firewall set service remotedesktop` | T1021.001 + T1562.004 - Impair Defenses: Disable Firewall |

### NTFS $LogFile for deleted-file recovery

When MFT entries show deleted files, or when the access log references files no
longer present on disk, use the NTFS $LogFile (transaction journal) to recover
allocation/deallocation records:

```bash
# Extract $LogFile from image
icat -o <offset> image.dd <$LogFile inode> > LogFile.bin

# Parse with LogFileParser (SIFT has this)
python3 LogFileParser.py -i LogFile.bin -o logfile_output.csv
grep -i "tmp\|webshell\|\.php" logfile_output.csv
```

The $LogFile retains records for files that have been deleted and MFT-overwritten,
because the journal is circular and overwrites more slowly than the MFT. This is
the last resort for recovering evidence of dropped-and-deleted payloads.

**Do not skip this step** when you find temporary files in the access log that
are absent from the disk. Dropped-and-deleted payloads that are gone from
MFT are often still recoverable here because the journal is circular and
overwrites more slowly.

### Setup.evtx for installed-software evidence

When the case involves malware installation or questions about what was present
at compromise time:

```bash
# Parse Setup.evtx for installer activity
python3 -m evtx /mnt/img/Windows/System32/winevt/Logs/Setup.evtx \
  | grep -i "install\|setup\|package" | head -40
```

### NTUser.dat for user activity artifacts

After confirming which account the attacker used or created, parse that account's
registry hive for MRU lists, recent files, typed paths, and Run keys:

```bash
# Dump NTUSER.DAT for target account
hivexsh /mnt/img/Users/<username>/NTUSER.DAT
# Or use RECmd / regipy for structured extraction
```
