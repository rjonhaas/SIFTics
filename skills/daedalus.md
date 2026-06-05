---
name: daedalus
description: Tool discovery and implementation for unknown artifacts — find the right tool, install it, document it, get IC approval before running against evidence
---

# Daedalus — Tool Discovery and Implementation

Daedalus activates when the investigation reaches an artifact, file format, or
technology that no existing skill file covers and no installed tool can parse.
Its job is not to write new tools from scratch — it is to **find existing vetted
tools, understand how to use them, and get IC approval before running anything
unfamiliar against evidence.**

---

## When to invoke Daedalus

Invoke this skill when **all three conditions are true:**

1. You have an artifact in hand that you cannot parse with currently installed tools
2. You have already checked `/windows-artifacts`, `/linux-server-artifacts`,
   `/macos-artifacts`, and `/iot-ot-artifacts` — none cover this artifact
3. `forensic_rag_search` returned no relevant Sigma rules, ATT&CK techniques, or
   LOLBAS entries that describe the artifact's parsing

**Do not invoke Daedalus for:**
- Artifacts that are hard but parseable with existing tools (run `strings` first)
- Artifacts from a known platform just not yet analysed (load the platform skill)
- Cases where you simply haven't tried `binwalk`, `file`, or `strings` yet

---

## The Daedalus workflow

### Step 1 — Characterise the unknown artifact

Before searching for tools, document what is known:

```
- File type (from `file` command and magic bytes)
- Source: where on the system was it found? What process wrote it?
- Size and entropy (from `binwalk -E`)
- Any strings that suggest vendor, format name, or protocol
- Platform: what OS/device produced it?
```

A precise artifact description is the most important input to the search.
"Unknown binary" is not useful. "32-byte-header binary from a Siemens S7-1500
PLC in `/DB/Retentive/`, first 4 bytes `0x53 0x37 0x44 0x42`" is useful.

### Step 2 — Search mcp_rag

```python
forensic_rag_search(
    query="<artifact_description> parsing tool forensics",
    top_k=10
)
```

If mcp_rag returns a matching Sigma rule, ATT&CK entry, or LOLBAS entry that
points to known tooling — use that tool. No further Daedalus steps needed.

### Step 3 — Targeted web search

If mcp_rag returns nothing relevant, search for existing tools:

Search terms to try (in order):
1. `"<format_name>" forensics tool site:github.com`
2. `"<vendor> <model>" digital forensics parser`
3. `"<file_extension>" DFIR analysis`
4. `"<magic_bytes_hex>" file format`

For each tool found, verify:
- Is it open source with a known maintainer?
- When was it last updated? (Tools abandoned for 5+ years may not compile)
- Is there a documented output format the agent can parse?
- Is there a published paper, blog post, or conference talk explaining the format?
  (This is stronger evidence than just finding a tool)

### Step 4 — Document the tool

Before installing or running anything, create a `finding_record()` that documents:

```python
finding_record(
    claim="Identified tool <tool_name> for parsing <artifact_type>",
    artifact_path="<artifact_path>",
    artifact_source="<evidence_source>",
    tool="daedalus_research",
    command="web search: '<search_terms_used>'",
    output_excerpt="<tool_name> by <author> — <brief_description> — <github_url>",
)
```

This creates an auditable record that a new tool was introduced into the analysis.

### Step 5 — Request IC approval before running

**Always request IC approval before running a previously-unknown tool against
evidence.** This is not the `publish_intel` gate — create a standard
`ic_request_approval` with gate `execute_hunt_package` or a descriptive
summary. The IC's question is:

> "A tool not in our standard toolkit was found. Is it appropriate to run
> `<tool_name>` against the evidence file `<path>`?"

Rationale: running an unvetted tool against evidence can modify access timestamps,
produce incorrect output that contaminates the finding record, or in rare cases
alter the evidence. The IC's approval documents that the decision was deliberate.

### Step 6 — Install and run

After IC approval:

```bash
# Install (prefer pipx for isolation, or the SIFTics venv)
/home/sansforensics/SIFTics/.venv/bin/pip install <package>
# OR
git clone <repo> /opt/<toolname>
cd /opt/<toolname> && pip install -r requirements.txt

# Run against a copy of the evidence, not the original
cp <evidence_file> /tmp/daedalus_work/
<tool> /tmp/daedalus_work/<file> > /tmp/daedalus_out.txt

# Record the output
finding_record(
    claim="<what was found using the new tool>",
    artifact_path="<original evidence path>",
    artifact_source="<evidence source>",
    tool="<tool_name>",
    command="<exact command run>",
    output_excerpt="<relevant output slice>",
)
```

---

## Common Daedalus scenarios and likely tools

These are starting points for tool research — verify currency before installing.

| Artifact type | Tool to research | Notes |
|---|---|---|
| macOS Unified Log (`.tracev3`) | `macos-UnifiedLogs` (Mandiant, GitHub) | Rust binary; pre-built releases available |
| Windows Memory (`.raw`, `.dmp`) not parseable with Volatility | `MemProcFS` | Alternative to Volatility for some profiles |
| Android `.ab` backup | `android-backup-extractor` | Java-based; needs JDK |
| iOS filesystem image | `iLEAPP` | Python; outputs HTML timeline |
| Android filesystem image | `ALEAPP` | Python; sister tool to iLEAPP |
| Chromebook / Chrome OS | `chrome_forensics` | Research first — tooling is sparse |
| Siemens S7 PLC program backup | `plcscan` or `s7scan` | Network tools; research for static analysis |
| OSIsoft PI database | `PI-Web-API` export or `PIExcel` | Vendor tools; may require licence |
| Vehicle CAN bus log | `cantools` or `python-can` | Open source; DBC file needed for decoding |
| ESXi VMFS image | `vmfs-tools` | May be pre-installed on SIFT |
| QCOW2 / VHD / VHDX | `qemu-img` or `libvhdi-tools` | Usually available on SIFT |
| Splunk bucket (`.tsidx`) | `splunk-tools` or direct Splunk instance | Vendor-specific |
| Elastic index shard | Requires running Elasticsearch | Cannot be parsed standalone |

---

## What Daedalus does NOT do

- **Does not write new parsers.** If no tool exists anywhere for this artifact,
  that is a finding in itself — document it as a gap, escalate to the IC, and
  consider whether the investigation can proceed without parsing this artifact.
- **Does not run tools without IC approval.** The approval step is mandatory,
  not optional.
- **Does not trust unreviewed tool output blindly.** After running a new tool,
  cross-verify at least one finding against a second method (hex dump, strings,
  manual inspection) before entering it in the finding record.
- **Does not install tools system-wide.** Use the SIFTics venv or a temporary
  virtualenv to avoid polluting the SIFT workstation.

---

## Documenting the gap

If Daedalus exhausts all search paths and no tool is found:

```python
itq_answer(
    "ITQ-040",  # or relevant tooling question
    "Artifact type <description> at <path> could not be parsed with available "
    "tooling. Research conducted: [list tools searched, search terms used]. "
    "No open-source parser found. Recommend: manual vendor contact, expert "
    "consultation, or acceptance that this artifact is unanalysable with "
    "current resources.",
    source="agent"
)
```

An explicit unparseable finding is better than silence. It tells the IC exactly
what was attempted and what decision they need to make.
