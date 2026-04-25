# Protocol SIFT MCP Server

A custom Model Context Protocol server that exposes the SANS SIFT Workstation's 200+ forensic tools as **typed, read-only functions** to the Protocol SIFT ICS swarm.

## Why This Architecture

The hackathon calls out Custom MCP Server as "the most sound architecture in the evaluation" — and this server is why. Instead of giving an agent `execute_shell_cmd` (which can do literally anything), this server exposes functions like:

```
get_prefetch_summary(evidence_id, time_range)
extract_mft_timeline(evidence_id, since, until)
parse_event_log(evidence_id, log_name, event_ids)
vol_pslist(memory_capture_id)
```

Each function:
1. Takes typed parameters — no arbitrary strings that could be shell-injected
2. Is read-only — the server has no write functions on evidence
3. Parses raw tool output into structured JSON before returning
4. Caps output size — large results are written to the branch's working directory, not dumped into the LLM context

## The Three Architectural Guarantees

### 1. No Shell Access
The server does not expose `exec_shell`, `run_command`, `eval`, or anything similar. Branch agents physically cannot execute arbitrary commands.

### 2. Read-Only Enforcement
Every internal call to an underlying SIFT tool runs against a read-only mount of the evidence. Tool invocations are wrapped to verify the evidence path is within the declared `EVIDENCE_MOUNT` and has the read-only bit set. Any attempt to reference a path outside the mount, or a path that is writable, fails before the tool runs.

### 3. Context Window Protection
Raw SIFT tool output is often huge — $MFT dumps, full event log exports, memory triage outputs can be hundreds of MB. This server:
- Parses the raw output into structured records
- Returns summaries + pointers by default
- Exposes typed query functions to drill in (e.g., `get_mft_records_for_path(path)` rather than returning the full $MFT)

This prevents the context degradation failure mode that plagues generic-shell-access agent designs.

## Directory Layout

```
mcp-server/
├── README.md                    # this file
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts                 # MCP server entry point
│   ├── server.ts                # MCP protocol handler
│   ├── tools/                   # one module per tool category
│   │   ├── disk/
│   │   │   ├── mft.ts
│   │   │   ├── prefetch.ts
│   │   │   ├── registry.ts
│   │   │   ├── eventlog.ts
│   │   │   ├── shellbags.ts
│   │   │   └── browser.ts
│   │   ├── memory/
│   │   │   └── volatility.ts    # wraps vol3 with typed outputs
│   │   ├── network/
│   │   │   ├── pcap.ts
│   │   │   └── zeek.ts
│   │   └── malware/
│   │       ├── static.ts
│   │       ├── yara.ts
│   │       └── capa.ts
│   ├── evidence/
│   │   ├── mount_manager.ts     # verifies read-only mounts
│   │   └── hash_registry.ts     # verifies ingest hashes
│   ├── schemas/
│   │   └── *.json               # JSON Schemas for every tool's I/O
│   └── safety/
│       ├── path_guard.ts        # enforces path containment
│       └── readonly_guard.ts    # enforces read-only on every call
└── test/
    ├── injection/               # prompt injection test harness
    ├── spoliation/              # evidence modification attempts
    └── fixtures/                # sample evidence for tests
```

## Tool Inventory (abbreviated)

See `src/tools/**/*.ts` for the full set. Key functions exposed:

### Disk (Windows focus, extensible)
- `get_system_info(evidence_id)`
- `list_users(evidence_id)`
- `get_run_keys(evidence_id, hive_filter?)`
- `get_services(evidence_id, since?)`
- `get_scheduled_tasks(evidence_id)`
- `parse_prefetch_summary(evidence_id)`
- `parse_prefetch_detailed(evidence_id, pf_name?)`
- `parse_amcache_detailed(evidence_id)`
- `parse_shimcache_detailed(evidence_id)`
- `extract_mft_timeline(evidence_id, since, until)`
- `parse_usn_journal(evidence_id, since, until)`
- `parse_event_logs(evidence_id, log_name, event_ids?, since?, until?)`
- `parse_browser_history(evidence_id, user?)`
- `parse_shellbags(evidence_id, user?)`
- `extract_file_by_path(evidence_id, path)` — copies to working_dir

### Memory
- `vol_pslist(memory_id)`
- `vol_pstree(memory_id)`
- `vol_psscan(memory_id)`
- `vol_cmdline(memory_id, pid?)`
- `vol_malfind(memory_id, pid?)`
- `vol_hollowfind(memory_id)`
- `vol_netscan(memory_id)`
- `vol_ldrmodules(memory_id, pid?)`
- `vol_yarascan(memory_id, rule_path)`

### Network
- `pcap_summary(pcap_id)`
- `zeek_conn_log(pcap_id)`
- `zeek_dns_log(pcap_id, filter?)`
- `zeek_ssl_log(pcap_id)`
- `beacon_detection(pcap_id, min_samples, variance_threshold)`
- `extract_files_from_pcap(pcap_id, flow_filter?)`

### Malware (static)
- `file_type_identify(sample_path)`
- `pe_header_parse(sample_path)`
- `extract_strings(sample_path, min_length, encoding)`
- `yara_scan_comprehensive(sample_path)`
- `capa_analysis(sample_path)`
- `entropy_analysis(sample_path)`

## Installation

The server is installed on the SIFT Workstation via:

```bash
cd mcp-server
npm install
npm run build
```

And registered in OpenClaw via the `mcp_servers` section of `openclaw.json`.

## Testing

Three test suites are critical for the hackathon Accuracy Report:

1. `test/injection/` — attempts to inject malicious instructions via filenames, registry values, and log entries that the LLM will see. Verifies typed output parsing strips them before they reach the LLM.
2. `test/spoliation/` — attempts to trigger a write to evidence through every exposed function. All must fail.
3. `test/fixtures/` — sample evidence with known-good ground truth for accuracy benchmarking.

## Why This Matters for Judging

- **Constraint Implementation**: guardrails are architectural (server exposes no write functions) rather than prompt-based. Test harness documents this.
- **Audit Trail Quality**: every function call logs a unique `execution_id` that findings reference.
- **IR Accuracy**: typed parsing means fewer hallucinations from the LLM trying to interpret raw tool output.
- **Usability**: other practitioners can install this server and extend it without touching the ICS skills layer.
