# SIFTics MCP Broker

Typed-function MCP gateway between the SIFTics agent and external services.
Currently exposes one tool module — Velociraptor — with a 10-function surface
for offline-collection retrieval and hunt lifecycle management.

## Why a broker?

The SIFTics agent runs inside Claude Code and talks to local SIFT tools via the
Bash tool. Reaching outside that VM (to a Velociraptor server, a REMnux VM, a
SIEM, a ticketing system) needs a different mental model: **typed functions**
instead of arbitrary shell exec, **parsed responses** instead of multi-megabyte
text dumps, and **per-call structured audit** instead of parsed bash logs.

That's what this broker provides. The agent calls a fixed catalog of typed
functions; the broker handles auth, request shaping, response parsing, and
audit logging.

## Architectural posture

| Boundary | Enforcement |
|---|---|
| The agent cannot exec arbitrary commands on the Velociraptor server | The MCP server only exposes the typed functions in the catalog below. There is no `exec`, no `shell`, no raw VQL passthrough. |
| The agent cannot send malformed VQL with shell-injection-style payloads | All agent-supplied strings flow through `_safe_str()` which rejects VQL-reserved characters (quotes, semicolons, backslashes, newlines). |
| The agent cannot create artifacts that overwrite Velociraptor built-ins | `upload_artifact` rejects names that don't start with `SIFTICS_` or `Custom.`. |
| Sensitive auth material never enters the agent's context window | The Velociraptor API key file is loaded server-side; the agent only sees typed function results. |
| Every agent → broker call is auditable | `mcp_broker/audit.jsonl` records every invocation with timestamp, args digest (sensitive values redacted), result summary, latency, status. |

## Install

Run from the SIFTics repo root:

```bash
python3 -m venv mcp_broker/.venv
mcp_broker/.venv/bin/pip install -r mcp_broker/requirements.txt
```

Tested with Python 3.10+. The broker uses the official `mcp` SDK (v1.0+),
`httpx`, and `pyyaml`.

## Configure

Copy the example config and fill in your Velociraptor server details:

```bash
cp mcp_broker/config/config.example.yaml mcp_broker/config/config.yaml
$EDITOR mcp_broker/config/config.yaml
```

Generate a Velociraptor API client config (run on the Velociraptor server VM):

```bash
velociraptor --config server.config.yaml config api_client \
    --name siftics-broker --role investigator > /path/to/api_client.yaml
```

Then point `velociraptor.api_key_path` in `config.yaml` at that file. The
broker will use mTLS to authenticate to Velociraptor.

## Run

### As an MCP server (for Claude Code)

```bash
mcp_broker/.venv/bin/python -m mcp_broker.server
```

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "siftics": {
      "command": "/abs/path/to/SIFTics/mcp_broker/.venv/bin/python",
      "args": ["-m", "mcp_broker.server"],
      "env": {
        "SIFTICS_MCP_CONFIG": "/abs/path/to/SIFTics/mcp_broker/config/config.yaml"
      }
    }
  }
}
```

After restarting Claude Code, the agent will see tools named
`siftics_velociraptor_<function>`.

### As a CLI (for shell scripts and ad-hoc testing)

```bash
mcp_broker/.venv/bin/python -m mcp_broker.tools.velociraptor list_clients
mcp_broker/.venv/bin/python -m mcp_broker.tools.velociraptor \
    pull_offline_collection client_id=C.1111aaaa output_path=/cases/jack/incoming/win11/c.zip
```

### Mock mode (no Velociraptor needed)

For development and demo recording without a real Velociraptor server:

```bash
SIFTICS_MCP_MOCK=1 mcp_broker/.venv/bin/python -m mcp_broker.tools.velociraptor list_clients
```

Mock mode returns realistic canned responses for every function. Use it to
develop the orchestrator and demo scripts before wiring up a real server.

## Function catalog (the agent's complete surface area)

| Function | Purpose |
|---|---|
| `velociraptor_list_clients(name_filter?)` | Enumerate endpoints with the agent installed |
| `velociraptor_get_client(client_id)` | Fetch one client by ID |
| `velociraptor_pull_offline_collection(client_id, output_path, artifact_pack?, parameters?)` | Trigger artifact collection and download the result zip |
| `velociraptor_upload_artifact(name, vql_yaml)` | Push a custom artifact YAML; name must start with `SIFTICS_` or `Custom.` |
| `velociraptor_create_hunt(name, artifact_name, parameters?, expires_hours?, description?)` | Define a hunt (PAUSED) |
| `velociraptor_start_hunt(hunt_id, client_filter?)` | Activate a hunt |
| `velociraptor_get_hunt_status(hunt_id)` | Current state, completion stats |
| `velociraptor_get_hunt_results(hunt_id, artifact_name?, limit?)` | Pull structured rows |
| `velociraptor_wait_for_hunt(hunt_id, timeout_s?)` | Poll until complete or timeout |
| `velociraptor_list_artifacts(name_filter?)` | Discover available artifact definitions |

There is no other surface. The agent cannot escape this catalog.

## End-to-end workflow

```
SIFTics agent
  │
  │ (1) Pulls offline collection from win11-victim
  ▼
mcp_broker.velociraptor.pull_offline_collection(client_id, output_path)
  │
  ▼
Velociraptor server  ──collects──▶  win11-victim agent
  │                                   │
  ◀─── triage zip ────────────────────┘
  │
  ▼
SIFTics processes the zip via phases 1–20
  │
  ▼
findings_to_hunt.py converts ioc_master.csv + anomalies.csv → SIFTICS_*.yaml
  │
  ▼
mcp_broker.velociraptor.upload_artifact(...) for each
mcp_broker.velociraptor.create_hunt(...)
mcp_broker.velociraptor.start_hunt(...)
mcp_broker.velociraptor.wait_for_hunt(...)
mcp_broker.velociraptor.get_hunt_results(...)
  │
  ▼
Cross-host findings → ingested back into SIFTics case as new evidence
  │
  ▼
[Optional] Re-run anomaly check + self-correct on the augmented data
```

`scripts/run_detect_hunt_loop.sh` wraps this entire flow.

## Files

```
mcp_broker/
├── README.md            (this file)
├── requirements.txt     (mcp, httpx, pyyaml)
├── server.py            (MCP server entry — registers tools, dispatches calls)
├── config.py            (load YAML config; defaults to mock mode if no config)
├── auth.py              (load Velociraptor API client bundle)
├── audit.py             (per-call JSONL audit logger; redacts sensitive args)
├── config/
│   └── config.example.yaml
└── tools/
    └── velociraptor.py  (10 typed functions; subprocess wrapper around `velociraptor` CLI)
```

## Adding a new tool module

1. Create `mcp_broker/tools/<service>.py` with typed functions.
2. Register tools in `server.py` `_TOOLS` and `_DISPATCH`.
3. Add input schemas matching the function signatures.
4. Use the `@audit.wrap()` decorator on each function so calls are logged.

The broker is designed to grow incrementally — each tool module is independent.
Future candidates: REMnux (malware analysis), Jira (case tracking), VirusTotal
(hash lookups, with rate-limit enforcement).
