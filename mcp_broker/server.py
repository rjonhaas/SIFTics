"""SIFTics MCP Broker — server entry point.

Exposes the Velociraptor typed-function gateway over the MCP protocol so
Claude Code (or any MCP client) can call it as a structured tool.

Run from the repo root:
    mcp_broker/.venv/bin/python -m mcp_broker.server

Add to ~/.claude/settings.json:
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

The MCP protocol negotiates capabilities at startup. Tools surface in the
agent's tool list as siftics_velociraptor_<function_name>.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
import mcp.types as types

from . import audit, config
from .tools import velociraptor

logger = logging.getLogger("siftics.mcp_broker")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,  # MCP uses stdout for protocol traffic
)


server: Server = Server("siftics-mcp-broker")


# ── tool registration ──────────────────────────────────────────────────────


def _tool(name: str, description: str, schema: dict[str, Any]) -> types.Tool:
    return types.Tool(name=name, description=description, inputSchema=schema)


_TOOLS: list[types.Tool] = [
    _tool(
        "velociraptor_list_clients",
        "List Velociraptor clients (endpoints with the agent installed). "
        "Optional name_filter is a case-insensitive hostname substring match.",
        {
            "type": "object",
            "properties": {
                "name_filter": {"type": "string"}
            },
        },
    ),
    _tool(
        "velociraptor_get_client",
        "Get one client by Velociraptor client ID (e.g. C.1234abcd).",
        {
            "type": "object",
            "properties": {"client_id": {"type": "string"}},
            "required": ["client_id"],
        },
    ),
    _tool(
        "velociraptor_pull_offline_collection",
        "Trigger a Velociraptor artifact collection on the named client and "
        "download the resulting evidence zip to output_path. Use this when "
        "you have a primary victim and want to pull KAPE-style triage into "
        "the SIFTics case directory.",
        {
            "type": "object",
            "properties": {
                "client_id": {"type": "string"},
                "output_path": {"type": "string"},
                "artifact_pack": {
                    "type": "string",
                    "default": "Generic.Collectors.File",
                },
                "parameters": {
                    "type": "object",
                    "description": "Artifact-specific parameters",
                },
            },
            "required": ["client_id", "output_path"],
        },
    ),
    _tool(
        "velociraptor_upload_artifact",
        "Upload a custom Velociraptor artifact YAML definition. Used by "
        "SIFTics' findings_to_hunt.py output. Artifact name MUST start with "
        "SIFTICS_ to avoid the built-in namespace.",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "vql_yaml": {"type": "string"},
            },
            "required": ["name", "vql_yaml"],
        },
    ),
    _tool(
        "velociraptor_create_hunt",
        "Define a new hunt. Does NOT start it (call start_hunt next).",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "artifact_name": {"type": "string"},
                "parameters": {"type": "object"},
                "expires_hours": {"type": "integer", "default": 24},
                "description": {"type": "string"},
            },
            "required": ["name", "artifact_name"],
        },
    ),
    _tool(
        "velociraptor_start_hunt",
        "Activate a paused hunt against matching clients.",
        {
            "type": "object",
            "properties": {
                "hunt_id": {"type": "string"},
                "client_filter": {
                    "type": "string",
                    "description": "Hostname substring filter",
                },
            },
            "required": ["hunt_id"],
        },
    ),
    _tool(
        "velociraptor_get_hunt_status",
        "Return current hunt state and progress (clients_total, "
        "clients_completed, clients_with_results, is_complete).",
        {
            "type": "object",
            "properties": {"hunt_id": {"type": "string"}},
            "required": ["hunt_id"],
        },
    ),
    _tool(
        "velociraptor_get_hunt_results",
        "Pull structured results from a completed hunt. Returns a list of "
        "rows; each row is one observation from one client.",
        {
            "type": "object",
            "properties": {
                "hunt_id": {"type": "string"},
                "artifact_name": {"type": "string"},
                "limit": {"type": "integer", "default": 1000},
            },
            "required": ["hunt_id"],
        },
    ),
    _tool(
        "velociraptor_wait_for_hunt",
        "Poll get_hunt_status until is_complete or timeout. Returns final "
        "status. Use BEFORE get_hunt_results for hunts you just started.",
        {
            "type": "object",
            "properties": {
                "hunt_id": {"type": "string"},
                "timeout_s": {"type": "integer"},
            },
            "required": ["hunt_id"],
        },
    ),
    _tool(
        "velociraptor_list_artifacts",
        "List Velociraptor artifact definitions known to the server. Use "
        "this to discover what built-in artifacts exist before constructing "
        "a custom one.",
        {
            "type": "object",
            "properties": {"name_filter": {"type": "string"}},
        },
    ),
]


_DISPATCH = {
    "velociraptor_list_clients": velociraptor.list_clients,
    "velociraptor_get_client": velociraptor.get_client,
    "velociraptor_pull_offline_collection": velociraptor.pull_offline_collection,
    "velociraptor_upload_artifact": velociraptor.upload_artifact,
    "velociraptor_create_hunt": velociraptor.create_hunt,
    "velociraptor_start_hunt": velociraptor.start_hunt,
    "velociraptor_get_hunt_status": velociraptor.get_hunt_status,
    "velociraptor_get_hunt_results": velociraptor.get_hunt_results,
    "velociraptor_wait_for_hunt": velociraptor.wait_for_hunt,
    "velociraptor_list_artifacts": velociraptor.list_artifacts,
}


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return _TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    if name not in _DISPATCH:
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": f"unknown tool: {name}"}),
        )]
    fn = _DISPATCH[name]
    try:
        result = fn(**(arguments or {}))
    except Exception as exc:  # noqa: BLE001
        logger.exception("tool %s failed", name)
        return [types.TextContent(
            type="text",
            text=json.dumps({
                "error": f"{type(exc).__name__}: {exc}",
                "tool": name,
            }),
        )]
    return [types.TextContent(
        type="text",
        text=json.dumps(result, default=str),
    )]


# ── main ────────────────────────────────────────────────────────────────────


async def main():
    try:
        cfg = config.load_config()
        velociraptor.init(cfg=cfg)
        logger.info("Loaded config from %s; mock_mode=%s",
                    "auto-discovered", velociraptor._MOCK)
    except config.ConfigError as exc:
        logger.warning("Config not loaded (%s) — falling back to mock mode "
                       "(set $SIFTICS_MCP_MOCK=0 and provide config to use a "
                       "real Velociraptor server)", exc)
        velociraptor.init(mock=True)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="siftics-mcp-broker",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
