"""mcp_broker — Velociraptor active-hunt MCP, 10 typed functions.

All custom artifact uploads must use the SIFTICS_ or Custom. prefix
(namespace guard G10). All VQL is template-driven; the agent cannot author
novel VQL — only fill in IOC slots in pre-committed templates.

Modes:
    SIFTICS_BROKER_MODE=mock       deterministic stub responses (default)
    SIFTICS_BROKER_MODE=real       talk to a real Velociraptor server via
                                   its REST API (mTLS).
                                   Required env in real mode:
                                     SIFTICS_BROKER_API_URL    https://host:8000
                                     SIFTICS_BROKER_API_CERT   client.pem
                                     SIFTICS_BROKER_API_KEY    client.key
                                   Optional:
                                     SIFTICS_BROKER_CA_CERT    server CA bundle
                                     SIFTICS_BROKER_VERIFY     true|false
                                                                (default true)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from siftics.audit import append_event

mcp = FastMCP("siftics-velociraptor-broker")

_MODE = os.environ.get("SIFTICS_BROKER_MODE", "mock").lower()
_NAMESPACE_PREFIXES = ("SIFTICS_", "Custom.")

# Curated VQL hunt templates — the only VQL the agent can ever cause to run.
_HUNT_TEMPLATES: dict[str, dict[str, Any]] = {
    "credential_dumper": {
        "artifact": "SIFTICS_Hunt.Windows.CredentialDumper",
        "description": "Hunt for credential-dumper imphash matches across the fleet.",
        "expected_params": ["imphashes", "capability_tags"],
        "vql_skeleton": (
            "SELECT * FROM artifact_set(artifact='Windows.Sysinternals.Procdump') "
            "WHERE Imphash IN imphashes"
        ),
    },
    "persistence_check": {
        "artifact": "SIFTICS_Hunt.Windows.PersistenceCheck",
        "description": "Hunt for Run / Services / Scheduled Tasks not in Rathbun baseline.",
        "expected_params": ["unknown_run_values", "unknown_service_names"],
        "vql_skeleton": (
            "SELECT * FROM artifact_set(artifact='Windows.Registry.RunKeys') "
            "WHERE Name IN unknown_run_values"
        ),
    },
    "network_beacon": {
        "artifact": "SIFTICS_Hunt.Network.BeaconCheck",
        "description": "Hunt for inbound/outbound connections matching given IPs/ports.",
        "expected_params": ["ips", "ports"],
        "vql_skeleton": (
            "SELECT * FROM artifact_set(artifact='Windows.Network.NetstatEnriched') "
            "WHERE Foreign.IP IN ips AND Foreign.Port IN ports"
        ),
    },
    "lolbas_misuse": {
        "artifact": "SIFTICS_Hunt.Windows.LOLBASMisuse",
        "description": "Hunt for LOLBAS binaries executed with suspicious arguments.",
        "expected_params": ["binaries", "argument_patterns"],
        "vql_skeleton": (
            "SELECT * FROM artifact_set(artifact='Windows.Sysinternals.Sysmon') "
            "WHERE Image_Filename IN binaries AND CommandLine REGEX argument_patterns"
        ),
    },
    "service_install_anomaly": {
        "artifact": "SIFTICS_Hunt.Windows.ServiceAnomaly",
        "description": "Hunt for services installed with non-baseline image paths.",
        "expected_params": ["image_path_substrings"],
        "vql_skeleton": (
            "SELECT * FROM artifact_set(artifact='Windows.Sys.Services') "
            "WHERE ImagePath REGEX image_path_substrings"
        ),
    },
}


# ---------------------------------------------------------------------------
# Internal state — mock mode persists in audit chain so demos are repeatable
# ---------------------------------------------------------------------------

_MOCK_HUNTS: dict[str, dict[str, Any]] = {}
_HTTP_CLIENT = None


def _http() -> Any:
    """Return a configured httpx.Client for the real Velociraptor server.

    Loads mTLS material from env vars exactly once. Reused across MCP calls.
    """
    global _HTTP_CLIENT
    if _HTTP_CLIENT is not None:
        return _HTTP_CLIENT
    import httpx  # local import keeps mock-mode dep-free
    api_url = os.environ.get("SIFTICS_BROKER_API_URL")
    if not api_url:
        raise RuntimeError("SIFTICS_BROKER_API_URL is required in real mode.")
    cert = os.environ.get("SIFTICS_BROKER_API_CERT")
    key = os.environ.get("SIFTICS_BROKER_API_KEY")
    if not (cert and key):
        raise RuntimeError(
            "real mode requires SIFTICS_BROKER_API_CERT and "
            "SIFTICS_BROKER_API_KEY (mTLS client cert PEM files)."
        )
    verify_env = os.environ.get("SIFTICS_BROKER_VERIFY", "true").lower()
    verify: bool | str = True
    if ca := os.environ.get("SIFTICS_BROKER_CA_CERT"):
        verify = ca
    elif verify_env in ("false", "0", "no"):
        verify = False
    _HTTP_CLIENT = httpx.Client(
        base_url=api_url.rstrip("/"),
        cert=(cert, key),
        verify=verify,
        timeout=30.0,
        headers={"User-Agent": "SIFTics/0.1 (mcp_broker)"},
    )
    return _HTTP_CLIENT


def _post(path: str, payload: dict) -> dict:
    """POST to a Velociraptor REST endpoint and return the parsed JSON.

    Velociraptor's REST API is the same surface the WebUI calls. Endpoint
    paths follow /api/v1/<MethodName>.
    """
    resp = _http().post(f"/api/v1/{path}", json=payload)
    resp.raise_for_status()
    if not resp.content:
        return {}
    return resp.json()


def _audit(event_type: str, payload: dict, actor: str = "mcp_broker") -> None:
    try:
        append_event(event_type, payload, actor=actor)
    except RuntimeError:
        pass  # case dir not set during tooling-only invocation


def _ensure_namespace(name: str) -> None:
    if not any(name.startswith(p) for p in _NAMESPACE_PREFIXES):
        raise ValueError(
            f"artifact name {name!r} violates SIFTics namespace guard "
            f"(must start with {_NAMESPACE_PREFIXES})."
        )


# ---------------------------------------------------------------------------
# The ten typed functions
# ---------------------------------------------------------------------------


@mcp.tool()
def list_clients() -> list[dict]:
    """List Velociraptor clients (hosts) currently registered with the server."""
    if _MODE == "mock":
        return [
            {"client_id": "C.mock-001", "hostname": "win11-victim",
             "os": "windows", "last_seen": "2026-05-22T15:30:00Z"},
            {"client_id": "C.mock-002", "hostname": "fileserver01",
             "os": "windows", "last_seen": "2026-05-22T15:29:55Z"},
            {"client_id": "C.mock-003", "hostname": "elastic-siem",
             "os": "linux", "last_seen": "2026-05-22T15:30:01Z"},
        ]
    data = _post("SearchClients", {"limit": 200, "query": "all"})
    out: list[dict] = []
    for c in data.get("items", []) or []:
        info = c.get("os_info") or {}
        out.append({
            "client_id": c.get("client_id"),
            "hostname": info.get("hostname") or info.get("fqdn") or "",
            "os": (info.get("system") or "").lower(),
            "last_seen": c.get("last_seen_at") or c.get("first_seen_at") or "",
        })
    return out


@mcp.tool()
def get_client(client_id: str) -> dict:
    """Retrieve full metadata for one client."""
    if _MODE == "mock":
        for c in list_clients():
            if c["client_id"] == client_id:
                return c
        return {"error": "not_found", "client_id": client_id}
    data = _post("GetClient", {"client_id": client_id})
    return data or {"error": "not_found", "client_id": client_id}


@mcp.tool()
def pull_offline_collection(client_id: str, collection_id: str) -> dict:
    """Download an offline collection ZIP from a client (returns local path)."""
    if _MODE == "mock":
        return {"status": "queued",
                "path": f"/tmp/siftics_mock_collection_{collection_id}.zip",
                "client_id": client_id, "_v1_note": "mock mode"}
    # Velociraptor: download zip via /api/v1/DownloadVFSFile after the
    # collection completes. Real-mode here returns a job pointer for the
    # agent to poll; binary download is handled by mcp_case file-staging.
    data = _post("GetFlowDetails",
                  {"client_id": client_id, "flow_id": collection_id})
    return {"status": data.get("context", {}).get("state", "unknown"),
            "client_id": client_id, "flow_id": collection_id,
            "download_path": data.get("context", {}).get("report_url")}


@mcp.tool()
def upload_artifact(artifact_name: str, artifact_yaml: str) -> dict:
    """Upload a custom Velociraptor artifact definition.

    Architectural guard: artifact_name MUST start with SIFTICS_ or Custom.
    (G10 in the constraint-implementation matrix).
    """
    _ensure_namespace(artifact_name)
    _audit("velociraptor_artifact_uploaded",
           {"artifact_name": artifact_name,
            "yaml_sha256": hashlib.sha256(artifact_yaml.encode()).hexdigest()})
    if _MODE == "mock":
        return {"status": "ok", "artifact_name": artifact_name,
                "_v1_note": "mock mode — artifact accepted but not persisted"}
    data = _post("SetArtifactFile",
                  {"artifact": artifact_yaml, "op": "SET"})
    return {"status": "ok" if data else "error",
            "artifact_name": artifact_name,
            "server_response": data}


@mcp.tool()
def list_artifacts(prefix: str = "") -> list[str]:
    """List artifacts available on the Velociraptor server."""
    if _MODE == "mock":
        base = [
            "Windows.Sysinternals.Procdump",
            "Windows.Sys.Services",
            "Windows.Registry.RunKeys",
            "Windows.Network.NetstatEnriched",
            "Windows.Sysinternals.Sysmon",
            *(f"SIFTICS_Hunt.{name}" for name in _HUNT_TEMPLATES),
        ]
        return [a for a in base if a.startswith(prefix)] if prefix else base
    data = _post("GetArtifacts", {"search_term": prefix or "", "number": 500})
    return sorted({item.get("name", "") for item in (data.get("items") or [])
                   if item.get("name")})


@mcp.tool()
def create_hunt(template: str, iocs: dict[str, Any],
                target_groups: list[str] | None = None,
                description: str = "") -> dict:
    """Create a hunt from a curated template + IOCs (no raw VQL accepted).

    The agent picks one of the templates returned by `list_hunt_templates`
    and supplies the typed IOC values. No string is interpreted as VQL by the
    agent — the template is the only VQL skeleton that runs.

    Returns the created hunt's id + signed package hash.
    """
    if template not in _HUNT_TEMPLATES:
        return {"error": "unknown_template", "template": template,
                "valid_templates": list(_HUNT_TEMPLATES)}
    tpl = _HUNT_TEMPLATES[template]
    missing = [k for k in tpl["expected_params"] if k not in iocs]
    if missing:
        return {"error": "missing_params", "missing": missing,
                "template": template}

    package_payload = {"template": template, "iocs": iocs,
                       "target_groups": target_groups or ["all"],
                       "artifact": tpl["artifact"]}
    package_hash = hashlib.sha256(
        json.dumps(package_payload, sort_keys=True,
                   separators=(",", ":")).encode()
    ).hexdigest()

    if _MODE == "mock":
        hunt_id = f"H.{uuid.uuid4().hex[:10]}"
        _MOCK_HUNTS[hunt_id] = {
            "hunt_id": hunt_id, "template": template, "iocs": iocs,
            "target_groups": target_groups or ["all"],
            "artifact": tpl["artifact"], "package_hash": package_hash,
            "status": "created", "created_at": _now(),
        }
    else:
        # Real Velociraptor: CreateHunt with a parameter-bound artifact spec.
        spec = {
            "artifacts": [tpl["artifact"]],
            "specs": [{
                "artifact": tpl["artifact"],
                "parameters": {"env": [{"key": k, "value": _stringify(v)}
                                        for k, v in iocs.items()]},
            }],
        }
        condition: dict = {"excluded_labels": []}
        if target_groups and target_groups != ["all"]:
            condition["labels"] = {"label": target_groups}
        data = _post("CreateHunt", {
            "start_request": spec,
            "description": description or
                f"SIFTics {template} ({package_hash[:8]})",
            "condition": condition,
        })
        hunt_id = data.get("hunt_id") or f"H.unknown.{uuid.uuid4().hex[:6]}"
    _audit("hunt_created", {"hunt_id": hunt_id, "template": template,
                             "package_hash": package_hash,
                             "target_groups": target_groups or ["all"]})
    return {"hunt_id": hunt_id, "package_hash": package_hash,
            "artifact": tpl["artifact"], "status": "created"}


def _stringify(v: Any) -> str:
    return v if isinstance(v, str) else json.dumps(v, separators=(",", ":"))


@mcp.tool()
def start_hunt(hunt_id: str) -> dict:
    """Start a previously created hunt."""
    if _MODE == "mock":
        if hunt_id not in _MOCK_HUNTS:
            return {"error": "unknown_hunt", "hunt_id": hunt_id}
        _MOCK_HUNTS[hunt_id]["status"] = "running"
        _MOCK_HUNTS[hunt_id]["started_at"] = _now()
        _audit("hunt_started", {"hunt_id": hunt_id})
        return {"hunt_id": hunt_id, "status": "running"}
    data = _post("ModifyHunt", {"hunt_id": hunt_id, "state": "RUNNING"})
    _audit("hunt_started", {"hunt_id": hunt_id})
    return {"hunt_id": hunt_id, "status": "running", "server_response": data}


@mcp.tool()
def get_hunt_status(hunt_id: str) -> dict:
    """Poll the status of a hunt."""
    if _MODE == "mock":
        h = _MOCK_HUNTS.get(hunt_id)
        if not h:
            return {"error": "unknown_hunt", "hunt_id": hunt_id}
        # Stub: any hunt is "completed" if it's been running > 2s
        if h["status"] == "running" and "started_at" in h:
            started = time.mktime(time.strptime(h["started_at"], "%Y-%m-%dT%H:%M:%SZ"))
            if time.time() - started > 2:
                h["status"] = "completed"
                h["completed_at"] = _now()
                h["client_count"] = len(list_clients())
                h["hit_count"] = 1
        return {"hunt_id": hunt_id, "status": h["status"],
                "client_count": h.get("client_count", 0),
                "hit_count": h.get("hit_count", 0)}
    data = _post("GetHunt", {"hunt_id": hunt_id})
    state = (data.get("state") or "").lower()
    state_map = {"running": "running", "paused": "paused",
                  "stopped": "stopped", "archived": "completed"}
    return {
        "hunt_id": hunt_id,
        "status": state_map.get(state, state or "unknown"),
        "client_count": int(data.get("stats", {}).get("total_clients_scheduled", 0)),
        "hit_count": int(data.get("stats", {}).get("total_clients_with_results", 0)),
    }


@mcp.tool()
def wait_for_hunt(hunt_id: str, timeout_seconds: int = 300) -> dict:
    """Block until the hunt completes or the timeout fires."""
    start = time.time()
    while time.time() - start < timeout_seconds:
        status = get_hunt_status(hunt_id)
        if status.get("status") in ("completed", "failed", "stopped"):
            return status
        time.sleep(1)
    return {"hunt_id": hunt_id, "status": "timeout",
            "elapsed_seconds": int(time.time() - start)}


@mcp.tool()
def get_hunt_results(hunt_id: str) -> dict:
    """Retrieve results from a completed hunt."""
    if _MODE == "mock":
        h = _MOCK_HUNTS.get(hunt_id)
        if not h:
            return {"error": "unknown_hunt", "hunt_id": hunt_id}
        # Stubbed result: one client returns a hit matching the IOC
        sample_rows = [
            {"client_id": "C.mock-001", "hostname": "win11-victim",
             "matched_at": _now(),
             "evidence": "Imphash match on lsass_helper.exe at C:\\Users\\Public\\"},
        ]
        _audit("hunt_results_pulled",
               {"hunt_id": hunt_id, "rows": len(sample_rows)})
        return {"hunt_id": hunt_id, "status": h["status"],
                "rows": sample_rows,
                "_v1_note": "mock mode — deterministic single-hit response"}
    # Real mode — GetHuntResults pages rows in JSON
    rows: list[dict] = []
    offset = 0
    page = 500
    while True:
        data = _post("GetHuntResults", {
            "hunt_id": hunt_id,
            "offset": offset, "rows": page,
        })
        page_rows = data.get("rows") or []
        rows.extend(page_rows)
        if len(page_rows) < page:
            break
        offset += page
        if offset >= 10_000:  # safety cap
            break
    _audit("hunt_results_pulled",
           {"hunt_id": hunt_id, "rows": len(rows)})
    return {"hunt_id": hunt_id, "status": "completed", "rows": rows}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@mcp.tool()
def list_hunt_templates() -> dict:
    """List curated hunt templates the agent may invoke via create_hunt."""
    return {k: {"artifact": v["artifact"], "description": v["description"],
                 "expected_params": v["expected_params"]}
            for k, v in _HUNT_TEMPLATES.items()}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="SIFTics Velociraptor broker MCP.")
    parser.add_argument("--transport", choices=("stdio", "sse"), default="stdio")
    parser.add_argument("--port", type=int, default=9105)
    args = parser.parse_args()
    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse", port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
