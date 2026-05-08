"""Velociraptor MCP tool — typed-function gateway to a Velociraptor server.

Architectural intent: the agent calls scoped, typed functions
(pull_offline_collection, upload_artifact, create_hunt, ...) instead of
arbitrary VQL or shell commands. The broker's INTERNAL implementation may
shell out to the `velociraptor` CLI binary, but the agent's interface is
fixed and constrained — it cannot exec arbitrary commands or send free-form
VQL.

Implementation strategy:
- Use the `velociraptor` CLI binary in subprocess form, with --api_config
  pointing at an api_client config. CLI args are programmatically constructed
  (no shell=True, no string interpolation of agent-supplied values into
  command strings). All agent input is passed as positional argv elements.
- Optional MOCK_MODE for testing without a real Velociraptor server. Returns
  realistic canned responses so the rest of the SIFTics pipeline (orchestrator
  + findings_to_hunt + ingest) can be developed and demonstrated without VR
  being deployed.

Function catalog (the agent's full surface area):
    list_clients(name_filter)
    get_client(client_id)
    pull_offline_collection(client_id, output_path, artifact_pack)
    upload_artifact(name, vql_yaml)
    create_hunt(name, artifact_name, parameters, expires_hours)
    start_hunt(hunt_id, client_filter)
    get_hunt_status(hunt_id)
    get_hunt_results(hunt_id, artifact_name)
    wait_for_hunt(hunt_id, timeout_s)
    list_artifacts(name_filter)
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from .. import audit, config


# ── module state ────────────────────────────────────────────────────────────

_CFG: Optional[config.Config] = None
_MOCK: bool = False


def init(cfg: Optional[config.Config] = None, mock: Optional[bool] = None) -> None:
    """Initialize module state. Called by the MCP server on startup, or by
    direct callers (CLI, scripts). Safe to re-call."""
    global _CFG, _MOCK
    if cfg is not None:
        _CFG = cfg
    if mock is not None:
        _MOCK = mock
    elif os.environ.get("SIFTICS_MCP_MOCK") == "1":
        _MOCK = True


def _require_cfg() -> config.Config:
    global _CFG
    if _CFG is None:
        if _MOCK or os.environ.get("SIFTICS_MCP_MOCK") == "1":
            # Mock mode: provide a default in-memory config so callers
            # don't need a YAML file just to test the typed-function surface.
            _CFG = config.Config(
                velociraptor=config.VelociraptorConfig(
                    api_url="https://mock.invalid",
                    api_key_path=None,
                    verify_tls=False,
                ),
                audit=config.AuditConfig(
                    log_path=os.environ.get(
                        "SIFTICS_MCP_AUDIT_LOG",
                        "./mcp_broker/audit.jsonl",
                    ),
                    enabled=True,
                ),
            )
        else:
            init(cfg=config.load_config())
    assert _CFG is not None
    return _CFG


def _audit_path() -> str:
    return _require_cfg().audit.log_path


def _vr_cli() -> str:
    """Locate the velociraptor binary. Override with $VELOCIRAPTOR_BIN."""
    explicit = os.environ.get("VELOCIRAPTOR_BIN")
    if explicit and Path(explicit).is_file():
        return explicit
    found = shutil.which("velociraptor")
    if found:
        return found
    raise RuntimeError(
        "velociraptor binary not found in PATH. Set $VELOCIRAPTOR_BIN or "
        "install: https://docs.velociraptor.app/downloads/"
    )


def _api_config_path() -> str:
    cfg = _require_cfg()
    p = cfg.velociraptor.api_key_path
    if not p or not Path(p).is_file():
        raise RuntimeError(
            f"Velociraptor api_config not found: {p}. Generate with: "
            "velociraptor --config server.config.yaml config api_client "
            "--name siftics-broker --role investigator > api_client.yaml"
        )
    return p


def _run_velociraptor(args: list[str], input_data: Optional[str] = None,
                      timeout_s: Optional[int] = None) -> tuple[int, str, str]:
    """Run the velociraptor CLI as a subprocess with controlled argv.
    Returns (returncode, stdout, stderr). Never uses shell=True."""
    cfg = _require_cfg()
    cmd = [_vr_cli(), "--api_config", _api_config_path()] + args
    timeout = timeout_s or cfg.velociraptor.request_timeout_s
    proc = subprocess.run(
        cmd,
        input=input_data,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _query_vql(vql: str, env: Optional[dict[str, str]] = None) -> list[dict[str, Any]]:
    """Run a VQL query through the CLI. Returns parsed JSON rows.
    Used internally — NOT exposed to the agent (the agent's interface is
    typed functions only)."""
    args = ["query", "--format", "json"]
    if env:
        for k, v in env.items():
            args.extend(["--env", f"{k}={v}"])
    args.append(vql)
    rc, out, err = _run_velociraptor(args)
    if rc != 0:
        raise RuntimeError(f"velociraptor query failed (rc={rc}): {err.strip()[:500]}")
    if not out.strip():
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # CLI sometimes emits one JSON object per line for streaming results
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
        return rows


# ── mock-mode fixtures ──────────────────────────────────────────────────────

_MOCK_CLIENTS = [
    {"client_id": "C.1111aaaa", "os_info.hostname": "win11-victim",
     "os_info.system": "Windows", "last_seen_at": "2026-05-08T10:00:00Z"},
    {"client_id": "C.2222bbbb", "os_info.hostname": "win11-victim-02",
     "os_info.system": "Windows", "last_seen_at": "2026-05-08T10:01:00Z"},
]
_MOCK_ARTIFACTS = [
    {"name": "Generic.System.Pstree", "description": "Process tree"},
    {"name": "Windows.Sys.Programs", "description": "Installed software"},
    {"name": "Generic.Forensic.LocalHashes.Glob", "description": "Hash files matching glob"},
    {"name": "Generic.Detection.Yara.Glob", "description": "YARA scan over glob"},
    {"name": "Windows.Network.Netstat", "description": "Active network connections"},
    {"name": "Windows.Registry.NTUser", "description": "NTUSER.DAT key inspection"},
    {"name": "Windows.System.TaskScheduler", "description": "Scheduled tasks"},
]


# ── typed functions (the agent's interface) ─────────────────────────────────


def list_clients(name_filter: Optional[str] = None) -> list[dict[str, Any]]:
    """List Velociraptor clients (endpoints with the agent installed).

    Args:
        name_filter: optional hostname substring; case-insensitive.

    Returns:
        List of dicts with at least: client_id, os_info.hostname, os_info.system,
        last_seen_at.
    """
    @audit.wrap(_audit_path(), "velociraptor.list_clients")
    def _impl(name_filter):
        if _MOCK:
            rows = list(_MOCK_CLIENTS)
        else:
            rows = _query_vql(
                "SELECT client_id, os_info.hostname, os_info.system, "
                "last_seen_at FROM clients()"
            )
        if name_filter:
            nf = name_filter.lower()
            rows = [r for r in rows
                    if nf in (r.get("os_info.hostname", "") or "").lower()]
        return rows
    return _impl(name_filter=name_filter)


def get_client(client_id: str) -> Optional[dict[str, Any]]:
    """Return one client by ID, or None if not found."""
    @audit.wrap(_audit_path(), "velociraptor.get_client")
    def _impl(client_id):
        if _MOCK:
            for c in _MOCK_CLIENTS:
                if c["client_id"] == client_id:
                    return c
            return None
        rows = _query_vql(
            f"SELECT * FROM clients() WHERE client_id = '{_safe_str(client_id)}'"
        )
        return rows[0] if rows else None
    return _impl(client_id=client_id)


def pull_offline_collection(
    client_id: str,
    output_path: str,
    artifact_pack: str = "Generic.Collectors.File",
    parameters: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Trigger a collection on the named client and download the result zip.

    For "live" agents: this runs an artifact collection via Velociraptor
    and streams the resulting flow data to disk.

    For pure offline mode (no live agent): this is a no-op stub that expects
    you to have manually generated an offline collector binary, run it on
    the target, and dropped the resulting zip at output_path. Use the
    `verify_collection` helper to confirm the file is present.

    Args:
        client_id: Velociraptor client ID (C.xxxxxxxx)
        output_path: where to write the collection zip
        artifact_pack: Velociraptor artifact name (default: Generic.Collectors.File)
        parameters: artifact parameters (e.g. file paths to collect)

    Returns:
        {"flow_id": "F.xxxx", "client_id": ..., "output_path": ...,
         "size_bytes": int, "status": "ok"}
    """
    @audit.wrap(_audit_path(), "velociraptor.pull_offline_collection")
    def _impl(client_id, output_path, artifact_pack, parameters):
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        if _MOCK:
            # Touch the output path so downstream callers see "a file"
            Path(output_path).write_bytes(b"MOCK_OFFLINE_COLLECTION_ZIP")
            return {
                "flow_id": "F.MOCK_FLOW",
                "client_id": client_id,
                "output_path": output_path,
                "size_bytes": Path(output_path).stat().st_size,
                "status": "ok-mock",
            }
        # Real path: run the artifact collection via VQL
        params_vql = ""
        if parameters:
            params_vql = ", env=dict(" + ", ".join(
                f"{_safe_str(k)}='{_safe_str(str(v))}'" for k, v in parameters.items()
            ) + ")"
        vql = (
            f"SELECT * FROM collect_client(client_id='{_safe_str(client_id)}', "
            f"artifacts=['{_safe_str(artifact_pack)}']{params_vql})"
        )
        rows = _query_vql(vql)
        if not rows:
            raise RuntimeError("collect_client returned no rows")
        flow_id = rows[0].get("flow_id") or rows[0].get("FlowId")
        # Now download the collection — using `velociraptor api collect`
        rc, out, err = _run_velociraptor(
            ["collect", flow_id, "--output", output_path],
            timeout_s=600,
        )
        if rc != 0:
            raise RuntimeError(f"download failed (rc={rc}): {err[:500]}")
        size = Path(output_path).stat().st_size if Path(output_path).is_file() else 0
        return {
            "flow_id": flow_id,
            "client_id": client_id,
            "output_path": output_path,
            "size_bytes": size,
            "status": "ok",
        }
    return _impl(
        client_id=client_id,
        output_path=output_path,
        artifact_pack=artifact_pack,
        parameters=parameters,
    )


def upload_artifact(name: str, vql_yaml: str) -> dict[str, Any]:
    """Push a custom Velociraptor artifact definition (YAML) to the server.

    Used by SIFTics to register hunt artifacts derived from analysis findings
    (e.g. SIFTICS_<case>_yara_<hash> with a YARA rule body extracted from
    findings_to_hunt.py output).

    Args:
        name: artifact name (must start with a custom prefix like SIFTICS_ to
              avoid colliding with built-in artifacts)
        vql_yaml: full artifact YAML body (parameters, sources, etc.)

    Returns:
        {"name": ..., "uploaded_at": ..., "status": "ok"}
    """
    @audit.wrap(_audit_path(), "velociraptor.upload_artifact")
    def _impl(name, vql_yaml):
        if not name.startswith(("SIFTICS_", "Custom.")):
            raise ValueError(
                "Custom artifact names must start with SIFTICS_ or Custom. "
                "Refusing to overwrite built-in artifact namespace."
            )
        if _MOCK:
            return {
                "name": name,
                "uploaded_at": _now(),
                "status": "ok-mock",
                "yaml_chars": len(vql_yaml),
            }
        # Pipe the YAML body to `velociraptor artifacts set --file -`
        rc, out, err = _run_velociraptor(
            ["artifacts", "set", "--file", "-"],
            input_data=vql_yaml,
            timeout_s=30,
        )
        if rc != 0:
            raise RuntimeError(f"upload_artifact failed (rc={rc}): {err[:500]}")
        return {
            "name": name,
            "uploaded_at": _now(),
            "status": "ok",
            "yaml_chars": len(vql_yaml),
        }
    return _impl(name=name, vql_yaml=vql_yaml)


def create_hunt(
    name: str,
    artifact_name: str,
    parameters: Optional[dict[str, Any]] = None,
    expires_hours: int = 24,
    description: Optional[str] = None,
) -> dict[str, Any]:
    """Create a hunt definition (does NOT start it — call start_hunt next).

    Args:
        name: hunt label
        artifact_name: name of the artifact to run (built-in or SIFTICS_*)
        parameters: artifact parameters
        expires_hours: hunt expires after this many hours
        description: optional human-readable description

    Returns:
        {"hunt_id": "H.xxxx", "status": "PAUSED", ...}
    """
    @audit.wrap(_audit_path(), "velociraptor.create_hunt")
    def _impl(name, artifact_name, parameters, expires_hours, description):
        if _MOCK:
            return {
                "hunt_id": f"H.MOCK_{int(time.time())}",
                "name": name,
                "artifact_name": artifact_name,
                "parameters": parameters or {},
                "status": "PAUSED",
                "created_at": _now(),
                "expires_at": _now(offset_hours=expires_hours),
            }
        params_vql = "dict()" if not parameters else (
            "dict(" + ", ".join(
                f"{_safe_key(k)}='{_safe_str(str(v))}'" for k, v in parameters.items()
            ) + ")"
        )
        expiry = int(time.time()) + (expires_hours * 3600)
        desc = description or f"SIFTics-generated hunt: {name}"
        vql = (
            f"SELECT hunt_id FROM hunt(description='{_safe_str(desc)}', "
            f"artifacts=['{_safe_str(artifact_name)}'], "
            f"env={params_vql}, expires={expiry})"
        )
        rows = _query_vql(vql)
        if not rows:
            raise RuntimeError("hunt() returned no rows")
        return {
            "hunt_id": rows[0].get("hunt_id") or rows[0].get("HuntId"),
            "name": name,
            "artifact_name": artifact_name,
            "parameters": parameters or {},
            "status": "PAUSED",
            "created_at": _now(),
            "expires_at": _now(offset_hours=expires_hours),
        }
    return _impl(
        name=name,
        artifact_name=artifact_name,
        parameters=parameters,
        expires_hours=expires_hours,
        description=description,
    )


def start_hunt(hunt_id: str, client_filter: Optional[str] = None) -> dict[str, Any]:
    """Activate a paused hunt.

    Args:
        hunt_id: hunt ID returned by create_hunt
        client_filter: optional VQL-safe substring filter on hostname (e.g. "win11")

    Returns:
        {"hunt_id": ..., "status": "RUNNING", "started_at": ...}
    """
    @audit.wrap(_audit_path(), "velociraptor.start_hunt")
    def _impl(hunt_id, client_filter):
        if _MOCK:
            return {"hunt_id": hunt_id, "status": "RUNNING",
                    "started_at": _now(), "client_filter": client_filter}
        # Use VQL to start the hunt
        vql = (
            f"SELECT * FROM hunt_start(hunt_id='{_safe_str(hunt_id)}')"
        )
        _query_vql(vql)
        return {"hunt_id": hunt_id, "status": "RUNNING",
                "started_at": _now(), "client_filter": client_filter}
    return _impl(hunt_id=hunt_id, client_filter=client_filter)


def get_hunt_status(hunt_id: str) -> dict[str, Any]:
    """Return current status: RUNNING / STOPPED / completion stats.

    Returns:
        {"hunt_id": ..., "state": "RUNNING|STOPPED|...", "clients_total": N,
         "clients_completed": N, "clients_with_results": N, "started_at": ...,
         "is_complete": bool}
    """
    @audit.wrap(_audit_path(), "velociraptor.get_hunt_status")
    def _impl(hunt_id):
        if _MOCK:
            # Simulate progress: first call RUNNING, then COMPLETED
            return {
                "hunt_id": hunt_id, "state": "STOPPED",
                "clients_total": 2, "clients_completed": 2,
                "clients_with_results": 1, "started_at": _now(offset_seconds=-30),
                "is_complete": True,
            }
        rows = _query_vql(
            f"SELECT * FROM hunts() WHERE hunt_id = '{_safe_str(hunt_id)}'"
        )
        if not rows:
            raise RuntimeError(f"hunt {hunt_id} not found")
        h = rows[0]
        state = h.get("state", "UNKNOWN")
        return {
            "hunt_id": hunt_id,
            "state": state,
            "clients_total": h.get("total_clients_scheduled", 0),
            "clients_completed": h.get("completed_clients", 0),
            "clients_with_results": h.get("clients_with_results", 0),
            "started_at": h.get("start_time"),
            "is_complete": state in ("STOPPED", "ARCHIVED"),
        }
    return _impl(hunt_id=hunt_id)


def get_hunt_results(
    hunt_id: str,
    artifact_name: Optional[str] = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Pull structured results from a hunt.

    Args:
        hunt_id: hunt ID
        artifact_name: filter to one artifact's results (default: all)
        limit: max rows to return (default 1000)

    Returns:
        List of result rows (dicts). Each row is one observation from one
        client, with fields specific to the artifact's schema.
    """
    @audit.wrap(_audit_path(), "velociraptor.get_hunt_results")
    def _impl(hunt_id, artifact_name, limit):
        if _MOCK:
            return [
                {"ClientId": "C.2222bbbb", "Hostname": "win11-victim-02",
                 "FullPath": "C:/Users/Public/svhost.exe",
                 "Hash.SHA256": "deadbeef" * 8, "match": True},
            ]
        artifact_clause = ""
        if artifact_name:
            artifact_clause = (
                f", artifact='{_safe_str(artifact_name)}'"
            )
        vql = (
            f"SELECT * FROM hunt_results(hunt_id='{_safe_str(hunt_id)}'"
            f"{artifact_clause}) LIMIT {int(limit)}"
        )
        return _query_vql(vql)
    return _impl(hunt_id=hunt_id, artifact_name=artifact_name, limit=limit)


def wait_for_hunt(hunt_id: str, timeout_s: Optional[int] = None) -> dict[str, Any]:
    """Poll get_hunt_status until is_complete or timeout. Returns final status."""
    @audit.wrap(_audit_path(), "velociraptor.wait_for_hunt")
    def _impl(hunt_id, timeout_s):
        cfg = _require_cfg()
        interval = cfg.velociraptor.poll_interval_s
        max_iter = cfg.velociraptor.max_poll_iterations
        if timeout_s:
            max_iter = max(1, timeout_s // interval)
        for _ in range(max_iter):
            status = get_hunt_status(hunt_id)
            if status.get("is_complete"):
                return status
            time.sleep(interval)
        return get_hunt_status(hunt_id)  # one final read
    return _impl(hunt_id=hunt_id, timeout_s=timeout_s)


def list_artifacts(name_filter: Optional[str] = None) -> list[dict[str, Any]]:
    """List artifact definitions known to the server.

    Useful for the agent to discover what hunt-able artifacts exist before
    constructing a custom one.
    """
    @audit.wrap(_audit_path(), "velociraptor.list_artifacts")
    def _impl(name_filter):
        if _MOCK:
            rows = list(_MOCK_ARTIFACTS)
        else:
            rows = _query_vql(
                "SELECT name, description FROM artifact_definitions()"
            )
        if name_filter:
            nf = name_filter.lower()
            rows = [r for r in rows if nf in (r.get("name", "") or "").lower()]
        return rows
    return _impl(name_filter=name_filter)


# ── helpers ─────────────────────────────────────────────────────────────────

_VQL_UNSAFE_CHARS = set("'\"\\;\n\r")


def _safe_str(s: str) -> str:
    """Escape a string for inclusion in a single-quoted VQL string literal.
    Defense-in-depth — agent inputs go through this before being injected
    into VQL. Strict whitelist: rejects strings with VQL-reserved chars."""
    if not isinstance(s, str):
        s = str(s)
    if any(c in _VQL_UNSAFE_CHARS for c in s):
        raise ValueError(
            f"VQL unsafe character in input: {s!r}. Refusing to inject."
        )
    return s


def _safe_key(k: str) -> str:
    """Validate a VQL identifier (parameter key)."""
    if not isinstance(k, str) or not k.replace("_", "").isalnum():
        raise ValueError(f"Invalid VQL identifier: {k!r}")
    return k


def _now(offset_seconds: int = 0, offset_hours: int = 0) -> str:
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        seconds=offset_seconds, hours=offset_hours
    )
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── CLI mode (run individual functions without an MCP server) ──────────────


def _cli():
    """Standalone CLI for testing / scripting without an MCP server.
    Usage: python -m mcp_broker.tools.velociraptor <function> [k=v ...]"""
    import sys

    if len(sys.argv) < 2:
        # List available functions
        functions = [n for n in globals()
                     if not n.startswith("_") and callable(globals()[n])
                     and n not in ("init",)]
        print("Available functions:")
        for f in sorted(functions):
            print(f"  {f}")
        print("\nUsage: python -m mcp_broker.tools.velociraptor <fn> key=value ...")
        sys.exit(0)

    fn_name = sys.argv[1]
    if fn_name not in globals() or not callable(globals()[fn_name]):
        print(f"unknown function: {fn_name}", file=sys.stderr)
        sys.exit(2)

    kwargs: dict[str, Any] = {}
    for arg in sys.argv[2:]:
        if "=" not in arg:
            print(f"args must be key=value, got: {arg}", file=sys.stderr)
            sys.exit(2)
        k, v = arg.split("=", 1)
        # Try to parse as JSON for ints/bools/lists; else string
        try:
            kwargs[k] = json.loads(v)
        except json.JSONDecodeError:
            kwargs[k] = v

    init()  # load config or mock mode
    result = globals()[fn_name](**kwargs)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    _cli()
