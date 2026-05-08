"""Configuration loader for the SIFTics MCP broker.

Config sources (in priority order):
  1. Path passed to load_config()
  2. $SIFTICS_MCP_CONFIG environment variable
  3. ./mcp_broker/config/config.yaml relative to CWD
  4. ~/.config/siftics/mcp_broker.yaml

Returns a frozen, validated Config dataclass. Missing optional fields use
sensible defaults; missing required fields raise ConfigError.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Optional

import yaml


class ConfigError(RuntimeError):
    """Raised when configuration is missing required fields."""


@dataclasses.dataclass(frozen=True)
class VelociraptorConfig:
    """Velociraptor server connection settings.

    The agent never sees the api_key directly — it's loaded from disk and
    held server-side. The agent only sees typed function results.
    """

    api_url: str  # e.g. "https://192.168.56.50:8889"
    api_key_path: Optional[str] = None  # path to file containing API key
    verify_tls: bool = False  # most lab Velociraptor instances use self-signed
    org_id: str = "root"
    request_timeout_s: int = 30
    poll_interval_s: int = 5
    max_poll_iterations: int = 60  # ~5 min default at 5s intervals


@dataclasses.dataclass(frozen=True)
class AuditConfig:
    """Per-call audit log settings."""

    log_path: str = "./mcp_broker/audit.jsonl"
    enabled: bool = True


@dataclasses.dataclass(frozen=True)
class Config:
    """Top-level broker config."""

    velociraptor: VelociraptorConfig
    audit: AuditConfig


def _candidate_paths() -> list[Path]:
    candidates = []
    env_path = os.environ.get("SIFTICS_MCP_CONFIG")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path.cwd() / "mcp_broker" / "config" / "config.yaml")
    candidates.append(
        Path.home() / ".config" / "siftics" / "mcp_broker.yaml"
    )
    return candidates


def load_config(path: Optional[str] = None) -> Config:
    """Load broker config from YAML. Required: velociraptor.api_url."""
    target: Optional[Path] = Path(path) if path else None
    if target is None:
        for c in _candidate_paths():
            if c.is_file():
                target = c
                break
    if target is None or not target.is_file():
        raise ConfigError(
            "No config found. Set $SIFTICS_MCP_CONFIG, place "
            "mcp_broker/config/config.yaml, or pass path explicitly. "
            "See mcp_broker/config/config.example.yaml for the schema."
        )

    with open(target, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    vr_raw = raw.get("velociraptor", {})
    if not vr_raw.get("api_url"):
        raise ConfigError(
            f"Config {target}: velociraptor.api_url is required"
        )

    vr = VelociraptorConfig(
        api_url=vr_raw["api_url"].rstrip("/"),
        api_key_path=vr_raw.get("api_key_path"),
        verify_tls=bool(vr_raw.get("verify_tls", False)),
        org_id=vr_raw.get("org_id", "root"),
        request_timeout_s=int(vr_raw.get("request_timeout_s", 30)),
        poll_interval_s=int(vr_raw.get("poll_interval_s", 5)),
        max_poll_iterations=int(vr_raw.get("max_poll_iterations", 60)),
    )

    audit_raw = raw.get("audit", {})
    audit = AuditConfig(
        log_path=audit_raw.get("log_path", "./mcp_broker/audit.jsonl"),
        enabled=bool(audit_raw.get("enabled", True)),
    )

    return Config(velociraptor=vr, audit=audit)
