"""Velociraptor API-key loading.

Velociraptor's API uses a self-signed gRPC client cert + key bundle, generated
by `velociraptor config api_client`. The output is a JSON document with
ca_certificate, client_cert, client_private_key, and api_connection_string.

This module reads that JSON file, validates it has the expected fields, and
returns a structured object the velociraptor tool module can use to make
authenticated requests. The agent NEVER sees the raw cert/key — only typed
function results.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Optional


class AuthError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class VelociraptorAuth:
    ca_certificate: str
    client_cert: str
    client_private_key: str
    api_connection_string: Optional[str] = None  # host:port, optional


def load_velociraptor_api_key(path: Optional[str]) -> Optional[VelociraptorAuth]:
    """Load Velociraptor API client bundle. Returns None if path is None
    (so the caller can fall back to anonymous/test mode for development)."""
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        raise AuthError(
            f"Velociraptor API key file not found: {p}. "
            "Generate with: velociraptor --config server.config.yaml config "
            "api_client --name siftics-broker --role investigator"
        )
    try:
        with open(p, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except json.JSONDecodeError as exc:
        raise AuthError(f"API key file {p} is not valid JSON: {exc}") from exc

    required = ("ca_certificate", "client_cert", "client_private_key")
    missing = [f for f in required if f not in raw or not raw[f]]
    if missing:
        raise AuthError(
            f"API key file {p} missing required fields: {missing}. "
            "Re-generate with `velociraptor config api_client`."
        )

    return VelociraptorAuth(
        ca_certificate=raw["ca_certificate"],
        client_cert=raw["client_cert"],
        client_private_key=raw["client_private_key"],
        api_connection_string=raw.get("api_connection_string"),
    )
