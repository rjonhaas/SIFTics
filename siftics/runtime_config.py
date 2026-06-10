"""Agent-runtime configuration: which LLM, which models, which budget.

Two layers (per-case overrides per-user defaults):
    1. ~/.config/siftics/agent.yaml          user default
    2. $SIFTICS_CASE_DIR/agent.yaml          per-case override (optional)

API-key resolution cascade:
    1. OS keychain (libsecret via `keyring` library) — preferred
    2. Environment variable named in `api_key_env`
    3. Plain file path in `api_key_file` (mode 0600 recommended) — fallback
    Never store keys directly in agent.yaml.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

Runtime = Literal[
    "claude_code",      # user's existing claude CLI subscription
    "codex",            # user's existing codex CLI
    "anthropic_api",    # in-process; we host the chat loop
    "openai_api",       # in-process; we host the chat loop
    "ollama",           # in-process; local LLM
]

DEFAULT_USER_CONFIG = Path.home() / ".config" / "siftics" / "agent.yaml"


@dataclass
class ModelRouting:
    """Which model to use for which task class."""
    investigator: str = "claude-sonnet-4-6"
    classifier: str = "claude-haiku-4-5-20251001"
    synthesizer: str = "claude-sonnet-4-6"
    deep_review: str = "claude-opus-4-7"


@dataclass
class AnthropicConfig:
    api_key_env: str = "SIFTICS_ANTHROPIC_KEY"
    api_key_file: str | None = None
    api_key_keyring_service: str = "siftics_anthropic"
    api_key_keyring_user: str = "default"
    models: ModelRouting = field(default_factory=ModelRouting)
    prompt_caching: bool = True
    max_tokens: int = 4096


@dataclass
class OpenAIConfig:
    api_key_env: str = "SIFTICS_OPENAI_KEY"
    api_key_file: str | None = None
    api_key_keyring_service: str = "siftics_openai"
    api_key_keyring_user: str = "default"
    models: ModelRouting = field(default_factory=lambda: ModelRouting(
        investigator="gpt-5",
        classifier="gpt-5-mini",
        synthesizer="gpt-5",
        deep_review="gpt-5",
    ))
    max_tokens: int = 4096


@dataclass
class OllamaConfig:
    endpoint: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5-coder:32b"   # tool-use-capable; recommend ≥30B for IR work
    max_tokens: int = 4096
    timeout_seconds: int = 120


@dataclass
class ClaudeCodeConfig:
    """Claude Code mode — user runs `claude` themselves; we just register MCP servers."""
    mcp_config_path: str = "~/.claude/settings.json"


@dataclass
class CodexConfig:
    mcp_config_path: str = "~/.config/codex/config.toml"


@dataclass
class IntegrationKey:
    """Generic credential descriptor for external services.

    All three resolution paths share the same security posture:
      1. OS keychain (libsecret via `keyring` library) — preferred
      2. Environment variable named in `api_key_env`
      3. Plain file at `api_key_file` (chmod 0600) — fallback only

    The raw key VALUE is never written to agent.yaml, never logged in the
    forensic audit chain, and never returned by any MCP tool.
    """
    api_key_env: str = ""
    api_key_file: str | None = None
    api_key_keyring_service: str = ""
    api_key_keyring_user: str = "default"
    configured: bool = False  # True once a key has been saved (UI hint only)


@dataclass
class IntegrationsConfig:
    """Optional external service credentials. None are required.

    Each integration degrades gracefully when its key is absent — the
    corresponding MCP tool returns an empty result and the agent records
    the gap rather than failing.
    """
    shodan: IntegrationKey = field(default_factory=lambda: IntegrationKey(
        api_key_env="SIFTICS_SHODAN_API_KEY",
        api_key_keyring_service="siftics_shodan",
    ))
    virustotal: IntegrationKey = field(default_factory=lambda: IntegrationKey(
        api_key_env="SIFTICS_VT_API_KEY",
        api_key_keyring_service="siftics_virustotal",
    ))
    osm: IntegrationKey = field(default_factory=lambda: IntegrationKey(
        api_key_env="SIFTICS_OSM_API_KEY",
        api_key_keyring_service="siftics_osm",
    ))


@dataclass
class VelociraptorTarget:
    """Velociraptor server — destination for execute_hunt_package gate.

    Authentication is mutual TLS via the standard Velociraptor client
    cert / key / CA bundle. File paths are not sensitive (just locations)
    and live in agent.yaml; the cert files themselves are chmod 0600 on
    disk under ~/.config/siftics/velociraptor/.
    """
    enabled: bool = False
    api_url: str = ""                # e.g. https://velo.example.com:8000
    client_cert_path: str = ""       # ~/.config/siftics/velociraptor/client.pem
    client_key_path: str = ""        # ~/.config/siftics/velociraptor/client.key
    ca_cert_path: str = ""           # ~/.config/siftics/velociraptor/ca.pem


@dataclass
class ElasticTarget:
    """Elastic SIEM — destination for publish_intel gate (push IOCs to a
    threat-intel index).

    The api_key is stored in the OS keychain (siftics_elastic service).
    """
    enabled: bool = False
    url: str = ""                    # e.g. https://es.example.com:9200
    index: str = "siftics-iocs"
    verify_tls: bool = True
    api_key: IntegrationKey = field(default_factory=lambda: IntegrationKey(
        api_key_env="SIFTICS_ELASTIC_API_KEY",
        api_key_keyring_service="siftics_elastic",
    ))


@dataclass
class EntraIDTarget:
    """Microsoft Entra ID (Azure AD) — identity response target.

    For the containment_action gate: revoke session tokens, reset password,
    disable account. v1 is stubbed — the gate fires, the intent is logged
    in the audit chain, but no Graph API call is made unless the operator
    explicitly enables live mode.

    Authentication uses the OAuth2 client credentials flow:
      tenant_id: the M365 tenant GUID
      client_id: the app registration client ID
      client_secret: the app registration secret (keyring-stored)
    """
    enabled: bool = False
    live_mode: bool = False          # False = log intent only (recommended)
    tenant_id: str = ""
    client_id: str = ""
    client_secret: IntegrationKey = field(default_factory=lambda: IntegrationKey(
        api_key_env="SIFTICS_ENTRA_CLIENT_SECRET",
        api_key_keyring_service="siftics_entra",
    ))


@dataclass
class ResponseTargetsConfig:
    """Connection profiles for the systems that authority gates fire against.

    None of these are required — gates produce a structured action checklist
    as their universal output. The targets below upgrade the checklist from
    "recommended actions" to "executed actions" when configured and enabled.
    """
    velociraptor: VelociraptorTarget = field(default_factory=VelociraptorTarget)
    elastic: ElasticTarget = field(default_factory=ElasticTarget)
    entra_id: EntraIDTarget = field(default_factory=EntraIDTarget)


@dataclass
class RuntimeConfig:
    runtime: Runtime = "claude_code"
    anthropic: AnthropicConfig = field(default_factory=AnthropicConfig)
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    claude_code: ClaudeCodeConfig = field(default_factory=ClaudeCodeConfig)
    codex: CodexConfig = field(default_factory=CodexConfig)
    integrations: IntegrationsConfig = field(default_factory=IntegrationsConfig)
    response_targets: ResponseTargetsConfig = field(default_factory=ResponseTargetsConfig)
    # Per-case budget in USD; 0 disables the circuit breaker.
    # Ollama runs always have cost = 0 so this is effectively ignored.
    cost_budget_per_case_usd: float = 10.0
    warn_at_pct: int = 80


# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------


def _from_dict(cls, data: dict | None):
    """Recursively build a dataclass from a dict (or default if missing)."""
    if data is None:
        return cls()
    if cls is ModelRouting:
        return ModelRouting(**{k: v for k, v in data.items() if v is not None})
    kwargs: dict = {}
    for fname, ftype in cls.__annotations__.items():
        v = data.get(fname)
        if fname == "models" and isinstance(v, dict):
            kwargs[fname] = ModelRouting(**v)
        elif v is None:
            continue
        else:
            kwargs[fname] = v
    return cls(**kwargs)


def load_config(case_dir: Path | str | None = None,
                user_config: Path | None = None) -> RuntimeConfig:
    """Load user default, then merge per-case override if present."""
    user_path = Path(user_config) if user_config else DEFAULT_USER_CONFIG
    data: dict = {}
    if user_path.exists():
        data = yaml.safe_load(user_path.read_text(encoding="utf-8")) or {}

    if case_dir:
        case_yaml = Path(case_dir) / "agent.yaml"
        if case_yaml.exists():
            override = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
            data = _deep_merge(data, override)

    return _build_config(data)


def _deep_merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _build_integrations(data: dict | None) -> IntegrationsConfig:
    if not data:
        return IntegrationsConfig()
    defaults = IntegrationsConfig()
    out = IntegrationsConfig(
        shodan=_merge_integration_key(defaults.shodan, data.get("shodan")),
        virustotal=_merge_integration_key(defaults.virustotal, data.get("virustotal")),
        osm=_merge_integration_key(defaults.osm, data.get("osm")),
    )
    return out


def _merge_integration_key(default: IntegrationKey, data: dict | None) -> IntegrationKey:
    if not data:
        return default
    return IntegrationKey(
        api_key_env=data.get("api_key_env") or default.api_key_env,
        api_key_file=data.get("api_key_file") or default.api_key_file,
        api_key_keyring_service=data.get("api_key_keyring_service") or default.api_key_keyring_service,
        api_key_keyring_user=data.get("api_key_keyring_user") or default.api_key_keyring_user,
        configured=bool(data.get("configured", False)),
    )


def _build_response_targets(data: dict | None) -> ResponseTargetsConfig:
    if not data:
        return ResponseTargetsConfig()
    defaults = ResponseTargetsConfig()
    out = ResponseTargetsConfig()
    if vd := data.get("velociraptor"):
        out.velociraptor = VelociraptorTarget(
            enabled=bool(vd.get("enabled", False)),
            api_url=vd.get("api_url", ""),
            client_cert_path=vd.get("client_cert_path", ""),
            client_key_path=vd.get("client_key_path", ""),
            ca_cert_path=vd.get("ca_cert_path", ""),
        )
    if ed := data.get("elastic"):
        out.elastic = ElasticTarget(
            enabled=bool(ed.get("enabled", False)),
            url=ed.get("url", ""),
            index=ed.get("index", "siftics-iocs"),
            verify_tls=bool(ed.get("verify_tls", True)),
            api_key=_merge_integration_key(defaults.elastic.api_key, ed.get("api_key")),
        )
    if nd := data.get("entra_id"):
        out.entra_id = EntraIDTarget(
            enabled=bool(nd.get("enabled", False)),
            live_mode=bool(nd.get("live_mode", False)),
            tenant_id=nd.get("tenant_id", ""),
            client_id=nd.get("client_id", ""),
            client_secret=_merge_integration_key(defaults.entra_id.client_secret, nd.get("client_secret")),
        )
    return out


def _build_config(data: dict) -> RuntimeConfig:
    return RuntimeConfig(
        runtime=data.get("runtime", "claude_code"),
        anthropic=_from_dict(AnthropicConfig, data.get("anthropic")),
        openai=_from_dict(OpenAIConfig, data.get("openai")),
        ollama=_from_dict(OllamaConfig, data.get("ollama")),
        claude_code=_from_dict(ClaudeCodeConfig, data.get("claude_code")),
        codex=_from_dict(CodexConfig, data.get("codex")),
        integrations=_build_integrations(data.get("integrations")),
        response_targets=_build_response_targets(data.get("response_targets")),
        cost_budget_per_case_usd=float(data.get("cost_budget_per_case_usd", 10.0)),
        warn_at_pct=int(data.get("warn_at_pct", 80)),
    )


def save_config(cfg: RuntimeConfig, path: Path | None = None) -> Path:
    target = path or DEFAULT_USER_CONFIG
    target.parent.mkdir(parents=True, exist_ok=True)
    out = {
        "runtime": cfg.runtime,
        "cost_budget_per_case_usd": cfg.cost_budget_per_case_usd,
        "warn_at_pct": cfg.warn_at_pct,
        "anthropic": _asdict_clean(cfg.anthropic),
        "openai": _asdict_clean(cfg.openai),
        "ollama": _asdict_clean(cfg.ollama),
        "claude_code": _asdict_clean(cfg.claude_code),
        "codex": _asdict_clean(cfg.codex),
        "integrations": _asdict_clean(cfg.integrations),
        "response_targets": _asdict_clean(cfg.response_targets),
    }
    target.write_text(yaml.safe_dump(out, sort_keys=False), encoding="utf-8")
    os.chmod(target, 0o600)
    return target


def _asdict_clean(obj) -> dict:
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _asdict_clean(getattr(obj, k)) for k in obj.__dataclass_fields__}
    return obj


# ---------------------------------------------------------------------------
# API-key resolution
# ---------------------------------------------------------------------------


class MissingAPIKey(Exception):
    pass


def resolve_anthropic_key(cfg: AnthropicConfig) -> str:
    return _resolve_key(cfg.api_key_env, cfg.api_key_file,
                        cfg.api_key_keyring_service, cfg.api_key_keyring_user)


def resolve_openai_key(cfg: OpenAIConfig) -> str:
    return _resolve_key(cfg.api_key_env, cfg.api_key_file,
                        cfg.api_key_keyring_service, cfg.api_key_keyring_user)


def _resolve_key(env_name: str, file_path: str | None,
                 keyring_service: str, keyring_user: str) -> str:
    # 1. Keyring
    try:
        import keyring  # type: ignore
        kv = keyring.get_password(keyring_service, keyring_user)
        if kv:
            return kv
    except Exception:
        pass

    # 2. Env var
    ev = os.environ.get(env_name)
    if ev:
        return ev

    # 3. File
    if file_path:
        p = Path(file_path).expanduser()
        if p.exists():
            return p.read_text(encoding="utf-8").strip()

    raise MissingAPIKey(
        f"API key not found via keyring service '{keyring_service}', "
        f"env var '{env_name}', or file '{file_path}'."
    )


def save_anthropic_key(cfg: AnthropicConfig, key: str) -> str:
    """Try keyring first; fall back to a chmod 600 file. Returns the location used."""
    try:
        import keyring  # type: ignore
        keyring.set_password(cfg.api_key_keyring_service, cfg.api_key_keyring_user, key)
        return f"keyring:{cfg.api_key_keyring_service}/{cfg.api_key_keyring_user}"
    except Exception:
        pass

    target = Path(cfg.api_key_file or "~/.config/siftics/anthropic.key").expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(key.strip() + "\n", encoding="utf-8")
    os.chmod(target, 0o600)
    cfg.api_key_file = str(target)
    return f"file:{target}"


def resolve_integration_key(cfg: IntegrationKey) -> str:
    """Resolve an integration credential. Same precedence as Anthropic/OpenAI."""
    return _resolve_key(cfg.api_key_env, cfg.api_key_file,
                        cfg.api_key_keyring_service, cfg.api_key_keyring_user)


def save_integration_key(cfg: IntegrationKey, key: str, fallback_filename: str) -> str:
    """Persist an integration credential. Returns the storage location string
    (suitable for audit logging — describes WHERE the key lives, never its VALUE).

    Tries OS keychain first; falls back to a chmod 0600 file under
    ~/.config/siftics/<fallback_filename>.
    """
    key = key.strip()
    if not key:
        raise ValueError("empty key")
    try:
        import keyring  # type: ignore
        keyring.set_password(cfg.api_key_keyring_service,
                              cfg.api_key_keyring_user, key)
        cfg.configured = True
        return f"keyring:{cfg.api_key_keyring_service}/{cfg.api_key_keyring_user}"
    except Exception:
        pass

    target = Path(cfg.api_key_file or f"~/.config/siftics/{fallback_filename}").expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(key + "\n", encoding="utf-8")
    os.chmod(target, 0o600)
    cfg.api_key_file = str(target)
    cfg.configured = True
    return f"file:{target}"


def integration_key_present(cfg: IntegrationKey) -> bool:
    """Check whether a key is available without exposing its value."""
    try:
        resolve_integration_key(cfg)
        return True
    except MissingAPIKey:
        return False
    except Exception:
        return False


def clear_integration_key(cfg: IntegrationKey) -> None:
    """Remove a stored integration key from both keyring and file fallback."""
    try:
        import keyring  # type: ignore
        try:
            keyring.delete_password(cfg.api_key_keyring_service, cfg.api_key_keyring_user)
        except Exception:
            pass
    except ImportError:
        pass
    if cfg.api_key_file:
        p = Path(cfg.api_key_file).expanduser()
        if p.exists():
            p.unlink()
    cfg.configured = False
