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
class RuntimeConfig:
    runtime: Runtime = "claude_code"
    anthropic: AnthropicConfig = field(default_factory=AnthropicConfig)
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    claude_code: ClaudeCodeConfig = field(default_factory=ClaudeCodeConfig)
    codex: CodexConfig = field(default_factory=CodexConfig)
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


def _build_config(data: dict) -> RuntimeConfig:
    return RuntimeConfig(
        runtime=data.get("runtime", "claude_code"),
        anthropic=_from_dict(AnthropicConfig, data.get("anthropic")),
        openai=_from_dict(OpenAIConfig, data.get("openai")),
        ollama=_from_dict(OllamaConfig, data.get("ollama")),
        claude_code=_from_dict(ClaudeCodeConfig, data.get("claude_code")),
        codex=_from_dict(CodexConfig, data.get("codex")),
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
