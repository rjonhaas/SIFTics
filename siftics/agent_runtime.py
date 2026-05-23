"""Pluggable agent runtimes.

Each implementation of AgentRuntime exposes the same minimal surface to the
SIFTics chat panel and CLI. The MCP server layer is shared; only the agent
loop differs per backend.

Implementations in this module:
    AnthropicRuntime       in-process chat loop using the anthropic SDK
                           (prompt caching enabled, cost tracking enabled)
    OllamaRuntime          in-process chat loop against a local Ollama
                           server's OpenAI-compatible endpoint
                           (cost always 0; smaller models may struggle with
                           multi-step tool use)
    ClaudeCodeRuntime      no in-process loop — registers MCP servers into
                           the user's `~/.claude/settings.json` and points
                           them at `claude` for the agent runtime
    OpenAIRuntime          stub — wire up if the user picks OpenAI
    CodexRuntime           stub — wire up if the user picks Codex CLI

`runtime_for_config(cfg)` returns the right implementation for the runtime
chosen in agent.yaml.

A "chat turn" returns a generator of typed events (text deltas, tool calls,
tool results, final). Streaming so the UI can render as the model thinks.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Literal, Protocol

from . import cost_tracker
from .audit import append_event
from .runtime_config import (
    AnthropicConfig,
    ClaudeCodeConfig,
    CodexConfig,
    OllamaConfig,
    OpenAIConfig,
    RuntimeConfig,
    resolve_anthropic_key,
    resolve_openai_key,
)


# ---------------------------------------------------------------------------
# Event types streamed back to the UI
# ---------------------------------------------------------------------------


@dataclass
class TextDelta:
    kind: Literal["text_delta"] = "text_delta"
    text: str = ""


@dataclass
class ToolUseEvent:
    kind: Literal["tool_use"] = "tool_use"
    tool_name: str = ""
    tool_input: dict = field(default_factory=dict)
    tool_use_id: str = ""


@dataclass
class ToolResultEvent:
    kind: Literal["tool_result"] = "tool_result"
    tool_use_id: str = ""
    content: Any = ""


@dataclass
class TurnFinal:
    kind: Literal["turn_final"] = "turn_final"
    cost_usd: float = 0.0
    model: str = ""
    task_class: str = "investigator"


@dataclass
class RuntimeError_:
    kind: Literal["error"] = "error"
    message: str = ""


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


class MCPToolExecutor(Protocol):
    """The chat panel passes one of these so the runtime can run tools."""
    def list_tools(self) -> list[dict]: ...
    def execute(self, tool_name: str, tool_input: dict) -> Any: ...


class AgentRuntime(Protocol):
    name: str
    cost_aware: bool

    def setup_check(self) -> tuple[bool, str]: ...
    def chat(
        self,
        *,
        system: str,
        messages: list[dict],
        executor: MCPToolExecutor,
        task_class: str = "investigator",
        purpose: str = "",
    ) -> Iterator[Any]: ...


# ---------------------------------------------------------------------------
# Anthropic — full chat loop with prompt caching + cost tracking
# ---------------------------------------------------------------------------


class AnthropicRuntime:
    name = "anthropic_api"
    cost_aware = True

    def __init__(self, cfg: AnthropicConfig, budget_usd: float):
        self.cfg = cfg
        self.budget_usd = budget_usd
        self._client = None

    def _client_or_build(self):
        if self._client is None:
            try:
                import anthropic  # type: ignore
            except ImportError as e:
                raise RuntimeError(
                    "anthropic SDK not installed. Run `pip install anthropic`."
                ) from e
            api_key = resolve_anthropic_key(self.cfg)
            self._client = anthropic.Anthropic(api_key=api_key)
        return self._client

    def setup_check(self) -> tuple[bool, str]:
        try:
            self._client_or_build()
        except Exception as e:
            return False, str(e)
        # cheap probe: list models is not available in the public API; trust the key
        # for now and surface real failures at first call time
        return True, "Anthropic client initialised."

    def chat(self, *, system, messages, executor, task_class="investigator", purpose=""):
        client = self._client_or_build()
        model = getattr(self.cfg.models, task_class, self.cfg.models.investigator)
        cost_tracker.check_budget_or_raise(self.budget_usd)

        tools = executor.list_tools()
        # Mark the stable system prompt as cacheable.
        sys_blocks = [{"type": "text", "text": system,
                       **({"cache_control": {"type": "ephemeral"}}
                          if self.cfg.prompt_caching else {})}]

        msgs = list(messages)
        for _safety_counter in range(20):  # max 20 tool-use rounds per turn
            resp = client.messages.create(
                model=model,
                max_tokens=self.cfg.max_tokens,
                system=sys_blocks,
                tools=tools or None,
                messages=msgs,
            )

            # Track cost from usage block
            usage = getattr(resp, "usage", None)
            if usage is not None:
                cost_tracker.track_call(
                    model=model,
                    input_tokens=int(getattr(usage, "input_tokens", 0)),
                    cached_read_tokens=int(getattr(usage, "cache_read_input_tokens", 0)),
                    cached_creation_tokens=int(getattr(usage, "cache_creation_input_tokens", 0)),
                    output_tokens=int(getattr(usage, "output_tokens", 0)),
                    task_class=task_class,
                    purpose=purpose,
                )

            # Stream text + tool_use back to caller
            assistant_content: list[dict] = []
            tool_uses: list[ToolUseEvent] = []
            for block in resp.content:
                if block.type == "text":
                    assistant_content.append({"type": "text", "text": block.text})
                    yield TextDelta(text=block.text)
                elif block.type == "tool_use":
                    tu = ToolUseEvent(tool_name=block.name,
                                       tool_input=dict(block.input or {}),
                                       tool_use_id=block.id)
                    tool_uses.append(tu)
                    assistant_content.append({
                        "type": "tool_use",
                        "id": block.id, "name": block.name,
                        "input": block.input,
                    })
                    yield tu

            msgs.append({"role": "assistant", "content": assistant_content})

            if resp.stop_reason != "tool_use" or not tool_uses:
                # Done with this turn
                yield TurnFinal(
                    cost_usd=cost_tracker.total_cost_usd(),
                    model=model,
                    task_class=task_class,
                )
                return

            # Execute each tool call via MCP, then loop back
            tool_results_block: list[dict] = []
            for tu in tool_uses:
                try:
                    result = executor.execute(tu.tool_name, tu.tool_input)
                    result_str = (json.dumps(result, default=str)
                                  if not isinstance(result, str) else result)
                except Exception as e:
                    result_str = f"TOOL_ERROR: {e}"
                tool_results_block.append({
                    "type": "tool_result",
                    "tool_use_id": tu.tool_use_id,
                    "content": result_str,
                })
                yield ToolResultEvent(tool_use_id=tu.tool_use_id, content=result_str)

            msgs.append({"role": "user", "content": tool_results_block})
            cost_tracker.check_budget_or_raise(self.budget_usd)

        yield RuntimeError_(message="exceeded 20 tool-use rounds in a single turn")


# ---------------------------------------------------------------------------
# Ollama — local LLM via OpenAI-compatible endpoint
# ---------------------------------------------------------------------------


class OllamaRuntime:
    name = "ollama"
    cost_aware = False

    def __init__(self, cfg: OllamaConfig, budget_usd: float = 0.0):
        self.cfg = cfg
        self.budget_usd = 0.0    # always free

    def setup_check(self) -> tuple[bool, str]:
        try:
            import httpx  # noqa: F401
        except ImportError:
            return False, "httpx not installed (run `pip install httpx`)."
        import urllib.request, urllib.error
        try:
            urllib.request.urlopen(self.cfg.endpoint + "/api/tags", timeout=3)
        except Exception as e:
            return False, f"Ollama endpoint {self.cfg.endpoint} unreachable: {e}"
        return True, f"Ollama reachable at {self.cfg.endpoint}; model={self.cfg.model}"

    def chat(self, *, system, messages, executor, task_class="investigator", purpose=""):
        try:
            import httpx
        except ImportError as e:
            raise RuntimeError("httpx required for OllamaRuntime") from e

        tools = executor.list_tools()
        ollama_msgs = [{"role": "system", "content": system}] + list(messages)
        url = self.cfg.endpoint + "/v1/chat/completions"

        for _safety_counter in range(20):
            payload = {
                "model": self.cfg.model,
                "messages": ollama_msgs,
                "tools": [{"type": "function", "function": t} for t in tools] if tools else None,
                "max_tokens": self.cfg.max_tokens,
                "stream": False,
            }
            resp = httpx.post(url, json=payload, timeout=self.cfg.timeout_seconds).json()
            choice = resp.get("choices", [{}])[0]
            msg = choice.get("message", {})
            text = msg.get("content") or ""
            if text:
                yield TextDelta(text=text)

            # Track call with cost=0
            usage = resp.get("usage", {})
            cost_tracker.track_call(
                model=self.cfg.model,
                input_tokens=int(usage.get("prompt_tokens", 0)),
                output_tokens=int(usage.get("completion_tokens", 0)),
                task_class=task_class, purpose=purpose,
            )

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                ollama_msgs.append({"role": "assistant", "content": text})
                yield TurnFinal(cost_usd=0.0, model=self.cfg.model, task_class=task_class)
                return

            ollama_msgs.append({"role": "assistant", "content": text or None,
                                "tool_calls": tool_calls})
            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                tu_id = tc.get("id") or f"tool_{int(time.time() * 1000)}"
                yield ToolUseEvent(tool_name=name, tool_input=args, tool_use_id=tu_id)
                try:
                    result = executor.execute(name, args)
                    result_str = (json.dumps(result, default=str)
                                  if not isinstance(result, str) else result)
                except Exception as e:
                    result_str = f"TOOL_ERROR: {e}"
                yield ToolResultEvent(tool_use_id=tu_id, content=result_str)
                ollama_msgs.append({"role": "tool", "tool_call_id": tu_id,
                                     "content": result_str})

        yield RuntimeError_(message="exceeded 20 tool-use rounds in a single turn")


# ---------------------------------------------------------------------------
# Claude Code — register MCP servers into ~/.claude/settings.json
# ---------------------------------------------------------------------------


class ClaudeCodeRuntime:
    """No in-process chat loop. The user runs `claude` themselves; we just register
    the SIFTics MCP servers so Claude Code can call them.
    """
    name = "claude_code"
    cost_aware = False

    def __init__(self, cfg: ClaudeCodeConfig, budget_usd: float = 0.0):
        self.cfg = cfg
        self.budget_usd = 0.0   # subscription-based

    def setup_check(self) -> tuple[bool, str]:
        # Look for the `claude` CLI in PATH
        import shutil
        if not shutil.which("claude"):
            return False, "`claude` CLI not found on PATH. Install Claude Code first."
        cfg_p = Path(self.cfg.mcp_config_path).expanduser()
        return True, f"Claude Code CLI found; MCP config will be written to {cfg_p}."

    def register_mcp_servers(self, servers: dict[str, dict]) -> Path:
        """Write SIFTics MCP server registrations into Claude Code's settings.json."""
        cfg_p = Path(self.cfg.mcp_config_path).expanduser()
        cfg_p.parent.mkdir(parents=True, exist_ok=True)
        existing: dict = {}
        if cfg_p.exists():
            try:
                existing = json.loads(cfg_p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing = {}
        existing.setdefault("mcpServers", {})
        existing["mcpServers"].update(servers)
        cfg_p.write_text(json.dumps(existing, indent=2, sort_keys=True),
                         encoding="utf-8")
        append_event("mcp_servers_registered",
                     {"runtime": "claude_code", "servers": list(servers),
                      "config_path": str(cfg_p)},
                     actor="setup")
        return cfg_p

    def chat(self, *, system, messages, executor, task_class="investigator", purpose=""):
        yield RuntimeError_(
            message="ClaudeCodeRuntime does not host an in-process chat loop. "
                    "Run `claude` in a terminal — its MCP config is already "
                    "wired to SIFTics's servers."
        )


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class OpenAIRuntime:
    name = "openai_api"
    cost_aware = True

    def __init__(self, cfg: OpenAIConfig, budget_usd: float):
        self.cfg = cfg
        self.budget_usd = budget_usd

    def setup_check(self) -> tuple[bool, str]:
        try:
            resolve_openai_key(self.cfg)
        except Exception as e:
            return False, str(e)
        return True, "OpenAI key resolved."

    def chat(self, *, system, messages, executor, task_class="investigator", purpose=""):
        yield RuntimeError_(message="OpenAIRuntime is a stub; wire up the openai SDK next.")


class CodexRuntime:
    name = "codex"
    cost_aware = False

    def __init__(self, cfg: CodexConfig, budget_usd: float = 0.0):
        self.cfg = cfg

    def setup_check(self) -> tuple[bool, str]:
        import shutil
        if not shutil.which("codex"):
            return False, "`codex` CLI not found on PATH."
        return True, f"Codex CLI found; MCP config will go in {self.cfg.mcp_config_path}."

    def chat(self, *, system, messages, executor, task_class="investigator", purpose=""):
        yield RuntimeError_(message="CodexRuntime is a stub; register MCP and run `codex` directly.")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def runtime_for_config(cfg: RuntimeConfig) -> AgentRuntime:
    if cfg.runtime == "anthropic_api":
        return AnthropicRuntime(cfg.anthropic, cfg.cost_budget_per_case_usd)
    if cfg.runtime == "ollama":
        return OllamaRuntime(cfg.ollama)
    if cfg.runtime == "claude_code":
        return ClaudeCodeRuntime(cfg.claude_code)
    if cfg.runtime == "openai_api":
        return OpenAIRuntime(cfg.openai, cfg.cost_budget_per_case_usd)
    if cfg.runtime == "codex":
        return CodexRuntime(cfg.codex)
    raise ValueError(f"unknown runtime: {cfg.runtime}")
