"""Token accounting + budget circuit breaker.

Every LLM call writes an `llm_call` event into the hash-chained audit log.
The cost tracker reads from that log (authoritative source) and exposes:

    track_call(...)       record a call (writes audit event, returns event row)
    total_cost_usd()      sum costs from audit log for the active case
    over_budget()         bool — does the running total exceed the configured budget?
    check_budget_or_raise()  raises BudgetExceeded; called before every LLM call

Pricing tables are per million-token (input / output) USD as of 2026-01.
Cached-input tokens are billed at 10 % of input rate (Anthropic prompt caching).
Cache-creation tokens are billed at 125 % of input rate (one-time write penalty).

This module is intentionally provider-agnostic — Ollama calls report
input_tokens/output_tokens too, with cost 0 (local model).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .audit import append_event, iter_events

TaskClass = Literal["investigator", "classifier", "synthesizer", "deep_review", "other"]


# Per-million-token USD; values current as of 2026-01.
# Updated when Anthropic/OpenAI/Ollama change pricing.
PRICE_TABLE_USD_PER_1M: dict[str, dict[str, float]] = {
    # Anthropic
    "claude-opus-4-7":               {"input": 15.0,  "output": 75.0},
    "claude-sonnet-4-6":             {"input": 3.0,   "output": 15.0},
    "claude-haiku-4-5-20251001":     {"input": 0.80,  "output": 4.0},
    # OpenAI (illustrative — verify against the OpenAI pricing page before submission)
    "gpt-5":                         {"input": 5.0,   "output": 25.0},
    "gpt-5-mini":                    {"input": 0.50,  "output": 2.5},
    # Ollama (local — always 0)
    "__ollama__":                    {"input": 0.0,   "output": 0.0},
}

# Cache discount/markup multipliers — Anthropic prompt-caching behaviour.
CACHE_READ_MULTIPLIER = 0.10
CACHE_CREATION_MULTIPLIER = 1.25


class BudgetExceeded(Exception):
    pass


class UnknownModel(Exception):
    pass


@dataclass(frozen=True)
class CostBreakdown:
    model: str
    input_tokens: int
    cached_read_tokens: int
    cached_creation_tokens: int
    output_tokens: int
    cost_usd: float
    cache_hit_rate: float


def _price(model: str) -> dict[str, float]:
    if model in PRICE_TABLE_USD_PER_1M:
        return PRICE_TABLE_USD_PER_1M[model]
    # Heuristic for ollama-served models that have a tag like "qwen2.5-coder:32b"
    if ":" in model and "/" not in model:
        return PRICE_TABLE_USD_PER_1M["__ollama__"]
    raise UnknownModel(f"no pricing entry for model '{model}'")


def compute_cost(model: str, *,
                 input_tokens: int,
                 cached_read_tokens: int = 0,
                 cached_creation_tokens: int = 0,
                 output_tokens: int = 0) -> CostBreakdown:
    p = _price(model)
    fresh_input = max(0, input_tokens - cached_read_tokens - cached_creation_tokens)
    in_rate = p["input"] / 1_000_000
    out_rate = p["output"] / 1_000_000

    cost = (
        fresh_input * in_rate
        + cached_read_tokens * in_rate * CACHE_READ_MULTIPLIER
        + cached_creation_tokens * in_rate * CACHE_CREATION_MULTIPLIER
        + output_tokens * out_rate
    )
    hit_rate = (cached_read_tokens / input_tokens) if input_tokens else 0.0
    return CostBreakdown(
        model=model,
        input_tokens=input_tokens,
        cached_read_tokens=cached_read_tokens,
        cached_creation_tokens=cached_creation_tokens,
        output_tokens=output_tokens,
        cost_usd=round(cost, 6),
        cache_hit_rate=round(hit_rate, 4),
    )


def track_call(model: str, *,
               input_tokens: int,
               cached_read_tokens: int = 0,
               cached_creation_tokens: int = 0,
               output_tokens: int = 0,
               task_class: TaskClass = "other",
               purpose: str = "",
               actor: str = "investigation-section-chief") -> dict:
    """Compute cost, append `llm_call` audit event, return the event payload."""
    cb = compute_cost(model,
                      input_tokens=input_tokens,
                      cached_read_tokens=cached_read_tokens,
                      cached_creation_tokens=cached_creation_tokens,
                      output_tokens=output_tokens)
    payload = {
        "model": cb.model,
        "task_class": task_class,
        "purpose": purpose,
        "input_tokens": cb.input_tokens,
        "cached_read_tokens": cb.cached_read_tokens,
        "cached_creation_tokens": cb.cached_creation_tokens,
        "output_tokens": cb.output_tokens,
        "cost_usd": cb.cost_usd,
        "cache_hit_rate": cb.cache_hit_rate,
    }
    append_event("llm_call", payload, actor=actor)
    return payload


def total_cost_usd() -> float:
    """Sum cost_usd across all llm_call events in the case audit log."""
    total = 0.0
    for ev in iter_events():
        if ev.get("type") == "llm_call":
            total += float(ev.get("payload", {}).get("cost_usd", 0.0))
    return round(total, 4)


def call_count() -> int:
    return sum(1 for ev in iter_events() if ev.get("type") == "llm_call")


def cache_hit_summary() -> dict:
    """Aggregate cache statistics across all llm_call events."""
    total_input = 0
    total_cached = 0
    n = 0
    for ev in iter_events():
        if ev.get("type") != "llm_call":
            continue
        p = ev.get("payload", {})
        total_input += int(p.get("input_tokens", 0))
        total_cached += int(p.get("cached_read_tokens", 0))
        n += 1
    return {
        "calls": n,
        "input_tokens": total_input,
        "cached_read_tokens": total_cached,
        "cache_hit_rate": round(total_cached / total_input, 4) if total_input else 0.0,
    }


def over_budget(budget_usd: float) -> bool:
    if budget_usd <= 0:
        return False
    return total_cost_usd() >= budget_usd


def check_budget_or_raise(budget_usd: float) -> None:
    """Architectural circuit breaker — call this at the top of every chat invocation."""
    if budget_usd <= 0:
        return
    cur = total_cost_usd()
    if cur >= budget_usd:
        raise BudgetExceeded(
            f"case cost ${cur:.4f} has reached the configured budget ${budget_usd:.2f}. "
            f"Either raise cost_budget_per_case_usd or close out the case."
        )


def remaining_budget_pct(budget_usd: float) -> float:
    if budget_usd <= 0:
        return 100.0
    return max(0.0, 100.0 - (total_cost_usd() / budget_usd * 100.0))
