"""In-process MCPToolExecutor — exposes the case-state and approval functions
directly to AnthropicRuntime / OllamaRuntime without going over MCP wire.

Same underlying functions, no subprocess. Claude Code mode goes over real MCP
(mcp_case.server + mcp_ic_approval.server); in-browser chat uses this.
"""
from __future__ import annotations

import inspect
import json
from typing import Any, Callable

from siftics import case_state, ic_approval, ingest

# Lazy imports for the optional MCP servers — we don't want to require their
# data files (baseline.sqlite, rag/index/) just to import the executor.
def _lazy_baseline():
    from mcp_baseline import server as s
    return s

def _lazy_cti():
    from mcp_cti import server as s
    return s

def _lazy_rag():
    from mcp_rag import server as s
    return s

def _lazy_broker():
    from mcp_broker import server as s
    return s


def _unwrap(tool):
    """FastMCP wraps registered functions; unwrap so we can call them directly."""
    return tool.fn if hasattr(tool, "fn") else tool


def _tool_schema(fn: Callable, name: str | None = None) -> dict:
    """Build an Anthropic-tool-schema dict from a Python function signature."""
    sig = inspect.signature(fn)
    props: dict[str, dict] = {}
    required: list[str] = []
    for pname, p in sig.parameters.items():
        if pname == "actor":
            continue   # injected internally
        ann = p.annotation if p.annotation is not inspect._empty else str
        prop = _py_type_to_schema(ann)
        props[pname] = prop
        if p.default is inspect._empty:
            required.append(pname)
    return {
        "name": name or fn.__name__,
        "description": (fn.__doc__ or "").strip().split("\n")[0] or fn.__name__,
        "input_schema": {
            "type": "object",
            "properties": props,
            "required": required,
        },
    }


def _py_type_to_schema(t) -> dict:
    if t is str:
        return {"type": "string"}
    if t is int:
        return {"type": "integer"}
    if t is float:
        return {"type": "number"}
    if t is bool:
        return {"type": "boolean"}
    origin = getattr(t, "__origin__", None)
    if origin is list:
        return {"type": "array"}
    if origin is dict or t is dict:
        return {"type": "object"}
    return {"type": "string"}


class InProcessToolExecutor:
    """An MCPToolExecutor that dispatches directly to Python functions.

    The exposed surface is identical to mcp_case and mcp_ic_approval servers —
    just packaged for in-process consumption by AnthropicRuntime / OllamaRuntime.
    """

    def __init__(self) -> None:
        self._tools: dict[str, Callable] = {
            "case_get_header":           case_state.case_get_header,
            "evidence_manifest":         ingest.read_manifest,
            "evidence_quicklook":        lambda max_chars=12000: ingest.read_quicklook(max_chars=max_chars),
            "case_update_header":        lambda fields: case_state.case_update_header(fields),
            "asr_open":                  case_state.asr_open,
            "asr_all":                   case_state.asr_all,
            "asr_append":                lambda **kw: case_state.asr_append(kw),
            "asr_update":                lambda serial_no, fields: case_state.asr_update(serial_no, fields),
            "cet_append":                lambda **kw: case_state.cet_append(kw),
            "cet_update":                lambda cca_no, fields: case_state.cet_update(cca_no, fields),
            "cet_pending":               case_state.cet_pending,
            "itq_unanswered":            case_state.itq_unanswered,
            "itq_answer":                lambda question_id, answer, source="agent", resulting_task="":
                                            case_state.itq_answer(question_id, answer, source=source,
                                                                   resulting_task=(resulting_task or None)),
            "itq_progress":              case_state.itq_progress,
            "briefing_post":             lambda summary_md: case_state.briefing_post(summary_md),
            "briefing_latest":           case_state.briefing_latest,
            "ic_request_approval":       ic_approval.request_approval,
            "ic_check_approval":         ic_approval.check_approval,
            # action functions deliberately omitted from in-process surface;
            # they live on the mcp_ic_approval server only.

            # mcp_baseline
            "baseline_lookup_sha256":    lambda sha256: _unwrap(
                _lazy_baseline().lookup_by_sha256)(sha256),
            "baseline_lookup_name_path": lambda name, path="": _unwrap(
                _lazy_baseline().lookup_by_name_path)(name, path),
            "baseline_classify_path":    lambda name, observed_path: _unwrap(
                _lazy_baseline().classify_path_anomaly)(name, observed_path),
            "baseline_lookup_registry":  lambda hive, key_path, value_name="": _unwrap(
                _lazy_baseline().lookup_registry_value)(hive, key_path, value_name),
            "baseline_lookup_service":   lambda name, image_path="": _unwrap(
                _lazy_baseline().lookup_service)(name, image_path),
            "baseline_lookup_task":      lambda task_name: _unwrap(
                _lazy_baseline().lookup_scheduled_task)(task_name),

            # mcp_cti
            "cti_lookup_hash":           lambda sha256: _unwrap(
                _lazy_cti().lookup_hash)(sha256),
            "cti_lookup_url":            lambda url: _unwrap(
                _lazy_cti().lookup_url)(url),
            "cti_lookup_ioc":            lambda ioc_value, ioc_type="auto": _unwrap(
                _lazy_cti().lookup_ioc)(ioc_value, ioc_type),
            "cti_lookup_c2_ip":          lambda ip: _unwrap(
                _lazy_cti().lookup_c2_ip)(ip),
            "cti_enrich":                lambda ioc_value, ioc_type="auto": _unwrap(
                _lazy_cti().enrich)(ioc_value, ioc_type),

            # mcp_rag
            "forensic_rag_search":       lambda query, top_k=10, source_filter=None, rerank=True: _unwrap(
                _lazy_rag().forensic_rag_search)(query, top_k, source_filter, rerank),
            "rag_meta":                  lambda: _unwrap(
                _lazy_rag().rag_meta)(),

            # mcp_broker (Velociraptor)
            "velo_list_clients":         lambda: _unwrap(
                _lazy_broker().list_clients)(),
            "velo_list_hunt_templates":  lambda: _unwrap(
                _lazy_broker().list_hunt_templates)(),
            "velo_create_hunt":          lambda template, iocs, target_groups=None, description="": _unwrap(
                _lazy_broker().create_hunt)(template, iocs, target_groups, description),
            "velo_start_hunt":           lambda hunt_id: _unwrap(
                _lazy_broker().start_hunt)(hunt_id),
            "velo_get_hunt_status":      lambda hunt_id: _unwrap(
                _lazy_broker().get_hunt_status)(hunt_id),
            "velo_wait_for_hunt":        lambda hunt_id, timeout_seconds=300: _unwrap(
                _lazy_broker().wait_for_hunt)(hunt_id, timeout_seconds),
            "velo_get_hunt_results":     lambda hunt_id: _unwrap(
                _lazy_broker().get_hunt_results)(hunt_id),
        }

        self._schemas: list[dict] = [
            {"name": "case_get_header",
             "description": "Return the current Incident COP header.",
             "input_schema": {"type": "object", "properties": {}, "required": []}},
            {"name": "evidence_manifest",
             "description": "Return deterministic DFIR ingest manifest for this case.",
             "input_schema": {"type": "object", "properties": {}, "required": []}},
            {"name": "evidence_quicklook",
             "description": "Return deterministic ingest quicklook markdown.",
             "input_schema": {"type": "object",
                              "properties": {"max_chars": {"type": "integer"}},
                              "required": []}},
            {"name": "case_update_header",
             "description": "Update fields in the case header.",
             "input_schema": {"type": "object",
                              "properties": {"fields": {"type": "object"}},
                              "required": ["fields"]}},
            {"name": "asr_open",
             "description": "List Affected Systems Register rows not yet marked safe.",
             "input_schema": {"type": "object", "properties": {}, "required": []}},
            {"name": "asr_all",
             "description": "List every ASR row (latest versions).",
             "input_schema": {"type": "object", "properties": {}, "required": []}},
            {"name": "asr_append",
             "description": "Append a new system row to the ASR.",
             "input_schema": {"type": "object",
                              "properties": {
                                  "system_type": {"type": "string"},
                                  "system_identifier": {"type": "string"},
                                  "location": {"type": "string"},
                                  "date_of_detection": {"type": "string"},
                                  "date_of_compromise": {"type": "string"},
                                  "how_determined": {"type": "string"},
                                  "impact_rating": {"type": "string",
                                                    "enum": ["low", "moderate", "high", "critical"]},
                                  "impact_description": {"type": "string"},
                                  "planned_action": {"type": "string"},
                                  "system_safe": {"type": "string",
                                                  "enum": ["not_safe", "safe", "pending_verification"]},
                              },
                              "required": ["system_type", "system_identifier",
                                           "location", "date_of_detection",
                                           "date_of_compromise", "how_determined",
                                           "impact_rating", "impact_description",
                                           "planned_action"]}},
            {"name": "itq_unanswered",
             "description": ("List open Lines of Inquiry checks - legacy "
                             "ITQ persistence API, primary driver for "
                             "next-action selection."),
             "input_schema": {"type": "object", "properties": {}, "required": []}},
            {"name": "itq_answer",
             "description": "Resolve a Line of Inquiry check with evidence.",
             "input_schema": {"type": "object",
                              "properties": {
                                  "question_id": {"type": "string"},
                                  "answer": {"type": "string"},
                                  "source": {"type": "string",
                                             "enum": ["ic", "agent", "auto_tooling"]},
                                  "resulting_task": {"type": "string"}},
                              "required": ["question_id", "answer"]}},
            {"name": "itq_progress",
             "description": "Return {answered, total, pct} inquiry-check progress.",
             "input_schema": {"type": "object", "properties": {}, "required": []}},
            {"name": "briefing_post",
             "description": "Write a new briefing markdown into the case.",
             "input_schema": {"type": "object",
                              "properties": {"summary_md": {"type": "string"}},
                              "required": ["summary_md"]}},
            {"name": "briefing_latest",
             "description": "Return the most recent briefing.",
             "input_schema": {"type": "object", "properties": {}, "required": []}},
            {"name": "ic_request_approval",
             "description": "Open an Authority Gate (typed action proposal). IC must sign out-of-band.",
             "input_schema": {"type": "object",
                              "properties": {
                                  "gate": {"type": "string"},
                                  "summary": {"type": "string"},
                                  "action": {"type": "object"}},
                              "required": ["gate", "summary", "action"]}},
            {"name": "ic_check_approval",
             "description": "Poll for IC decision on a pending request.",
             "input_schema": {"type": "object",
                              "properties": {"request_id": {"type": "string"}},
                              "required": ["request_id"]}},

            # ---- mcp_baseline (Rathbun) ----
            {"name": "baseline_lookup_sha256",
             "description": "Is this SHA-256 hash in the Rathbun known-good Windows baseline?",
             "input_schema": {"type": "object",
                              "properties": {"sha256": {"type": "string"}},
                              "required": ["sha256"]}},
            {"name": "baseline_classify_path",
             "description": ("Given a filename and observed path, decide whether the path is a "
                              "stock-Windows location. Returns 'name_not_in_baseline' for unknown "
                              "binaries; 'name_exists_but_wrong_location' for masquerades."),
             "input_schema": {"type": "object",
                              "properties": {"name": {"type": "string"},
                                              "observed_path": {"type": "string"}},
                              "required": ["name", "observed_path"]}},
            {"name": "baseline_lookup_registry",
             "description": "Is this registry value in the stock Windows baseline (e.g. Run keys, Services)?",
             "input_schema": {"type": "object",
                              "properties": {"hive": {"type": "string"},
                                              "key_path": {"type": "string"},
                                              "value_name": {"type": "string"}},
                              "required": ["hive", "key_path"]}},
            {"name": "baseline_lookup_service",
             "description": "Is this Windows service a stock service?",
             "input_schema": {"type": "object",
                              "properties": {"name": {"type": "string"},
                                              "image_path": {"type": "string"}},
                              "required": ["name"]}},
            {"name": "baseline_lookup_task",
             "description": "Is this Scheduled Task part of a stock Windows install?",
             "input_schema": {"type": "object",
                              "properties": {"task_name": {"type": "string"}},
                              "required": ["task_name"]}},

            # ---- mcp_cti ----
            {"name": "cti_lookup_hash",
             "description": "Look up a SHA-256 in abuse.ch MalwareBazaar.",
             "input_schema": {"type": "object",
                              "properties": {"sha256": {"type": "string"}},
                              "required": ["sha256"]}},
            {"name": "cti_lookup_url",
             "description": "Look up a URL in abuse.ch URLhaus.",
             "input_schema": {"type": "object",
                              "properties": {"url": {"type": "string"}},
                              "required": ["url"]}},
            {"name": "cti_lookup_c2_ip",
             "description": "Check abuse.ch Feodo Tracker for a known C2 IP.",
             "input_schema": {"type": "object",
                              "properties": {"ip": {"type": "string"}},
                              "required": ["ip"]}},
            {"name": "cti_enrich",
             "description": ("Single-call IOC enrichment across MalwareBazaar, URLhaus, ThreatFox, "
                              "Feodo Tracker, and (if configured) OSM STIX."),
             "input_schema": {"type": "object",
                              "properties": {"ioc_value": {"type": "string"},
                                              "ioc_type": {"type": "string",
                                                            "enum": ["auto", "sha256", "ip",
                                                                     "domain", "url"]}},
                              "required": ["ioc_value"]}},

            # ---- mcp_rag ----
            {"name": "forensic_rag_search",
             "description": ("Semantic search over Sigma + ATT&CK + LOLBAS + Atomic Red Team + "
                              "OSM STIX. Use to explain/classify observations already supported "
                              "by case evidence; RAG is not proof by itself."),
             "input_schema": {"type": "object",
                              "properties": {
                                  "query": {"type": "string"},
                                  "top_k": {"type": "integer"},
                                  "source_filter": {"type": "array",
                                                     "items": {"type": "string"}},
                                  "rerank": {"type": "boolean"}},
                              "required": ["query"]}},

            # ---- mcp_broker (Velociraptor active hunt) ----
            {"name": "velo_list_clients",
             "description": "List Velociraptor clients (hosts) currently registered.",
             "input_schema": {"type": "object", "properties": {}, "required": []}},
            {"name": "velo_list_hunt_templates",
             "description": "List curated hunt templates the agent may invoke.",
             "input_schema": {"type": "object", "properties": {}, "required": []}},
            {"name": "velo_create_hunt",
             "description": ("Create a Velociraptor hunt from a curated template + typed IOCs. "
                              "No raw VQL — agent picks template, fills IOC slots."),
             "input_schema": {"type": "object",
                              "properties": {
                                  "template": {"type": "string"},
                                  "iocs": {"type": "object"},
                                  "target_groups": {"type": "array",
                                                     "items": {"type": "string"}},
                                  "description": {"type": "string"}},
                              "required": ["template", "iocs"]}},
            {"name": "velo_get_hunt_results",
             "description": "Retrieve results from a completed hunt.",
             "input_schema": {"type": "object",
                              "properties": {"hunt_id": {"type": "string"}},
                              "required": ["hunt_id"]}},
        ]

    # ---- MCPToolExecutor Protocol ----

    def list_tools(self) -> list[dict]:
        return list(self._schemas)

    def execute(self, tool_name: str, tool_input: dict) -> Any:
        fn = self._tools.get(tool_name)
        if fn is None:
            raise ValueError(f"unknown tool: {tool_name}")
        return fn(**tool_input)
