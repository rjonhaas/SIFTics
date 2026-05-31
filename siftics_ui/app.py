"""SIFTics web UI — Flask + HTMX.

Run:
    SIFTICS_CASE_DIR=/path/to/case flask --app siftics_ui.app run --port 8080

Localhost-only by default. Provides:
    /              redirect → /dashboard
    /dashboard     Incident COP header, latest briefing, ASR/CET/ITQ summaries
    /gates         Pending Authority Gates + sign/deny actions
    /gates/sign    POST — HMAC-sign an approval (passphrase form)
    /gates/deny    POST — HMAC-sign a denial
    /audit         Live audit-chain tail + verify button
    /audit/verify  POST — recompute audit chain
    /events        SSE — pushes audit events to the dashboard as they land

Partials served via HX-Request detection so the same routes work for
full-page loads and HTMX fragment swaps.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
from pathlib import Path

from flask import Flask, Response, abort, jsonify, redirect, render_template, request, url_for

from siftics import (
    agent_runtime,
    audit,
    case_state,
    cost_tracker,
    ic_approval,
    runtime_config,
)

from .labels import load_labels


def create_app() -> Flask:
    app = Flask(__name__,
                template_folder=str(Path(__file__).parent / "templates"),
                static_folder=str(Path(__file__).parent / "static"))
    app.config["LABELS"] = load_labels()
    app.config["EVENT_QUEUES"] = []  # list[queue.Queue] for SSE clients
    _start_audit_tailer(app)

    @app.context_processor
    def _inject_labels() -> dict:
        return {"labels": app.config["LABELS"]}

    # -----------------------------------------------------------------
    # Pages
    # -----------------------------------------------------------------

    @app.route("/")
    def index():
        # Land on case-init if no case exists yet; otherwise go to dashboard.
        try:
            case_dir = audit.case_dir()
            if not (case_dir / "case.json").exists():
                return redirect(url_for("new_case_view"))
        except Exception:
            return redirect(url_for("new_case_view"))
        return redirect(url_for("dashboard"))

    @app.route("/dashboard")
    def dashboard():
        ctx = _dashboard_context()
        return render_template("dashboard.html", **ctx)

    @app.route("/dashboard/asr-summary")
    def dashboard_asr_summary():
        return render_template("_asr_summary.html", asr=_asr_summary())

    @app.route("/dashboard/cet-summary")
    def dashboard_cet_summary():
        return render_template("_cet_summary.html", cet=_cet_summary())

    @app.route("/dashboard/itq-progress")
    def dashboard_itq_progress():
        return render_template("_itq_progress.html", itq=case_state.itq_progress())

    @app.route("/gates")
    def gates():
        pending = _list_pending_gates()
        recent = _list_signed_gates(limit=10)
        return render_template("gates.html", pending=pending, recent=recent)

    @app.route("/gates/pending-count")
    def gates_pending_count():
        return render_template("_pending_gates.html", pending=_list_pending_gates())

    @app.route("/gates/sign", methods=["POST"])
    def gates_sign():
        return _sign_request(decision="approved")

    @app.route("/gates/deny", methods=["POST"])
    def gates_deny():
        return _sign_request(decision="denied")

    @app.route("/audit")
    def audit_view():
        events = list(audit.iter_events(limit=200))
        events.reverse()  # newest first
        return render_template("audit.html", events=events)

    @app.route("/audit/verify", methods=["POST"])
    def audit_verify():
        ok, errors = audit.verify_chain()
        return jsonify({"ok": ok, "errors": errors})

    # -----------------------------------------------------------------
    # New case landing page
    # -----------------------------------------------------------------

    @app.route("/new-case")
    def new_case_view():
        return render_template("new_case.html")

    @app.route("/api/list-cases")
    def api_list_cases():
        base = Path(request.args.get("base", "~/cases")).expanduser()
        try:
            dirs = sorted(
                str(p) for p in base.iterdir() if p.is_dir()
            ) if base.is_dir() else []
        except PermissionError:
            dirs = []
        return jsonify({"base": str(base), "dirs": dirs})

    # -----------------------------------------------------------------
    # Setup wizard
    # -----------------------------------------------------------------

    @app.route("/setup")
    def setup_view():
        cfg = runtime_config.load_config(case_dir=audit.case_dir())
        options = _setup_options(cfg)
        return render_template("setup.html",
                                cfg=cfg,
                                options=options,
                                current_runtime=cfg.runtime,
                                config_path=str(runtime_config.DEFAULT_USER_CONFIG)
                                            if runtime_config.DEFAULT_USER_CONFIG.exists() else None)

    @app.route("/setup/init-case", methods=["POST"])
    def setup_init_case():
        case_dir_raw = request.form.get("case_dir", "").strip()
        case_id = request.form.get("case_id", "").strip()
        name = request.form.get("name", "").strip()
        ic_name = request.form.get("ic_name", "").strip()
        passphrase = request.form.get("passphrase", "").strip()

        errors = []
        if not case_dir_raw:
            errors.append("Case directory is required.")
        if not case_id:
            errors.append("Case ID is required.")
        if not name:
            errors.append("Incident name is required.")
        if not ic_name:
            errors.append("IC name is required.")
        if not passphrase:
            errors.append("IC passphrase is required.")
        if errors:
            return Response("<br>".join(errors), status=400, mimetype="text/html")

        import os as _os
        case_path = Path(case_dir_raw).expanduser().resolve()
        try:
            case_path.mkdir(parents=True, exist_ok=True)
            _os.environ["SIFTICS_CASE_DIR"] = str(case_path)
            itq_tmpl = Path(__file__).parent.parent / "templates" / "itq_questions.yaml"
            case_state.init_case(
                case_id=case_id,
                name=name,
                ic_name=ic_name,
                ic_contact="",
                itq_template=itq_tmpl if itq_tmpl.exists() else None,
            )
            ic_approval.init_ic_key(passphrase, ic_name=ic_name)
        except Exception as exc:
            return Response(f"Case init failed: {exc}", status=500, mimetype="text/html")

        audit.append_event("case_init_via_ui",
                           {"case_dir": str(case_path), "case_id": case_id, "ic_name": ic_name},
                           actor="ic")
        if not app.config.get("AUDIT_TAILER_STARTED"):
            _start_audit_tailer(app)
        resp = Response("", status=200)
        resp.headers["HX-Redirect"] = url_for("dashboard")
        return resp

    @app.route("/setup/save", methods=["POST"])
    def setup_save():
        cfg = runtime_config.load_config(case_dir=audit.case_dir())
        cfg.runtime = request.form.get("runtime", cfg.runtime)
        try:
            cfg.cost_budget_per_case_usd = float(request.form.get("budget") or cfg.cost_budget_per_case_usd)
        except ValueError:
            pass
        path = runtime_config.save_config(cfg)
        key = (request.form.get("anthropic_key") or "").strip()
        key_location: str | None = None
        if key:
            key_location = runtime_config.save_anthropic_key(cfg.anthropic, key)
        # Don't audit the key value; do audit the location.
        audit.append_event("runtime_config_saved",
                            {"runtime": cfg.runtime,
                             "budget_usd": cfg.cost_budget_per_case_usd,
                             "config_path": str(path),
                             "api_key_location": key_location},
                            actor="ic")
        return redirect(url_for("dashboard"))

    # -----------------------------------------------------------------
    # Dashboard cost partial
    # -----------------------------------------------------------------

    @app.route("/dashboard/runtime-status")
    def dashboard_runtime_status():
        return render_template("_runtime_status.html",
                                runtime=_runtime_status())

    # -----------------------------------------------------------------
    # Chat panel
    # -----------------------------------------------------------------

    @app.route("/chat")
    def chat_view():
        try:
            cfg = runtime_config.load_config(case_dir=audit.case_dir())
        except Exception:
            cfg = runtime_config.RuntimeConfig()
        return render_template("chat.html", cfg=cfg)

    @app.route("/chat/stream", methods=["POST"])
    def chat_stream():
        user_msg = request.form.get("message", "").strip()
        if not user_msg:
            return Response("empty message", status=400)
        cfg = runtime_config.load_config(case_dir=audit.case_dir())
        runtime = agent_runtime.runtime_for_config(cfg)
        from siftics_ui.executor import InProcessToolExecutor
        executor = InProcessToolExecutor()
        system_prompt = _build_system_prompt()
        messages = [{"role": "user", "content": user_msg}]

        def stream():
            try:
                for ev in runtime.chat(system=system_prompt, messages=messages,
                                        executor=executor,
                                        task_class="investigator",
                                        purpose="chat panel"):
                    payload = _event_to_dict(ev)
                    yield f"event: {payload['kind']}\n" \
                          f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"
                yield "event: end\ndata: {}\n\n"
            except cost_tracker.BudgetExceeded as e:
                yield f"event: budget_exceeded\ndata: {json.dumps({'message': str(e)})}\n\n"
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'message': str(e)})}\n\n"

        return Response(stream(), mimetype="text/event-stream")

    # -----------------------------------------------------------------
    # SSE
    # -----------------------------------------------------------------

    @app.route("/events")
    def sse_events():
        q: queue.Queue = queue.Queue()
        app.config["EVENT_QUEUES"].append(q)

        def stream():
            try:
                # Initial ping so the browser knows the connection is live
                yield "event: ping\ndata: hello\n\n"
                while True:
                    try:
                        item = q.get(timeout=30)
                    except queue.Empty:
                        yield "event: ping\ndata: keepalive\n\n"
                        continue
                    yield f"event: {item['type']}\n" \
                          f"data: {json.dumps(item, separators=(',', ':'))}\n\n"
            finally:
                if q in app.config["EVENT_QUEUES"]:
                    app.config["EVENT_QUEUES"].remove(q)

        return Response(stream(), mimetype="text/event-stream")

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dashboard_context() -> dict:
    try:
        header = case_state.case_get_header()
    except FileNotFoundError:
        header = None
    return {
        "case": header,
        "latest_briefing": case_state.briefing_latest(),
        "asr": _asr_summary(),
        "cet": _cet_summary(),
        "itq": case_state.itq_progress(),
        "pending_gate_count": len(_list_pending_gates()),
        "runtime": _runtime_status(),
    }


def _runtime_status() -> dict:
    """Snapshot of the active runtime + cost state for the dashboard card."""
    try:
        cfg = runtime_config.load_config(case_dir=audit.case_dir())
    except Exception:
        cfg = runtime_config.RuntimeConfig()
    cur_cost = 0.0
    cache_stats = {"calls": 0, "cache_hit_rate": 0.0}
    try:
        cur_cost = cost_tracker.total_cost_usd()
        cache_stats = cost_tracker.cache_hit_summary()
    except Exception:
        pass
    budget = cfg.cost_budget_per_case_usd
    pct = (cur_cost / budget * 100.0) if budget > 0 else 0.0
    return {
        "runtime": cfg.runtime,
        "budget_usd": budget,
        "spent_usd": round(cur_cost, 4),
        "pct": round(pct, 1),
        "warn": pct >= cfg.warn_at_pct,
        "calls": cache_stats["calls"],
        "cache_hit_rate": cache_stats["cache_hit_rate"],
    }


def _setup_options(cfg) -> list[dict]:
    """Probe each runtime backend; return a list of card dicts for the wizard."""
    out = []
    for value, label, desc, recommended in [
        ("claude_code",   "Claude Code (recommended)",
            "Uses your existing claude CLI subscription. SIFTics writes MCP server "
            "registrations into ~/.claude/settings.json so claude calls them.",
            True),
        ("anthropic_api", "Anthropic API key",
            "In-process chat loop in SIFTics's UI. Routes per task class "
            "(Sonnet 4.6 default, Haiku 4.5 for classification, Opus 4.7 for "
            "deep review). Prompt caching enabled. Cost tracking + per-case "
            "budget circuit breaker active.",
            False),
        ("ollama",        "Ollama (fully local)",
            "Talks to a local Ollama server (default http://127.0.0.1:11434). "
            "Recommend qwen2.5-coder:32b or llama3.1:70b for tool-use quality. "
            "Cost = $0; expect reduced autonomy compared to frontier models.",
            False),
        ("openai_api",    "OpenAI API key",
            "(stub) In-process chat loop using the OpenAI SDK. Pin via models block.",
            False),
        ("codex",         "Codex CLI",
            "(stub) Uses Codex CLI as the agent runtime; SIFTics registers MCP servers.",
            False),
    ]:
        rt = agent_runtime.runtime_for_config(_force_runtime(cfg, value))
        ok, status = rt.setup_check()
        out.append({
            "value": value, "label": label, "description": desc,
            "recommended": recommended, "detected": ok, "status": status,
        })
    return out


def _force_runtime(cfg, runtime_value):
    """Helper for setup_check() — clone cfg with a different runtime to probe each."""
    import copy
    c = copy.deepcopy(cfg)
    c.runtime = runtime_value
    return c


def _build_system_prompt() -> str:
    """Minimal v1 system prompt — production version reads from skills/*.md."""
    return (
        "You are the Investigation Section Chief for an IR case under NIMS ICS "
        "doctrine. The human analyst is the Incident Commander.\n\n"
        "Your tactical autonomy: drive the investigation through the case's "
        "MCP tool surface (asr_*, cet_*, itq_*, briefing_post, ic_request_approval).\n\n"
        "Authority Gates: any fleet-wide action (hunt deployment, host isolation, "
        "cold-path escalation) requires `ic_request_approval` followed by IC "
        "sign-off in another surface (the /gates UI or `sift-approve` CLI). "
        "You cannot execute these actions yourself; the action MCP functions "
        "reject calls without a signed approval object.\n\n"
        "Start each turn by checking ITQ progress and the open ASR/CET state. "
        "Drive unanswered ITQ questions toward closure using available tools. "
        "Post briefings when material findings change the IC's picture."
    )


def _event_to_dict(ev) -> dict:
    """Convert AgentRuntime event dataclasses to JSON-serialisable dicts."""
    out = {"kind": getattr(ev, "kind", "unknown")}
    for f in ("text", "tool_name", "tool_input", "tool_use_id",
              "content", "cost_usd", "model", "task_class", "message"):
        if hasattr(ev, f):
            v = getattr(ev, f)
            if v not in (None, "", {}):
                out[f] = v
    return out


def _asr_summary() -> dict:
    rows = case_state.asr_all()
    return {
        "total": len(rows),
        "open": sum(1 for r in rows if r.get("system_safe") != "safe"),
        "safe": sum(1 for r in rows if r.get("system_safe") == "safe"),
        "critical": sum(1 for r in rows if r.get("impact_rating") == "critical"),
        "recent": sorted(rows, key=lambda r: r.get("written_at", ""), reverse=True)[:5],
    }


def _cet_summary() -> dict:
    rows = case_state.cet_all()
    pending = case_state.cet_pending()
    return {
        "total": len(rows),
        "pending": len(pending),
        "remediated": len(rows) - len(pending),
        "high_priority": sum(1 for r in pending if r.get("priority_order", 99) <= 3),
        "recent": sorted(rows, key=lambda r: r.get("written_at", ""), reverse=True)[:5],
    }


def _list_pending_gates() -> list[dict]:
    pdir = audit.case_dir() / "approvals" / "pending"
    if not pdir.exists():
        return []
    out = []
    sdir = audit.case_dir() / "approvals" / "signed"
    for p in sorted(pdir.glob("*.json")):
        # Skip if already signed
        if (sdir / p.name).exists():
            continue
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return out


def _list_signed_gates(limit: int = 10) -> list[dict]:
    sdir = audit.case_dir() / "approvals" / "signed"
    if not sdir.exists():
        return []
    files = sorted(sdir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
    out = []
    for p in files:
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return out


def _sign_request(decision: str) -> Response:
    request_id = request.form.get("request_id")
    passphrase = request.form.get("passphrase", "")
    if not request_id or not passphrase:
        return Response("missing request_id or passphrase", status=400)
    try:
        approval = ic_approval.sign_approval(request_id, passphrase, decision)
    except ic_approval.ApprovalInvalidError as e:
        return Response(f"signature failed: {e}", status=403)
    except FileNotFoundError:
        return Response("no such pending request", status=404)
    # Best-effort: scrub passphrase reference from the form dict
    request.form = None  # type: ignore[assignment]
    if request.headers.get("HX-Request"):
        return Response(
            f"<div class='text-emerald-400 p-2'>"
            f"Signed {decision} for <code>{request_id}</code>"
            f"</div>",
            mimetype="text/html",
        )
    return redirect(url_for("gates"))


# ---------------------------------------------------------------------------
# Audit-log tailer → SSE fan-out
# ---------------------------------------------------------------------------


def _start_audit_tailer(app: Flask) -> None:
    """Tail forensic_audit.jsonl and push every new line to all SSE queues.

    Re-reads SIFTICS_CASE_DIR each iteration so switching case dirs mid-session
    (e.g. after /setup/init-case) is picked up without restarting the server.
    """
    if app.config.get("AUDIT_TAILER_STARTED"):
        return
    app.config["AUDIT_TAILER_STARTED"] = True

    def runner():
        position = 0
        last_path: Path | None = None
        while True:
            try:
                path = audit.audit_path()
            except RuntimeError:
                time.sleep(0.5)
                continue
            if path != last_path:
                position = path.stat().st_size if path.exists() else 0
                last_path = path
            if not path.exists():
                time.sleep(0.5)
                continue
            with path.open("r", encoding="utf-8") as fh:
                fh.seek(position)
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    for q in list(app.config.get("EVENT_QUEUES", [])):
                        q.put(row)
                position = fh.tell()
            time.sleep(0.25)

    t = threading.Thread(target=runner, daemon=True, name="audit-tailer")
    t.start()


# Use `flask --app "siftics_ui.app:create_app" run` (factory form) or
# `siftics-ui run` (preferred) so SIFTICS_CASE_DIR is checked first.
