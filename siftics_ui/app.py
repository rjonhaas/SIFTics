"""SIFTics web UI — Flask + vanilla JS.

Run via: siftics-ui run   (preferred)
     or: SIFTICS_CASE_DIR=/path/to/case flask --app siftics_ui.app:create_app run --port 8080
"""
from __future__ import annotations

import copy
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

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
    # TODO: remove before hackathon submission — dev aid only
    app.config["BUILD_CODE"] = str(int.from_bytes(os.urandom(2), "big") % 10000).zfill(4)
    _start_audit_tailer(app)

    @app.context_processor
    def _inject_labels() -> dict:
        return {"labels": app.config["LABELS"], "build_code": app.config["BUILD_CODE"]}

    @app.after_request
    def _no_cache(response):
        if "text/html" in response.content_type:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response

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

    @app.route("/report")
    def report_view():
        try:
            header = case_state.case_get_header()
        except Exception:
            header = None
        try:
            briefings = case_state.briefing_history(limit=50)
            briefings.reverse()  # chronological
        except Exception:
            briefings = []
        try:
            findings = case_state.asr_all()
        except Exception:
            findings = []
        try:
            itq = case_state.itq_progress()
            itq_answered = [q for q in case_state.itq_all() if q.get("answer")]
        except Exception:
            itq = {}
            itq_answered = []
        return render_template("report.html",
                               header=header,
                               briefings=briefings,
                               findings=findings,
                               itq=itq,
                               itq_answered=itq_answered)

    @app.route("/report/download")
    def report_download():
        try:
            header = case_state.case_get_header()
        except Exception:
            header = {}
        try:
            briefings = case_state.briefing_history(limit=50)
            briefings.reverse()
        except Exception:
            briefings = []
        try:
            findings = case_state.asr_all()
        except Exception:
            findings = []
        try:
            itq_answered = [q for q in case_state.itq_all() if q.get("answer")]
        except Exception:
            itq_answered = []

        lines = []
        lines.append(f"# Case Report — {header.get('name', 'Unknown')}\n")
        lines.append(f"**Case ID:** {header.get('case_id', '')}  ")
        lines.append(f"**Incident Commander:** {header.get('incident_commander', {}).get('name', '')}  ")
        lines.append(f"**Opened:** {header.get('opened_at', '')[:10]}  ")
        lines.append(f"**Impact:** {header.get('impact_level', '').upper()}  \n")

        # Evidence findings chain
        try:
            from siftics import findings as findings_lib
            evidence_findings = findings_lib.finding_list()
        except Exception:
            evidence_findings = []
        if evidence_findings:
            lines.append("---\n## Evidence Findings\n")
            for ef in evidence_findings:
                lines.append(f"### {ef.get('finding_id')} — {ef.get('claim', '')}")
                lines.append(f"**Artifact:** `{ef.get('artifact_path', '')}` in `{ef.get('artifact_source', '')}`  ")
                lines.append(f"**Tool:** {ef.get('tool', '')}  ")
                lines.append(f"**Command:** `{ef.get('command', '')}`  ")
                lines.append(f"**Output:**\n```\n{ef.get('output_excerpt', '')}\n```\n")

        if findings:
            lines.append("---\n## Affected Systems\n")
            for f in findings:
                lines.append(f"### {f.get('serial_no')} — {f.get('system_identifier')}")
                lines.append(f"**Impact:** {f.get('impact_rating')}  ")
                lines.append(f"**Status:** {f.get('system_safe')}  \n")
                lines.append(f.get('impact_description', '') + "\n")

        if itq_answered:
            lines.append("---\n## Triage Questions\n")
            for q in itq_answered:
                lines.append(f"**{q.get('question_id')}** — {q.get('question', '')}")
                lines.append(f"> {q.get('answer', '')}\n")

        for b in briefings:
            lines.append("\n---\n")
            lines.append(b.get("summary_md", ""))

        md = "\n".join(lines)
        filename = f"report_{header.get('case_id', 'case')}.md"
        return Response(md, mimetype="text/markdown",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})

    @app.route("/findings")
    def findings_view():
        from siftics import findings as findings_lib
        try:
            rows = findings_lib.finding_list()
        except Exception:
            rows = []
        return render_template("findings.html", findings=rows)

    @app.route("/intel")
    def intel_view():
        from siftics import intel as intel_lib
        try:
            rows = intel_lib.ioc_list()
        except Exception:
            rows = []
        return render_template("intel.html", iocs=rows)

    @app.route("/intel/artifact/<ioc_id>/<fmt>")
    def intel_artifact(ioc_id: str, fmt: str):
        from siftics import intel as intel_lib
        row = intel_lib.ioc_get(ioc_id)
        if not row:
            return "IOC not found", 404
        content = row.get("artifacts", {}).get(fmt, "")
        if not content:
            return f"Format {fmt} not available for {ioc_id}", 404
        mt = "application/json" if fmt == "stix" else "text/plain"
        fname = f"{ioc_id}.{fmt}{'rule' if fmt == 'yara' else '.yaml' if fmt == 'sigma' else '.json'}"
        return Response(content, mimetype=mt,
                        headers={"Content-Disposition": f"attachment; filename={fname}"})

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
    # Cases list + switch
    # -----------------------------------------------------------------

    def _scan_cases(base: Path) -> list[dict]:
        cases = []
        if not base.is_dir():
            return cases
        for p in sorted(base.iterdir()):
            if not p.is_dir():
                continue
            cj = p / "case.json"
            if not cj.exists():
                continue
            try:
                data = json.loads(cj.read_text())
            except Exception:
                continue
            evidence_dir = p / "evidence"
            evidence_files = sorted(f.name for f in evidence_dir.iterdir() if not f.name.startswith('.')) if evidence_dir.exists() else []
            cases.append({
                "path": str(p),
                "case_id": data.get("case_id", p.name),
                "name": data.get("name", ""),
                "ic_name": data.get("incident_commander", {}).get("name", ""),
                "impact_level": data.get("impact_level", "unknown"),
                "opened_at": data.get("opened_at", ""),
                "active": str(p) == str(audit.case_dir()) if _case_loaded() else False,
                "evidence_files": evidence_files,
                "evidence_dir": str(evidence_dir),
            })
        return cases

    def _case_loaded() -> bool:
        try:
            d = audit.case_dir()
            return (d / "case.json").exists()
        except Exception:
            return False

    @app.route("/cases")
    def cases_list():
        base = Path(request.args.get("base", "~/Desktop/cases")).expanduser()
        cases = _scan_cases(base)
        return render_template("cases.html", cases=cases, base=str(base))

    @app.route("/cases/switch", methods=["POST"])
    def cases_switch():
        case_path = request.form.get("case_path", "").strip()
        if not case_path or not (Path(case_path) / "case.json").exists():
            return Response("Invalid case path.", status=400, mimetype="text/html")
        # Block switching while an agent is running — prevents SIFTICS_CASE_DIR
        # changing mid-stream and mixing writes from two different cases.
        try:
            current = audit.case_dir()
            lock = _case_lock(str(current))
            if not lock.acquire(blocking=False):
                return Response(
                    "Cannot switch cases while an agent is running. "
                    "Wait for the agent to finish or stop it first.",
                    status=409, mimetype="text/plain")
            lock.release()
        except RuntimeError:
            pass  # no current case loaded — switching is safe
        os.environ["SIFTICS_CASE_DIR"] = case_path
        resp = Response("", status=200)
        resp.headers["X-Redirect"] = url_for("dashboard")
        return resp

    # -----------------------------------------------------------------
    # New case landing page
    # -----------------------------------------------------------------

    @app.route("/new-case")
    def new_case_view():
        return render_template("new_case.html")

    @app.route("/api/list-cases")
    def api_list_cases():
        base = Path(request.args.get("base", "~/Desktop/cases")).expanduser()
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
        case_id      = request.form.get("case_id", "").strip()
        name         = request.form.get("name", "").strip()
        ic_name      = request.form.get("ic_name", "").strip()
        passphrase   = request.form.get("passphrase", "").strip()

        def _fail(messages):
            html = "".join(
                f'<p class="text-rose-400 font-semibold">&#x26A0; {m}</p>'
                for m in messages
            )
            return Response(html, status=200, mimetype="text/html")

        errors = []
        if not case_dir_raw: errors.append("Case directory is required.")
        if not case_id:      errors.append("Case ID is required.")
        if not name:         errors.append("Incident name is required.")
        if not ic_name:      errors.append("Incident Commander is required.")
        if not passphrase:   errors.append("IC passphrase is required.")
        if errors:
            return _fail(errors)

        case_path = Path(case_dir_raw).expanduser().resolve()
        try:
            case_path.mkdir(parents=True, exist_ok=True)
            (case_path / "evidence").mkdir(exist_ok=True)
            os.environ["SIFTICS_CASE_DIR"] = str(case_path)
            itq_tmpl = Path(__file__).parent.parent / "templates" / "itq_questions.yaml"
            case_state.init_case(
                case_id=case_id, name=name, ic_name=ic_name, ic_contact="",
                itq_template=itq_tmpl if itq_tmpl.exists() else None,
            )
            ic_approval.init_ic_key(passphrase, ic_name=ic_name)
        except Exception as exc:
            return _fail([f"Case init failed: {exc}"])

        audit.append_event("case_init_via_ui",
                           {"case_dir": str(case_path), "case_id": case_id, "ic_name": ic_name},
                           actor="ic")
        if not app.config.get("AUDIT_TAILER_STARTED"):
            _start_audit_tailer(app)
        resp = Response("", status=200)
        resp.headers["X-Redirect"] = url_for("dashboard")
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
    # Claude Code agent — subprocess integration
    # -----------------------------------------------------------------

    @app.route("/api/agent/start", methods=["POST"])
    def api_agent_start():
        try:
            case_path = audit.case_dir()
        except Exception:
            return Response("No case loaded.", status=400)
        evidence_dir = case_path / "evidence"
        evidence_files = sorted(evidence_dir.iterdir()) if evidence_dir.exists() else []
        evidence_list = "\n".join(f"  - {f.name}" for f in evidence_files) if evidence_files else "  (no files yet — drop evidence into the evidence/ folder)"
        prompt = (
            f"You are the Investigation Section Chief for this case.\n\n"
            f"Evidence is in: {evidence_dir}\n"
            f"Evidence files:\n{evidence_list}\n\n"
            f"Case directory: {case_path}\n\n"
            f"Introduce yourself briefly, confirm what evidence you can see, "
            f"read the open triage questions, state your initial plan, then begin working. "
            f"Use /investigation-section-chief to guide your workflow — it lists all available "
            f"domain skills (/windows-artifacts, /linux-server-artifacts, /macos-artifacts, "
            f"/iot-ot-artifacts, /malware-triage, /timeline-reconstruction, "
            f"/anti-forensics-detection, /reporting-conventions, /daedalus). "
            f"Load the relevant domain skill before working in that area. "
            f"Work continuously through the loop — do not stop to ask if you should continue. "
            f"Post briefings as you go and keep going. The IC will interrupt if they need to redirect you."
        )
        cmd, env = _make_agent_cmd(case_path, prompt)
        def generate():
            yield "data: " + json.dumps({"type": "ui", "subtype": "agent_starting"}) + "\n\n"
            yield from _stream_agent(cmd, env, case_path)
            yield "data: " + json.dumps({"type": "ui", "subtype": "agent_done"}) + "\n\n"
        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/api/agent/message", methods=["POST"])
    def api_agent_message():
        try:
            case_path = audit.case_dir()
        except Exception:
            return Response("No case loaded.", status=400)
        message = request.form.get("message", "").strip()
        if not message:
            return Response("Empty message.", status=400)
        sess = _read_session(case_path)
        session_id = sess.get("session_id")
        # Validate that the stored session belongs to this case, not a
        # different one that was accidentally left in this directory.
        if session_id and sess.get("case_id"):
            try:
                header = case_state.case_get_header()
                if sess["case_id"] != header.get("case_id", ""):
                    # Session is from a different case — start fresh.
                    session_id = None
            except Exception:
                pass
        cmd, env = _make_agent_cmd(case_path, message, session_id=session_id)
        def generate():
            yield from _stream_agent(cmd, env, case_path)
            yield "data: " + json.dumps({"type": "ui", "subtype": "agent_done"}) + "\n\n"
        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/api/agent/status")
    def api_agent_status():
        try:
            case_path = audit.case_dir()
        except Exception:
            return jsonify({"has_session": False, "running": False})
        sess = _read_session(case_path)
        lock = _case_lock(str(case_path))
        running = not lock.acquire(blocking=False)
        if not running:
            lock.release()
        return jsonify({
            "has_session": bool(sess.get("session_id")),
            "session_id": sess.get("session_id"),
            "running": running,
        })

    # -----------------------------------------------------------------
    # Investigation control — status, activity feed, phase runner
    # -----------------------------------------------------------------

    @app.route("/api/investigation/status")
    def api_investigation_status():
        try:
            events = list(audit.iter_events(limit=500))
        except Exception:
            events = []
        types = {e["type"] for e in events}
        llm_calls = sum(1 for e in events if e["type"] == "llm_call")
        itq_answered = sum(1 for e in events if e["type"] == "itq_answered")
        asr_count = sum(1 for e in events if e["type"] in ("asr_appended", "asr_updated"))
        if llm_calls == 0:
            state = "fresh"
        elif any(e["type"] == "case_closed" for e in events):
            state = "complete"
        else:
            state = "active"
        phase_runs = {}
        for e in events:
            pid = e.get("payload", {}).get("phase_id")
            if pid:
                phase_runs[pid] = e["ts"]
        return jsonify({
            "state": state,
            "llm_calls": llm_calls,
            "itq_answered": itq_answered,
            "asr_count": asr_count,
            "phase_runs": phase_runs,
        })

    @app.route("/api/activity/feed")
    def api_activity_feed():
        try:
            events = list(audit.iter_events(limit=40))
        except Exception:
            events = []
        events.reverse()
        readable = []
        labels = {
            "llm_call":             "Agent LLM call",
            "itq_answered":         "ITQ question answered",
            "asr_appended":         "Finding recorded",
            "asr_updated":          "Finding updated",
            "cet_appended":         "CET entry added",
            "ic_request_approval":  "Authority Gate requested",
            "ic_approval_signed":   "Authority Gate signed",
            "rag_lookup":           "RAG knowledge lookup",
            "baseline_lookup":      "Baseline hash check",
            "cti_lookup":           "CTI IOC lookup",
            "briefing_posted":      "Briefing posted",
            "finding_recorded":     "Evidence finding recorded",
            "ioc_generated":        "IOC artifact generated",
            "intel_published":      "Intel published",
            "case_initialised":     "Case initialised",
            "itq_seeded":           "ITQ seeded",
            "phase_started":        "Phase started",
            "phase_complete":       "Phase complete",
        }
        for e in events:
            label = labels.get(e["type"], e["type"])
            payload = e.get("payload", {})
            detail = ""
            if e["type"] == "itq_answered":
                detail = payload.get("question_id", "")
            elif e["type"] in ("asr_appended", "asr_updated"):
                detail = payload.get("title", payload.get("host", ""))
            elif e["type"] == "ic_request_approval":
                detail = payload.get("gate", "")
            elif e["type"] == "llm_call":
                cost = payload.get("cost_usd")
                detail = f"${cost:.4f}" if cost else ""
            elif e["type"] in ("phase_started", "phase_complete"):
                detail = payload.get("phase_id", "")
            elif e["type"] == "finding_recorded":
                detail = payload.get("finding_id", "")
            elif e["type"] == "ioc_generated":
                detail = payload.get("ioc_id", "") + " " + payload.get("ioc_type", "")
            elif e["type"] == "intel_published":
                detail = f"{payload.get('count', '')} IOCs"
            readable.append({
                "ts": e["ts"],
                "type": e["type"],
                "label": label,
                "detail": detail,
                "actor": e.get("actor", ""),
            })
        return jsonify(readable)

    @app.route("/api/phase/run/<phase_id>", methods=["POST"])
    def api_phase_run(phase_id):
        phase = next((p for p in PHASES if p["id"] == phase_id), None)
        if not phase:
            return jsonify({"ok": False, "output": "Unknown phase."}), 400
        if not phase.get("runnable"):
            return jsonify({"ok": False, "output": phase.get("reason", "Not runnable from the UI.")}), 400
        case_path = str(audit.case_dir())
        env = {**os.environ, "SIFTICS_CASE_DIR": case_path}
        try:
            audit.append_event("phase_started", {"phase_id": phase_id}, actor="ui")
            proc = subprocess.Popen(
                [sys.executable, "-m", f"phases.{phase_id}"] + phase.get("args", []),
                cwd=str(Path(__file__).parent.parent),
                env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            out, _ = proc.communicate(timeout=120)
            audit.append_event("phase_complete",
                               {"phase_id": phase_id, "returncode": proc.returncode,
                                "output_lines": len(out.splitlines())},
                               actor="ui")
            return jsonify({"ok": proc.returncode == 0, "output": out[-3000:] or "(no output)"})
        except Exception as exc:
            return jsonify({"ok": False, "output": str(exc)}), 500

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
# Phase definitions
# ---------------------------------------------------------------------------

# runnable=True  → one-click, reads from SIFTICS_CASE_DIR
# runnable=False → needs specific inputs; UI explains instead of showing Run
PHASES = [
    {"id": "fast_persistence_scan",   "name": "Persistence Scan",
     "description": "Check run keys, services, and scheduled tasks against the known-good baseline.",
     "runnable": True,  "args": []},
    {"id": "fast_evtx_attack_filter", "name": "Windows Event Log Filter",
     "description": "Scan Windows event logs for attack-relevant event IDs.",
     "runnable": False, "reason": "Requires a folder of .evtx files — run from the agent."},
    {"id": "classify_binary",         "name": "Binary Classifier",
     "description": "Hash check + MalwareBazaar + ThreatFox lookup for a suspicious file.",
     "runnable": False, "reason": "Requires a file path or hash — run from the agent."},
    {"id": "anomaly_check",           "name": "Anomaly Check",
     "description": "Look for contradictions across all findings collected so far.",
     "runnable": True,  "args": []},
]


# ---------------------------------------------------------------------------
# Agent subprocess helpers
# ---------------------------------------------------------------------------

_agent_locks: dict = {}
_agent_lock_meta = threading.Lock()


def _case_lock(case_path: str) -> threading.Lock:
    with _agent_lock_meta:
        if case_path not in _agent_locks:
            _agent_locks[case_path] = threading.Lock()
        return _agent_locks[case_path]


def _session_file(case_path: Path) -> Path:
    return case_path / "agent_session.json"


def _read_session(case_path: Path) -> dict:
    sf = _session_file(case_path)
    if sf.exists():
        try:
            return json.loads(sf.read_text())
        except Exception:
            pass
    return {}


def _write_session(case_path: Path, data: dict) -> None:
    _session_file(case_path).write_text(json.dumps(data))


def _mcp_config(case_path: str, venv_python: str) -> dict:
    env_block = {"SIFTICS_CASE_DIR": case_path}
    servers = {
        "siftics_case":        {"command": venv_python, "args": ["-m", "mcp_case.server"],        "env": env_block},
        "siftics_ic_approval": {"command": venv_python, "args": ["-m", "mcp_ic_approval.server"], "env": env_block},
        "siftics_baseline":    {"command": venv_python, "args": ["-m", "mcp_baseline.server"],    "env": env_block},
        "siftics_rag":         {"command": venv_python, "args": ["-m", "mcp_rag.server"],         "env": env_block},
        "siftics_cti":         {"command": venv_python, "args": ["-m", "mcp_cti.server"],         "env": env_block},
        "siftics_broker":      {"command": venv_python, "args": ["-m", "mcp_broker.server"],      "env": env_block},
        "siftics_intel":       {"command": venv_python, "args": ["-m", "mcp_intel.server"],       "env": env_block},
    }
    return {"mcpServers": servers}


def _stream_agent(cmd: list, env: dict, case_path: Path):
    """Run claude subprocess and yield SSE data lines."""
    lock = _case_lock(str(case_path))
    if not lock.acquire(blocking=False):
        yield "data: " + json.dumps({"type": "error", "message": "Agent is already running."}) + "\n\n"
        return
    # Accumulate token usage across all assistant turns so we can write a
    # single llm_call audit event when the result event arrives.
    _usage = {"input": 0, "cached_read": 0, "cached_creation": 0, "output": 0, "model": ""}
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=env)
        for raw in proc.stdout:
            raw = raw.strip()
            if not raw:
                continue
            try:
                evt = json.loads(raw)
            except Exception:
                continue
            if evt.get("type") == "system" and evt.get("session_id"):
                sess = _read_session(case_path)
                sess["session_id"] = evt["session_id"]
                # Bind session to this case so resuming it in the wrong case
                # is detectable.
                try:
                    header = case_state.case_get_header()
                    sess["case_id"] = header.get("case_id", "")
                except Exception:
                    pass
                _write_session(case_path, sess)
            elif evt.get("type") == "assistant":
                msg = evt.get("message", {})
                if not _usage["model"] and msg.get("model"):
                    _usage["model"] = msg["model"]
                u = msg.get("usage") or {}
                _usage["input"] += int(u.get("input_tokens", 0))
                _usage["cached_read"] += int(u.get("cache_read_input_tokens", 0))
                _usage["cached_creation"] += int(u.get("cache_creation_input_tokens", 0))
                _usage["output"] += int(u.get("output_tokens", 0))
            elif evt.get("type") == "result":
                try:
                    cost_usd = float(
                        evt.get("total_cost_usd") or evt.get("cost_usd") or 0.0
                    )
                    inp = _usage["input"]
                    hit_rate = round(_usage["cached_read"] / inp, 4) if inp else 0.0
                    old_case = os.environ.get("SIFTICS_CASE_DIR")
                    os.environ["SIFTICS_CASE_DIR"] = str(case_path)
                    try:
                        audit.append_event("llm_call", {
                            "model": _usage["model"] or "claude-code",
                            "task_class": "investigator",
                            "purpose": "claude_code_agent_turn",
                            "input_tokens": inp,
                            "cached_read_tokens": _usage["cached_read"],
                            "cached_creation_tokens": _usage["cached_creation"],
                            "output_tokens": _usage["output"],
                            "cost_usd": round(cost_usd, 6),
                            "cache_hit_rate": hit_rate,
                        }, actor="claude_code_agent")
                    finally:
                        if old_case is None:
                            os.environ.pop("SIFTICS_CASE_DIR", None)
                        else:
                            os.environ["SIFTICS_CASE_DIR"] = old_case
                except Exception:
                    pass
            yield "data: " + json.dumps(evt) + "\n\n"
        proc.wait()
    finally:
        lock.release()


def _make_agent_cmd(case_path: Path, prompt: str,
                    session_id: str | None = None) -> tuple[list, dict]:
    venv_bin = str(Path(__file__).parent.parent / ".venv" / "bin")
    venv_python = str(Path(venv_bin) / "python3")
    mcp_file = Path(tempfile.mktemp(suffix=".json", prefix="siftics_mcp_"))
    mcp_file.write_text(json.dumps(_mcp_config(str(case_path), venv_python)))
    # Prompt must come before variadic flags (--mcp-config consumes subsequent args).
    # --dangerously-skip-permissions required: permission prompts block in the background
    # process and cannot be answered from the browser UI.
    cmd = ["claude", "-p", prompt,
           "--output-format", "stream-json",
           "--verbose",
           "--dangerously-skip-permissions",
           "--mcp-config", str(mcp_file),
           "--add-dir", str(case_path)]
    if session_id:
        cmd += ["--resume", session_id]
    # Prepend venv bin to PATH so the agent's bash commands resolve pip3,
    # python3, and all venv-installed tools to the venv versions, not the
    # system ones (which reject installs with PEP 668 on Ubuntu 23+).
    env = {**os.environ, "SIFTICS_CASE_DIR": str(case_path)}
    env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")
    env["VIRTUAL_ENV"] = str(Path(venv_bin).parent)
    return cmd, env


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dashboard_context() -> dict:
    try:
        header = case_state.case_get_header()
    except FileNotFoundError:
        header = None
    try:
        cfg = runtime_config.load_config(case_dir=audit.case_dir())
    except Exception:
        cfg = runtime_config.RuntimeConfig()
    return {
        "case": header,
        "latest_briefing": case_state.briefing_latest(),
        "asr": _asr_summary(),
        "cet": _cet_summary(),
        "itq": case_state.itq_progress(),
        "pending_gate_count": len(_list_pending_gates()),
        "draft_ioc_count": _draft_ioc_count(),
        "runtime": _runtime_status(),
        "cfg": cfg,
        "phases": PHASES,
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
    # The agent is always run via `claude` subprocess regardless of agent.yaml;
    # reflect the actual runtime label rather than the config value.
    return {
        "runtime": "claude_code",
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
            "Uses your existing Claude Code subscription. SIFTics registers its tool "
            "servers with Claude so the agent can read evidence, record findings, and "
            "request approvals automatically.",
            True),
        ("anthropic_api", "Anthropic API key",
            "In-process chat loop in SIFTics's UI. Prompt caching enabled. "
            "Cost tracking + per-case budget circuit breaker active.",
            False),
    ]:
        c = copy.deepcopy(cfg)
        c.runtime = value
        rt = agent_runtime.runtime_for_config(c)
        ok, status = rt.setup_check()
        out.append({
            "value": value, "label": label, "description": desc,
            "recommended": recommended, "detected": ok, "status": status,
        })
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


def _draft_ioc_count() -> int:
    try:
        from siftics import intel as intel_lib
        return intel_lib.ioc_count(status="draft")
    except Exception:
        return 0


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
