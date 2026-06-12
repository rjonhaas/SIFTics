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
    _start_audit_tailer(app)

    @app.context_processor
    def _inject_labels() -> dict:
        return {"labels": app.config["LABELS"]}

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
        exec_summary = _executive_summary(header or {}, findings, briefings, itq or {})
        return render_template("report.html",
                               header=header,
                               briefings=briefings,
                               findings=findings,
                               itq=itq,
                               itq_answered=itq_answered,
                               exec_summary=exec_summary)

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

        try:
            itq = case_state.itq_progress()
        except Exception:
            itq = {}
        exec_summary = _executive_summary(header or {}, findings, briefings, itq or {})

        lines = []
        lines.append(f"# Case Report — {header.get('name', 'Unknown')}\n")
        lines.append(f"**Case ID:** {header.get('case_id', '')}  ")
        lines.append(f"**Incident Commander:** {header.get('incident_commander', {}).get('name', '')}  ")
        lines.append(f"**Opened:** {header.get('opened_at', '')[:10]}  ")
        lines.append(f"**Impact:** {header.get('impact_level', '').upper()}  \n")

        if exec_summary:
            lines.append("---\n## Executive Summary\n")
            for para in exec_summary:
                lines.append(para)
                lines.append("")  # blank line between paragraphs

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

    # NB: /audit and /audit/verify routes intentionally removed — the raw
    # audit chain (forensic_audit.jsonl) is still written on disk and can be
    # inspected with `audit_verify.sh` or any JSONL tool. A UI view of the
    # raw events was not useful to operators.

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
        # Pre-populate the case_id field with YYYY-MM-DD-NN so the operator
        # doesn't have to type a name unless they want a custom one. The
        # helper looks at ~/Desktop/cases for today's existing dirs and
        # returns the next zero-padded sequence number.
        default_case_id = case_state.next_case_id("~/Desktop/cases")
        return render_template("new_case.html",
                               form={"case_id": default_case_id})

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
        # Probe each integration key without exposing the value
        integrations_status = {
            name: runtime_config.integration_key_present(getattr(cfg.integrations, name))
            for name in ("shodan", "virustotal", "osm")
        }
        # Probe response target credential presence (only the keyring-backed ones)
        targets_status = {
            "elastic_api_key": runtime_config.integration_key_present(cfg.response_targets.elastic.api_key),
            "entra_client_secret": runtime_config.integration_key_present(cfg.response_targets.entra_id.client_secret),
        }
        # Auth state for the template — tells it which radio to select
        # and whether to show the "claude.ai subscription detected" badge.
        oauth_creds = (Path.home() / ".claude" / ".credentials.json")
        oauth_creds_alt = (Path.home() / ".claude" / "credentials.json")
        oauth_detected = oauth_creds.exists() or oauth_creds_alt.exists()
        env_key_set = bool(os.environ.get("ANTHROPIC_API_KEY"))
        current_auth_mode = "api_key" if env_key_set else "subscription_oauth"

        # Response posture — drives mcp_broker's _MODE via env var.
        # The broker reads SIFTICS_BROKER_MODE at its own subprocess start;
        # patching os.environ here means the next broker spawn picks it up
        # without restarting siftics-ui.
        current_broker_mode = os.environ.get("SIFTICS_BROKER_MODE", "mock").lower()
        if current_broker_mode not in ("mock", "real"):
            current_broker_mode = "mock"

        return render_template("setup.html",
                                cfg=cfg,
                                options=options,
                                current_runtime=cfg.runtime,
                                current_auth_mode=current_auth_mode,
                                oauth_detected=oauth_detected,
                                env_key_set=env_key_set,
                                current_broker_mode=current_broker_mode,
                                integrations_status=integrations_status,
                                targets_status=targets_status,
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

        # Anthropic key — separate flow (legacy)
        key = (request.form.get("anthropic_key") or "").strip()
        anthropic_key_location: str | None = None
        if key:
            anthropic_key_location = runtime_config.save_anthropic_key(cfg.anthropic, key)

        # Integration keys — Shodan / VirusTotal / OSM
        # Blank = no change; CLEAR = remove.
        integration_locations: dict[str, str] = {}
        for name, fallback_file in [
            ("shodan", "shodan.key"),
            ("virustotal", "virustotal.key"),
            ("osm", "osm.key"),
        ]:
            field = (request.form.get(f"{name}_key") or "").strip()
            ikey = getattr(cfg.integrations, name)
            if field == "CLEAR":
                runtime_config.clear_integration_key(ikey)
                integration_locations[name] = "cleared"
            elif field:
                integration_locations[name] = runtime_config.save_integration_key(
                    ikey, field, fallback_file)

        # Response targets — Velociraptor / Elastic / Entra ID
        # Non-secret fields (URL, cert paths, tenant ID, etc.) go in agent.yaml.
        # Secret fields (Elastic API key, Entra client secret) go in keyring.
        targets_form = {
            "velociraptor_enabled": "velociraptor_enabled" in request.form,
            "velociraptor_url": (request.form.get("velociraptor_url") or "").strip(),
            "velociraptor_client_cert": (request.form.get("velociraptor_client_cert") or "").strip(),
            "velociraptor_client_key": (request.form.get("velociraptor_client_key") or "").strip(),
            "velociraptor_ca_cert": (request.form.get("velociraptor_ca_cert") or "").strip(),
            "elastic_enabled": "elastic_enabled" in request.form,
            "elastic_url": (request.form.get("elastic_url") or "").strip(),
            "elastic_index": (request.form.get("elastic_index") or "").strip(),
            "entra_enabled": "entra_enabled" in request.form,
            "entra_live": "entra_live" in request.form,
            "entra_tenant": (request.form.get("entra_tenant") or "").strip(),
            "entra_client_id": (request.form.get("entra_client_id") or "").strip(),
        }
        rt = cfg.response_targets
        rt.velociraptor.enabled = targets_form["velociraptor_enabled"]
        if targets_form["velociraptor_url"]:
            rt.velociraptor.api_url = targets_form["velociraptor_url"]
        if targets_form["velociraptor_client_cert"]:
            rt.velociraptor.client_cert_path = targets_form["velociraptor_client_cert"]
        if targets_form["velociraptor_client_key"]:
            rt.velociraptor.client_key_path = targets_form["velociraptor_client_key"]
        if targets_form["velociraptor_ca_cert"]:
            rt.velociraptor.ca_cert_path = targets_form["velociraptor_ca_cert"]
        rt.elastic.enabled = targets_form["elastic_enabled"]
        if targets_form["elastic_url"]:
            rt.elastic.url = targets_form["elastic_url"]
        if targets_form["elastic_index"]:
            rt.elastic.index = targets_form["elastic_index"]
        rt.entra_id.enabled = targets_form["entra_enabled"]
        rt.entra_id.live_mode = targets_form["entra_live"]
        if targets_form["entra_tenant"]:
            rt.entra_id.tenant_id = targets_form["entra_tenant"]
        if targets_form["entra_client_id"]:
            rt.entra_id.client_id = targets_form["entra_client_id"]

        # Keyring-backed secrets for response targets
        target_secret_locations: dict[str, str] = {}
        for name, ikey, fallback_file in [
            ("elastic_api_key", rt.elastic.api_key, "elastic.key"),
            ("entra_client_secret", rt.entra_id.client_secret, "entra_client_secret.key"),
        ]:
            field = (request.form.get(name) or "").strip()
            if field == "CLEAR":
                runtime_config.clear_integration_key(ikey)
                target_secret_locations[name] = "cleared"
            elif field:
                target_secret_locations[name] = runtime_config.save_integration_key(
                    ikey, field, fallback_file)

        path = runtime_config.save_config(cfg)

        # ----------------------------------------------------------------
        # Auth method switch — apply to the running Flask process so the
        # NEXT agent subprocess inherits the new credential without
        # restarting siftics-ui. Without this, the operator can change
        # auth in /setup but the running case keeps using whatever
        # ANTHROPIC_API_KEY was inherited from the shell that launched
        # siftics-ui, and the case appears to "freak out" because the
        # UI says one thing but claude is doing another.
        #
        # Two modes recognised on the form:
        #   auth_mode=api_key          → ensure os.environ has the key
        #   auth_mode=subscription     → pop the env var so `claude` falls
        #                                through to its own ~/.claude OAuth
        #
        # If the form doesn't carry auth_mode (older client), we infer
        # from whether a new key was provided.
        # ----------------------------------------------------------------
        prev_auth_method = "api_key" if os.environ.get("ANTHROPIC_API_KEY") else "subscription_oauth"
        auth_mode = (request.form.get("auth_mode") or "").strip()
        if not auth_mode:
            auth_mode = "api_key" if (key or anthropic_key_location) else prev_auth_method

        if auth_mode == "api_key":
            try:
                resolved = runtime_config.resolve_anthropic_key(cfg.anthropic)
                os.environ["ANTHROPIC_API_KEY"] = resolved
                new_auth_method = "api_key"
            except runtime_config.MissingAPIKey:
                # User picked api_key mode but nothing is on disk yet —
                # leave any pre-existing env var alone, audit the intent.
                new_auth_method = "api_key_pending"
        else:  # subscription
            os.environ.pop("ANTHROPIC_API_KEY", None)
            new_auth_method = "subscription_oauth"

        # Audit the LOCATIONS, never the key values.
        audit.append_event("runtime_config_saved",
                            {"runtime": cfg.runtime,
                             "budget_usd": cfg.cost_budget_per_case_usd,
                             "config_path": str(path),
                             "anthropic_key_location": anthropic_key_location,
                             "integration_keys_updated": integration_locations or None,
                             "response_targets_enabled": {
                                 "velociraptor": rt.velociraptor.enabled,
                                 "elastic": rt.elastic.enabled,
                                 "entra_id": rt.entra_id.enabled,
                                 "entra_live_mode": rt.entra_id.live_mode,
                             },
                             "response_target_secrets_updated": target_secret_locations or None},
                            actor="ic")

        # Auth method change is its own event — easier for a reviewer
        # replaying the chain to explain "turns 1-13 ran on API key,
        # turns 14+ ran on subscription" without having to diff configs.
        if prev_auth_method != new_auth_method:
            audit.append_event("runtime_auth_changed",
                                {"from": prev_auth_method,
                                 "to": new_auth_method,
                                 "env_var_set": bool(os.environ.get("ANTHROPIC_API_KEY"))},
                                actor="ic")

        # ----------------------------------------------------------------
        # Response posture — same in-process env-patch pattern as auth.
        # Patching SIFTICS_BROKER_MODE here means the next mcp_broker
        # subprocess inherits the new posture (the agent re-spawns brokers
        # per turn, so this takes effect on the next message).
        # ----------------------------------------------------------------
        prev_broker_mode = os.environ.get("SIFTICS_BROKER_MODE", "mock").lower()
        if prev_broker_mode not in ("mock", "real"):
            prev_broker_mode = "mock"
        new_broker_mode = (request.form.get("broker_mode") or prev_broker_mode).strip().lower()
        if new_broker_mode not in ("mock", "real"):
            new_broker_mode = prev_broker_mode

        os.environ["SIFTICS_BROKER_MODE"] = new_broker_mode

        if prev_broker_mode != new_broker_mode:
            audit.append_event("response_posture_changed",
                                {"from": prev_broker_mode,
                                 "to": new_broker_mode},
                                actor="ic")
        return redirect(url_for("dashboard"))

    # -----------------------------------------------------------------
    # Dashboard cost partial
    # -----------------------------------------------------------------

    @app.route("/dashboard/runtime-status")
    def dashboard_runtime_status():
        return render_template("_runtime_status.html",
                                runtime=_runtime_status())

    @app.route("/dashboard/gates-summary")
    def dashboard_gates_summary():
        return render_template("_gates_summary.html",
                                pending_gate_count=len(_list_pending_gates()))

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
        "siftics_containment": {"command": venv_python, "args": ["-m", "mcp_containment.server"], "env": env_block},
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


def _executive_summary(header: dict, findings: list, briefings: list, itq: dict) -> list[str]:
    """Derive an executive-summary in narrative paragraphs.

    Returns a list of paragraph strings (typically 2): the first covers
    who / what / when / where / why; the second covers what we did and
    what remains. Empty list if no findings exist yet — the template
    then suppresses the section entirely.

    Composed from existing case state (header, ASR rows, briefings, ITQ
    progress) on every render — sharpens automatically as data accrues.
    No separate field for the agent to maintain.
    """
    import re

    if not findings:
        # Empty case — nothing meaningful to summarise as prose
        return []

    # --- derivations (same logic as before, but kept as locals, not returned) ---

    # WHO (affected)
    by_impact: dict[str, list[str]] = {}
    for f in findings:
        rating = (f.get("impact_rating") or "low").lower()
        by_impact.setdefault(rating, []).append(f.get("system_identifier") or "?")
    worst_systems: list[str] = []
    worst_label = "affected"
    for rating in ("critical", "high", "moderate", "medium", "low"):
        if by_impact.get(rating):
            worst_systems = sorted(set(by_impact[rating]))
            worst_label = rating
            break
    n_total = len({(f.get("system_identifier") or "?") for f in findings})

    # WHO (attacker) — non-RFC1918 IPs from ASR notes
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    private_prefixes = ("10.", "192.168.", "127.", "0.")
    external_ips: set[str] = set()
    for f in findings:
        for fld in (f.get("notes"), f.get("how_determined"), f.get("impact_description")):
            if not fld:
                continue
            for ip in ip_re.findall(fld):
                if ip.startswith(private_prefixes):
                    continue
                if ip.startswith("172."):
                    second = ip.split(".")[1]
                    if second.isdigit() and 16 <= int(second) <= 31:
                        continue
                external_ips.add(ip)

    # WHAT — earliest briefing narrative or worst finding's impact_description
    narrative = ""
    if briefings:
        text = briefings[0].get("text") or briefings[0].get("summary") or ""
        narrative = text.strip()
    if not narrative:
        rank = {"critical": 0, "high": 1, "moderate": 2, "medium": 2, "low": 3}
        worst = sorted(findings, key=lambda r: rank.get((r.get("impact_rating") or "low").lower(), 9))[0]
        narrative = (worst.get("impact_description") or "").strip()
    # Strip trailing period — we re-add when joining sentences
    narrative = narrative.rstrip(".").strip()

    # WHEN
    detected = (header.get("opened_at") or "")[:10]
    compromise_dates = sorted(
        {(f.get("date_of_compromise") or "")[:10] for f in findings if f.get("date_of_compromise")}
    )

    # WHERE
    locations = sorted({(f.get("location") or "").strip() for f in findings if f.get("location")})

    # WHY
    motivation = (header.get("motivation") or header.get("why") or "").strip()

    # WHAT WE DID
    hunt_ids: set[str] = set()
    for f in findings:
        for h in f.get("linked_hunts") or []:
            if h:
                hunt_ids.add(h)
    isolated = sorted({
        f.get("system_identifier") for f in findings
        if "isolation" in (f.get("notes") or "").lower() and f.get("system_identifier")
    })

    # WHAT REMAINS
    pending_actions = []
    for f in findings:
        if (f.get("system_safe") or "").lower() != "safe":
            pa = (f.get("planned_action") or "").strip()
            if pa:
                pending_actions.append((f.get("system_identifier"), pa))
    itq_open = max(0, (itq.get("total") or 0) - (itq.get("answered") or 0))

    # --- prose composition ---

    impact_lvl = (header.get("impact_level") or "moderate").lower()
    case_name = (header.get("name") or "an incident").strip()

    p1_sentences: list[str] = []

    # Sentence 1 — detection, impact, affected systems
    sys_phrase = (
        f"{worst_label} severity on {', '.join(worst_systems)}"
        + (f" (of {n_total} systems involved)" if n_total > len(worst_systems) else "")
    )
    if detected:
        p1_sentences.append(
            f"On {detected}, {case_name} was opened as a {impact_lvl}-impact incident, "
            f"with {sys_phrase}"
        )
    else:
        p1_sentences.append(
            f"{case_name} is under investigation as a {impact_lvl}-impact incident, "
            f"with {sys_phrase}"
        )

    # Sentence 2 — narrative (what happened)
    if narrative:
        # Cap the narrative so the paragraph stays readable
        if len(narrative) > 320:
            narrative = narrative[:320].rsplit(" ", 1)[0] + "…"
        p1_sentences.append(narrative)

    # Sentence 3 — attacker infra + compromise window
    when_phrase = ""
    if compromise_dates:
        if len(compromise_dates) == 1:
            when_phrase = f"observed on {compromise_dates[0]}"
        else:
            when_phrase = f"spanning {compromise_dates[0]} through {compromise_dates[-1]}"
    if external_ips:
        ips = ", ".join(sorted(external_ips))
        if when_phrase:
            p1_sentences.append(f"Attacker infrastructure observed: {ips}, with activity {when_phrase}")
        else:
            p1_sentences.append(f"Attacker infrastructure observed: {ips}")
    elif when_phrase:
        p1_sentences.append(f"Compromise activity was {when_phrase}")

    # Sentence 4 — location context (if it adds anything not already in sys_phrase)
    extra_locations = [loc for loc in locations
                       if not any(s in loc for s in worst_systems)]
    if extra_locations:
        p1_sentences.append(f"Affected location(s): {'; '.join(extra_locations)}")

    # Sentence 5 — motivation / why
    if motivation:
        p1_sentences.append(f"Working hypothesis on motive: {motivation.rstrip('.')}")
    else:
        p1_sentences.append(
            "Attacker motive remains under analysis; the Incident Commander has not yet "
            "characterised it in the case header"
        )

    paragraph_1 = ". ".join(s.rstrip(".").strip() for s in p1_sentences if s.strip()) + "."

    # --- Paragraph 2 — what we did and what's left ---

    p2_sentences: list[str] = []

    actions = []
    if hunt_ids:
        actions.append(f"executed {len(hunt_ids)} fleet hunt{'s' if len(hunt_ids) != 1 else ''} "
                       f"({', '.join(sorted(hunt_ids))})")
    if isolated:
        actions.append(f"requested isolation for {', '.join(isolated)}")
    if briefings:
        actions.append(f"posted {len(briefings)} briefing{'s' if len(briefings) != 1 else ''} "
                       "to the Common Operating Picture (COP)")
    if actions:
        # Conjoin naturally: "a; b; and c."
        if len(actions) == 1:
            joined = actions[0]
        elif len(actions) == 2:
            joined = f"{actions[0]} and {actions[1]}"
        else:
            joined = "; ".join(actions[:-1]) + f"; and {actions[-1]}"
        p2_sentences.append(f"In response, the investigation team has {joined}")
    else:
        p2_sentences.append(
            "No completed response actions have been recorded yet; "
            "the investigation is in its initial scoping phase"
        )

    # Remaining work
    remaining = []
    if pending_actions:
        # Up to 2 system: action pairs, then count overflow
        shown = pending_actions[:2]
        rendered = "; ".join(
            f"{sid} ({pa.split('.')[0].strip()})" for sid, pa in shown
        )
        if len(pending_actions) > 2:
            remaining.append(f"pending actions on {rendered} and {len(pending_actions) - 2} other system(s)")
        else:
            remaining.append(f"pending actions on {rendered}")
    if itq_open:
        q_word = "triage question" if itq_open == 1 else "triage questions"
        remaining.append(f"{itq_open} unanswered {q_word}")
    if remaining:
        if len(remaining) == 1:
            joined = remaining[0]
        else:
            joined = " and ".join(remaining)
        p2_sentences.append(f"Outstanding work includes {joined}")

    paragraph_2 = ". ".join(s.rstrip(".").strip() for s in p2_sentences if s.strip()) + "."

    return [paragraph_1, paragraph_2]


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
            gate = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        # Attach Command Staff assessments — the matching Safety + Legal
        # consults from the audit log keyed on action_hash. Pending gate
        # objects already carry `action_hash` (since the G16/G17 wire-up).
        ah = gate.get("action_hash")
        if ah:
            gate["safety"], gate["legal"] = _command_staff_for(ah)
        out.append(gate)
    return out


def _command_staff_for(ah: str) -> tuple[dict | None, dict | None]:
    """Return (safety_assessment_payload, legal_review_payload) for an
    action_hash — most recent matching audit events, or (None, None) if
    none exist. Used to render the Command Staff panel under each
    pending gate on /gates."""
    safety: dict | None = None
    legal: dict | None = None
    for ev in reversed(list(audit.iter_events())):
        et = ev.get("type")
        payload = ev.get("payload") or {}
        if payload.get("action_hash") != ah:
            continue
        if et == "safety_assessment" and safety is None:
            safety = payload
        elif et == "legal_review" and legal is None:
            legal = payload
        if safety and legal:
            break
    return safety, legal


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
    import html as _html
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
        # Include gate metadata as data-* attributes so the gates.html JS
        # can pick them up and auto-dispatch a follow-up agent message
        # ("execute the approved action") — this is the "fight back at AI
        # speed" loop closure. Only fires for approvals; denials do not
        # auto-dispatch.
        gate = _html.escape(str(approval.get("gate") or ""), quote=True)
        summary = _html.escape(str(approval.get("summary") or "")[:200],
                                quote=True)
        req_id_esc = _html.escape(str(request_id), quote=True)
        return Response(
            f"<div class='text-emerald-400 p-2' "
            f"data-signed='{decision}' "
            f"data-request-id='{req_id_esc}' "
            f"data-gate='{gate}' "
            f"data-summary='{summary}'>"
            f"Signed {decision} for <code>{req_id_esc}</code>"
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
