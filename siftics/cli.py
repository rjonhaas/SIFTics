"""Console-script entry points: sift-case-init, sift-approve, sift-counsel-acknowledge."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import case_state, ic_approval


def case_init_main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Initialise a SIFTics case directory.")
    p.add_argument("--case-dir", required=True, type=Path,
                   help="Path to the case directory (will be created if missing).")
    p.add_argument("--case-id", required=True)
    p.add_argument("--name", required=True, help="Human-readable incident name.")
    p.add_argument("--ic-name", required=True, help="Incident Commander username.")
    p.add_argument("--ic-contact", default="", help="IC email or chat handle.")
    p.add_argument("--context", default="",
                   help="Free-form initial briefing the IC wants the agent to "
                        "read on day one. The kind of one-paragraph sendoff a "
                        "real IC would give: what was reported, what evidence "
                        "got pulled and from where, what looks suspicious. "
                        "The agent reads it for orientation but verifies "
                        "against evidence - it's not ground truth.")
    p.add_argument("--itq-template", default=None, type=Path,
                   help="Path to siftics/templates/itq_questions.yaml.")
    p.add_argument("--no-key", action="store_true",
                   help="Skip IC key initialisation (rare — only for tests).")
    args = p.parse_args(argv)

    os.environ["SIFTICS_CASE_DIR"] = str(args.case_dir.expanduser().resolve())

    header = case_state.init_case(
        case_id=args.case_id,
        name=args.name,
        ic_name=args.ic_name,
        ic_contact=args.ic_contact,
        context=args.context,
        itq_template=args.itq_template,
    )
    print(f"[case-init] case header written to {Path(os.environ['SIFTICS_CASE_DIR']) / 'case.json'}")
    print(f"[case-init] incident commander: {header['incident_commander']['name']}")

    if not args.no_key:
        print("[case-init] now initialising IC HMAC key...")
        passphrase = getpass.getpass("Set IC passphrase: ")
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            print("[case-init] passphrases did not match — aborting.", file=sys.stderr)
            return 2
        meta = ic_approval.init_ic_key(passphrase, ic_name=args.ic_name)
        print(f"[case-init] IC key fingerprint: {meta['key_fingerprint_sha256'][:16]}…")
        print(f"[case-init] PBKDF2 iterations: {meta['iterations']}")
    print("[case-init] done.")
    return 0


def approve_main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Sign / deny an IC Authority Gate.")
    p.add_argument("request_id")
    p.add_argument("--case-dir", required=False, type=Path,
                   help="Override $SIFTICS_CASE_DIR.")
    p.add_argument("--deny", action="store_true",
                   help="Sign as denial instead of approval.")
    p.add_argument("--show-only", action="store_true",
                   help="Show the pending request without signing.")
    args = p.parse_args(argv)

    if args.case_dir:
        os.environ["SIFTICS_CASE_DIR"] = str(args.case_dir.expanduser().resolve())

    pending_p = ic_approval.case_dir() / "approvals" / "pending" / f"{args.request_id}.json"
    if not pending_p.exists():
        print(f"No pending request: {args.request_id}", file=sys.stderr)
        return 1
    request = json.loads(pending_p.read_text(encoding="utf-8"))

    print()
    print(f"Pending request: {args.request_id}")
    print()
    print(f"  Gate:          {request['gate']}")
    print(f"  Proposed by:   {request['proposed_by']}")
    print(f"  Summary:       {request['summary']}")
    print(f"  Action:")
    for line in json.dumps(request['action'], indent=4).splitlines():
        print(f"    {line}")
    print(f"  Requested at:  {request['requested_at']}")
    print(f"  Agent context: {request['agent_context_hash'][:16]}…")
    print()

    if args.show_only:
        return 0

    decision = "denied" if args.deny else "approved"
    confirm = input(f"Sign as '{decision}'? [y/N] ").strip().lower()
    if confirm != "y":
        print("[approve] no action taken.")
        return 3
    passphrase = getpass.getpass("Enter IC passphrase: ")
    try:
        approval = ic_approval.sign_approval(args.request_id, passphrase, decision)
    except ic_approval.ApprovalInvalidError as e:
        print(f"[approve] error: {e}", file=sys.stderr)
        return 4
    print(f"[approve] signed: {decision}")
    print(f"[approve] signature: {approval['signature'][:16]}…")
    return 0


def counsel_acknowledge_main(argv: list[str] | None = None) -> int:
    """Record an IC acknowledgement that outside counsel has been engaged.

    Required before any Authority Gate with a Legal Officer verdict of
    ``outside_counsel_required`` can be signed (G17 enforcement in
    `siftics/ic_approval.py`).

    The CLI appends a ``counsel_acknowledged`` audit event with the IC's
    name, an optional matter ID, and a free-text reason. The audit event
    is what `request_approval` checks for before lifting the
    LegalCounselRequired refusal.
    """
    p = argparse.ArgumentParser(
        description="Record IC acknowledgement that outside counsel has been engaged "
                    "(required to clear a Legal Officer outside_counsel_required verdict).",
    )
    p.add_argument("--case-dir", required=False, type=Path,
                   help="Override $SIFTICS_CASE_DIR.")
    p.add_argument("--matter-id", default=None,
                   help="Specific legal matter ID this acknowledgement covers. Omit "
                        "for single-matter cases (any counsel_acknowledged event will "
                        "satisfy any matter).")
    p.add_argument("--reason", required=True,
                   help="One-sentence reason / context for the acknowledgement. "
                        "Goes into the audit chain — write it as something a "
                        "reviewer or regulator could read months from now.")
    p.add_argument("--ic-name", default=None,
                   help="IC name for the audit row. Defaults to the case header's "
                        "incident_commander.name, then $USER.")
    p.add_argument("--firm", default=None,
                   help="Outside counsel firm or contact (optional, informational).")
    args = p.parse_args(argv)

    if args.case_dir:
        os.environ["SIFTICS_CASE_DIR"] = str(args.case_dir.expanduser().resolve())

    try:
        header = case_state.case_get_header()
    except Exception:
        header = {}
    ic_name = (args.ic_name
               or ((header.get("incident_commander") or {}).get("name"))
               or os.environ.get("USER")
               or "ic")

    reason = args.reason.strip()
    if len(reason) < 15:
        print("[counsel-acknowledge] error: --reason must be at least 15 characters "
              "(write a substantive note for the audit chain).", file=sys.stderr)
        return 2

    payload = {
        "ic_name": ic_name,
        "reason": reason,
    }
    if args.matter_id:
        payload["matter_id"] = args.matter_id.strip()
    if args.firm:
        payload["firm"] = args.firm.strip()

    case_state.append_event("counsel_acknowledged", payload, actor="ic")

    print(f"[counsel-acknowledge] recorded for {ic_name}"
          + (f" (matter {payload.get('matter_id')})" if payload.get("matter_id") else "")
          + ".")
    print("[counsel-acknowledge] Authority Gates blocked by "
          "LegalCounselRequired can now be signed.")
    return 0
