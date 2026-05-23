"""Console-script entry points: sift-case-init, sift-approve."""
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
    p.add_argument("--itq-template", default=None, type=Path,
                   help="Path to templates/itq_questions.yaml.")
    p.add_argument("--no-key", action="store_true",
                   help="Skip IC key initialisation (rare — only for tests).")
    args = p.parse_args(argv)

    os.environ["SIFTICS_CASE_DIR"] = str(args.case_dir.expanduser().resolve())

    header = case_state.init_case(
        case_id=args.case_id,
        name=args.name,
        ic_name=args.ic_name,
        ic_contact=args.ic_contact,
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
