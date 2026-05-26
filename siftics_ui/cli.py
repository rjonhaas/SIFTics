"""siftics-ui CLI — `siftics-ui run`."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from .app import create_app


def run_main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Run the SIFTics web UI.",
        usage="siftics-ui run [options]",
    )
    # Accept optional 'run' positional to match `siftics-ui run --case-dir ...`
    p.add_argument("subcommand", nargs="?", choices=["run"],
                   help="Subcommand (only 'run' is supported; may be omitted).")
    p.add_argument("--case-dir", type=Path,
                   help="Override $SIFTICS_CASE_DIR.")
    p.add_argument("--host", default="127.0.0.1", help="Default 127.0.0.1.")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args(argv)

    if args.case_dir:
        os.environ["SIFTICS_CASE_DIR"] = str(args.case_dir.expanduser().resolve())
    if not os.environ.get("SIFTICS_CASE_DIR"):
        raise SystemExit("SIFTICS_CASE_DIR is required (or pass --case-dir).")

    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
    return 0
