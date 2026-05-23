"""Build the baseline SQLite from Rathbun's published corpora.

Usage:
    python -m mcp_baseline.build_baseline_db --output mcp_baseline/baseline.sqlite

Sources (each cloned into a temp dir, parsed, normalised):
    https://github.com/AndrewRathbun/VanillaWindowsReference
    https://github.com/AndrewRathbun/VanillaWindowsRegistryHives

The schema is designed for fast equality lookups by mcp_baseline.server.
Embeddings live in mcp_rag — keep them apart.
"""
from __future__ import annotations

import argparse
import csv
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS files (
    path     TEXT NOT NULL,
    sha256   TEXT,
    build    TEXT NOT NULL,
    edition  TEXT NOT NULL,
    signer   TEXT,
    size     INTEGER,
    version  TEXT
);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_path   ON files(path);

CREATE TABLE IF NOT EXISTS registry (
    hive             TEXT NOT NULL,
    key_path         TEXT NOT NULL,
    value_name       TEXT,
    value_data_hash  TEXT,
    build            TEXT NOT NULL,
    edition          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reg_path ON registry(hive, key_path);

CREATE TABLE IF NOT EXISTS services (
    name        TEXT NOT NULL,
    image_path  TEXT,
    sha256      TEXT,
    build       TEXT NOT NULL,
    edition     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_svc_name ON services(name);

CREATE TABLE IF NOT EXISTS scheduled (
    task_name TEXT NOT NULL,
    action    TEXT,
    build     TEXT NOT NULL,
    edition   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sched_name ON scheduled(task_name);
"""


def init_db(path: Path) -> sqlite3.Connection:
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(str(path))
    conn.executescript(SCHEMA)
    return conn


def stamp_meta(conn: sqlite3.Connection, **kwargs: str) -> None:
    for k, v in kwargs.items():
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            (k, v),
        )


def clone_or_skip(repo: str, dest: Path) -> None:
    if dest.exists():
        print(f"[clone] {dest} exists; skipping git clone.")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[clone] git clone --depth 1 {repo} {dest}")
    subprocess.run(["git", "clone", "--depth", "1", repo, str(dest)], check=True)


def ingest_vanilla_windows_reference(conn: sqlite3.Connection, root: Path) -> dict:
    """Walk Rathbun's VanillaWindowsReference for file inventory CSVs.

    The repo organises content per build/edition; we walk every CSV and try
    to extract (path, sha256, signer, size, version) tuples by inspecting
    column headers.
    """
    counts = {"files": 0, "scanned_csv": 0, "skipped_csv": 0}
    for csv_path in root.rglob("*.csv"):
        rel = csv_path.relative_to(root)
        parts = list(rel.parts)
        # Expect: <build>/<edition>/<...>/file.csv
        if len(parts) < 3:
            counts["skipped_csv"] += 1
            continue
        build = parts[0]
        edition = parts[1]
        try:
            with csv_path.open("r", encoding="utf-8", errors="ignore") as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    counts["skipped_csv"] += 1
                    continue
                # Heuristic field detection (Rathbun's columns vary by tool)
                fn = {k.lower(): k for k in reader.fieldnames}
                path_col = (fn.get("path") or fn.get("fullname")
                            or fn.get("filepath") or fn.get("filename"))
                sha_col = (fn.get("sha256") or fn.get("hash") or fn.get("sha-256"))
                signer_col = (fn.get("signer") or fn.get("signature")
                              or fn.get("authenticodesigner"))
                size_col = fn.get("size") or fn.get("length")
                ver_col = (fn.get("fileversion") or fn.get("productversion")
                           or fn.get("version"))
                if not path_col:
                    counts["skipped_csv"] += 1
                    continue
                counts["scanned_csv"] += 1
                for row in reader:
                    path_v = (row.get(path_col) or "").strip()
                    if not path_v:
                        continue
                    sha_v = (row.get(sha_col) or "").strip().lower() if sha_col else None
                    sig_v = (row.get(signer_col) or "").strip() if signer_col else None
                    sz_v = None
                    if size_col:
                        try:
                            sz_v = int(row.get(size_col) or 0)
                        except ValueError:
                            sz_v = None
                    ver_v = (row.get(ver_col) or "").strip() if ver_col else None
                    conn.execute(
                        "INSERT INTO files(path, sha256, build, edition, "
                        "signer, size, version) VALUES (?,?,?,?,?,?,?)",
                        (path_v, sha_v, build, edition, sig_v, sz_v, ver_v),
                    )
                    counts["files"] += 1
        except Exception as e:
            print(f"[ingest] {rel}: error {e}", file=sys.stderr)
            counts["skipped_csv"] += 1
    return counts


def ingest_vanilla_registry(conn: sqlite3.Connection, root: Path) -> dict:
    """Walk VanillaWindowsRegistryHives.

    For v1 we don't decode hive files directly (would need python-registry +
    significant work). Instead we look for any companion CSV/JSON exports
    that ship per-key inventories; many Rathbun repos include those alongside
    the raw hives.
    """
    counts = {"registry": 0, "scanned": 0}
    # Look for any pre-extracted CSV; format depends on what Rathbun ships.
    for csv_path in root.rglob("*.csv"):
        counts["scanned"] += 1
        # Skip very large file-listing CSVs that we already covered above
        if csv_path.stat().st_size > 50 * 1024 * 1024:
            continue
        rel = csv_path.relative_to(root)
        parts = list(rel.parts)
        if len(parts) < 2:
            continue
        build = parts[0]
        edition = parts[1] if len(parts) >= 2 else "unknown"
        try:
            with csv_path.open("r", encoding="utf-8", errors="ignore") as fh:
                reader = csv.DictReader(fh)
                if not reader.fieldnames:
                    continue
                fn = {k.lower(): k for k in reader.fieldnames}
                hive_col = fn.get("hive")
                key_col = fn.get("key") or fn.get("keypath") or fn.get("path")
                val_col = fn.get("valuename") or fn.get("name")
                if not (hive_col and key_col):
                    continue
                for row in reader:
                    conn.execute(
                        "INSERT INTO registry(hive, key_path, value_name, "
                        "value_data_hash, build, edition) VALUES (?,?,?,?,?,?)",
                        ((row.get(hive_col) or "").strip(),
                         (row.get(key_col) or "").strip(),
                         (row.get(val_col) or "").strip() if val_col else None,
                         None, build, edition),
                    )
                    counts["registry"] += 1
        except Exception:
            continue
    return counts


def main() -> int:
    p = argparse.ArgumentParser(description="Build the Rathbun baseline SQLite.")
    p.add_argument("--output", type=Path, default=Path("mcp_baseline/baseline.sqlite"))
    p.add_argument("--cache-dir", type=Path, default=Path("./_rathbun_cache"),
                   help="Where to clone Rathbun's repos. Reused across runs.")
    p.add_argument("--skip-files", action="store_true",
                   help="Skip the file-inventory ingest (registry only).")
    p.add_argument("--skip-registry", action="store_true",
                   help="Skip the registry ingest.")
    args = p.parse_args()

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    file_root = args.cache_dir / "VanillaWindowsReference"
    reg_root  = args.cache_dir / "VanillaWindowsRegistryHives"

    clone_or_skip("https://github.com/AndrewRathbun/VanillaWindowsReference",
                  file_root)
    clone_or_skip("https://github.com/AndrewRathbun/VanillaWindowsRegistryHives",
                  reg_root)

    conn = init_db(args.output)
    summary: dict[str, dict] = {}
    if not args.skip_files:
        print("[ingest] Vanilla Windows Reference (files)…")
        summary["files"] = ingest_vanilla_windows_reference(conn, file_root)
        conn.commit()
    if not args.skip_registry:
        print("[ingest] Vanilla Windows Registry Hives…")
        summary["registry"] = ingest_vanilla_registry(conn, reg_root)
        conn.commit()

    stamp_meta(conn,
               built_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               source_files="github.com/AndrewRathbun/VanillaWindowsReference",
               source_registry="github.com/AndrewRathbun/VanillaWindowsRegistryHives")
    conn.commit()
    conn.close()

    print(f"[ingest] done -> {args.output}")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
