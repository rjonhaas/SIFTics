"""Build the forensic-RAG index from upstream knowledge corpora.

Usage:
    python -m mcp_rag.build_index --output mcp_rag/index/

Source corpora cloned (or expected) under --cache-dir:
    SigmaHQ/sigma
    mitre/cti  (ATT&CK STIX JSON)
    lolbas-project/LOLBAS  (data/yml)
    redcanaryco/atomic-red-team  (atomics/T*/T*.yaml)
    AndrewRathbun reference metadata
    osm STIX bundle (from $SIFTICS_OSM_BUNDLE_PATH, if provided)

The script normalises each into a common record schema:
    {id, source, title, body, attack_techniques, tags, url}

then embeds the `title + body` field with the configured embedder.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

from .embeddings import load_embedder
from .store import VectorStore


def _clone(repo: str, dest: Path) -> None:
    if dest.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[clone] {repo} -> {dest}")
    subprocess.run(["git", "clone", "--depth", "1", repo, str(dest)], check=True)


def normalise_sigma(root: Path) -> list[dict]:
    import yaml
    out: list[dict] = []
    for p in (root / "rules").rglob("*.yml"):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        techniques = []
        for tag in doc.get("tags", []) or []:
            if isinstance(tag, str) and tag.lower().startswith("attack."):
                techniques.append(tag.split(".", 1)[1].upper())
        out.append({
            "id": f"sigma:{doc.get('id', p.stem)}",
            "source": "sigma",
            "title": doc.get("title", p.stem),
            "body": (doc.get("description", "") or "").strip(),
            "attack_techniques": techniques,
            "tags": doc.get("tags", []) or [],
            "url": f"https://github.com/SigmaHQ/sigma/blob/master/{p.relative_to(root)}",
        })
    return out


def normalise_attack(root: Path) -> list[dict]:
    out: list[dict] = []
    for stix_file in (root / "enterprise-attack").glob("*.json"):
        try:
            bundle = json.loads(stix_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        for obj in bundle.get("objects", []):
            if obj.get("type") not in ("attack-pattern", "course-of-action",
                                         "x-mitre-data-source"):
                continue
            tid = None
            for ref in obj.get("external_references", []) or []:
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    break
            out.append({
                "id": f"attack:{obj.get('id')}",
                "source": "attack",
                "title": (obj.get("name") or "")[:200],
                "body": (obj.get("description") or "")[:4000],
                "attack_techniques": [tid] if tid else [],
                "tags": [obj.get("type")],
                "url": f"https://attack.mitre.org/techniques/{tid}" if tid else "",
            })
    return out


def normalise_lolbas(root: Path) -> list[dict]:
    import yaml
    out: list[dict] = []
    yml_dir = root / "yml"
    for p in yml_dir.rglob("*.yml"):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        commands = doc.get("Commands") or []
        body_parts = [doc.get("Description", "")]
        for c in commands:
            if isinstance(c, dict):
                body_parts.append(c.get("Description", ""))
                body_parts.append(c.get("Command", ""))
        out.append({
            "id": f"lolbas:{doc.get('Name', p.stem)}",
            "source": "lolbas",
            "title": doc.get("Name", p.stem),
            "body": "\n".join(s for s in body_parts if s)[:4000],
            "attack_techniques": list({c.get("MitreID")
                                        for c in commands
                                        if isinstance(c, dict) and c.get("MitreID")}),
            "tags": ["lolbas"],
            "url": f"https://lolbas-project.github.io/lolbas/Binaries/{doc.get('Name', p.stem)}/",
        })
    return out


def normalise_atomic(root: Path) -> list[dict]:
    import yaml
    out: list[dict] = []
    for p in (root / "atomics").rglob("T*/T*.yaml"):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        tid = doc.get("attack_technique") or p.parent.name
        for test in doc.get("atomic_tests", []) or []:
            out.append({
                "id": f"atomic:{tid}:{test.get('auto_generated_guid', 'n/a')}",
                "source": "atomic",
                "title": f"{tid} {test.get('name', '')}"[:200],
                "body": (test.get("description", "") or "")[:4000],
                "attack_techniques": [tid],
                "tags": ["atomic"],
                "url": f"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{tid}/",
            })
    return out


def normalise_osm_bundle(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    out: list[dict] = []
    for obj in bundle.get("objects", []) or []:
        if obj.get("type") != "indicator":
            continue
        out.append({
            "id": f"osm:{obj.get('id')}",
            "source": "osm_stix",
            "title": obj.get("name", "")[:200],
            "body": (obj.get("description") or obj.get("pattern", ""))[:4000],
            "attack_techniques": [],
            "tags": obj.get("labels", []) or [],
            "url": obj.get("external_references", [{}])[0].get("url", "") if obj.get("external_references") else "",
        })
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="Build the forensic-RAG index.")
    p.add_argument("--output", type=Path, default=Path("mcp_rag/index/"))
    p.add_argument("--cache-dir", type=Path, default=Path("./_rag_cache"))
    p.add_argument("--osm-bundle", type=Path, default=None,
                   help="Path to an OSM STIX JSON bundle (if you've already pulled it).")
    p.add_argument("--skip-clone", action="store_true",
                   help="Assume cache-dir already contains the source repos.")
    args = p.parse_args()

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    sigma_dir = args.cache_dir / "sigma"
    attack_dir = args.cache_dir / "cti"
    lolbas_dir = args.cache_dir / "LOLBAS"
    atomic_dir = args.cache_dir / "atomic-red-team"

    if not args.skip_clone:
        _clone("https://github.com/SigmaHQ/sigma", sigma_dir)
        _clone("https://github.com/mitre/cti", attack_dir)
        _clone("https://github.com/lolbas-project/LOLBAS", lolbas_dir)
        _clone("https://github.com/redcanaryco/atomic-red-team", atomic_dir)

    records: list[dict] = []
    print("[norm] sigma…")
    records += normalise_sigma(sigma_dir)
    print(f"  -> {len(records)} so far")
    print("[norm] attack…")
    records += normalise_attack(attack_dir)
    print(f"  -> {len(records)} so far")
    print("[norm] lolbas…")
    records += normalise_lolbas(lolbas_dir)
    print(f"  -> {len(records)} so far")
    print("[norm] atomic…")
    records += normalise_atomic(atomic_dir)
    print(f"  -> {len(records)} so far")

    if args.osm_bundle:
        print("[norm] osm…")
        records += normalise_osm_bundle(args.osm_bundle)
        print(f"  -> {len(records)} so far")

    if not records:
        print("[build] no records normalised; aborting", file=sys.stderr)
        return 1

    print(f"[embed] {len(records)} records…")
    embedder = load_embedder()
    texts = [f"{r['title']} | {r['body']}" for r in records]
    vectors = embedder.encode(texts)

    print(f"[store] writing index to {args.output}")
    VectorStore.build(args.output, records, vectors, embedder.name)
    print(f"[store] done. {len(records)} records, dim={vectors.shape[1]}, "
          f"model={embedder.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
