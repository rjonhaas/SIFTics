"""mcp_rag — Custom MCP for semantic search over ~22K forensic-knowledge records.

Records (built by `mcp_rag.build_index`):
    Sigma rules · MITRE ATT&CK · LOLBAS · Atomic Red Team
    · OSM STIX descriptions · reference metadata for context

This server retrieves forensic knowledge for explanation/classification. It
does not prove case facts. Deterministic known-good comparison is handled by
`mcp_baseline`.

Query interface (a single MCP tool):
    forensic_rag_search(query, top_k=10, source_filter=[…])

Cosine search → optional literal-token BM25 rerank.

Environment:
    SIFTICS_RAG_INDEX_DIR     where the prebuilt index lives
                              (default: $REPO_ROOT/mcp_rag/index/)
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .embeddings import load_embedder
from .store import VectorStore

try:
    from siftics.audit import append_event as _audit
except ImportError:
    def _audit(*a, **kw): pass  # type: ignore[misc]

mcp = FastMCP("siftics-forensic-rag")

_INDEX: VectorStore | None = None
_EMBEDDER = None


def _index_dir() -> Path:
    if env := os.environ.get("SIFTICS_RAG_INDEX_DIR"):
        return Path(env)
    return Path(__file__).parent / "index"


def _store() -> VectorStore:
    global _INDEX
    if _INDEX is None:
        d = _index_dir()
        if not (d / "records.jsonl").exists():
            raise RuntimeError(
                f"forensic RAG index not found at {d}. Run "
                f"`python -m mcp_rag.build_index` or "
                f"`./scripts/download_rag_index.sh`."
            )
        _INDEX = VectorStore.load(d)
    return _INDEX


def _embed():
    global _EMBEDDER
    if _EMBEDDER is None:
        _EMBEDDER = load_embedder()
    return _EMBEDDER


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def forensic_rag_search(query: str, top_k: int = 10,
                        source_filter: list[str] | None = None,
                        rerank: bool = True) -> dict:
    """Semantic + optional BM25 rerank over the forensic-knowledge corpus.

    Args:
        query: natural-language question or observation snippet
               (e.g. "process reading lsass.exe memory without debug right").
        top_k: number of results to return (default 10).
        source_filter: optional list restricting results to one or more
                       sources — `sigma`, `attack`, `lolbas`, `atomic`,
                       `rathbun`, `osm_stix`. None means all sources.
        rerank: if True, boost results that contain literal tokens from the
                query (helpful for queries with specific identifiers like
                "T1078" or "CVE-2024-3400").

    Returns {'query': str, 'count': int, 'results': [...]}.
    """
    s = _store()
    e = _embed()
    qv = e.encode([query])[0]
    raw = s.search(qv, top_k=top_k, source_filter=source_filter)
    if rerank:
        raw = s.bm25_rerank(query, raw)
    try:
        _audit("rag_lookup", {
            "source_type": "ai_enrichment",
            "query": query[:200],
            "top_k": top_k,
            "source_filter": source_filter,
            "result_count": len(raw),
            "record_ids": [r.get("record_id") for r in raw[:5]],
            "embedder": e.name,
        }, actor="mcp_rag")
    except RuntimeError:
        pass
    return {"query": query, "count": len(raw), "results": raw,
            "rerank": rerank, "embedder": e.name}


@mcp.tool()
def rag_meta() -> dict:
    """Return metadata about the loaded RAG index."""
    try:
        return _store().meta
    except RuntimeError as e:
        return {"loaded": False, "error": str(e)}


@mcp.tool()
def rag_sources_available() -> list[str]:
    """List the source identifiers present in the loaded index."""
    s = _store()
    return sorted({r.get("source", "unknown") for r in s.records})


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="SIFTics forensic-RAG MCP server.")
    parser.add_argument("--transport", choices=("stdio", "sse"), default="stdio")
    parser.add_argument("--port", type=int, default=9104)
    args = parser.parse_args()
    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse", port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
