"""SIFTics forensic RAG MCP — embedded semantic search over forensic knowledge.

22 000-record corpus: Sigma + ATT&CK + LOLBAS + Atomic Red Team + Rathbun
metadata + OSM STIX descriptions.

Embedded vector store (numpy / sqlite-vec) — no OpenSearch dependency.
Pre-built index ships as a GitHub Release asset; cloners fetch it once.

Embedding model: sentence-transformers/all-MiniLM-L6-v2 (~80 MB, 384-dim).
Optional: bge-small-en-v1.5 for slightly higher precision.

Two-tier ranking:
    1. vector top-K   (semantic similarity over embeddings)
    2. BM25 / FTS5 rerank  (boosts literal-token matches like T1078, CVE-2024-…)
"""
__version__ = "0.1.0"
