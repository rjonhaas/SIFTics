"""Vector store with optional BM25 rerank.

Storage layout:
    <index_dir>/
        records.jsonl        one record per line  {id, source, title, body, ...}
        embeddings.npy       float32 [N, D]
        meta.json            {dim, model, count, built_at}

Brute-force cosine over numpy is fast enough for <100K records on CPU.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np


def _normalise(v: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(v, axis=-1, keepdims=True)
    norms = np.where(norms == 0, 1.0, norms)
    return v / norms


@dataclass
class VectorStore:
    records: list[dict]
    vectors: np.ndarray            # (N, D), L2-normalised
    meta: dict

    @classmethod
    def load(cls, index_dir: Path) -> "VectorStore":
        records = [json.loads(line) for line in
                   (index_dir / "records.jsonl").read_text(encoding="utf-8").splitlines()
                   if line.strip()]
        vectors = np.load(index_dir / "embeddings.npy")
        if vectors.dtype != np.float32:
            vectors = vectors.astype(np.float32)
        meta = json.loads((index_dir / "meta.json").read_text(encoding="utf-8"))
        return cls(records=records, vectors=_normalise(vectors), meta=meta)

    @classmethod
    def build(cls, index_dir: Path, records: list[dict],
              vectors: np.ndarray, model_name: str) -> "VectorStore":
        index_dir.mkdir(parents=True, exist_ok=True)
        with (index_dir / "records.jsonl").open("w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n")
        v = vectors.astype(np.float32)
        np.save(index_dir / "embeddings.npy", v)
        meta = {
            "dim": int(v.shape[1]),
            "count": int(v.shape[0]),
            "model": model_name,
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        (index_dir / "meta.json").write_text(json.dumps(meta, indent=2,
                                                         sort_keys=True),
                                              encoding="utf-8")
        return cls(records=records, vectors=_normalise(v), meta=meta)

    def search(self, query_vec: np.ndarray, top_k: int = 10,
               source_filter: list[str] | None = None) -> list[dict]:
        if self.vectors.size == 0:
            return []
        q = _normalise(query_vec.reshape(1, -1)).astype(np.float32)
        scores = (self.vectors @ q.T).ravel()          # cosine, all positive after normalise

        # Optional source filter applied before top-k
        if source_filter:
            mask = np.array([(r.get("source") in source_filter)
                             for r in self.records], dtype=bool)
            scores = np.where(mask, scores, -1.0)

        if top_k >= len(scores):
            order = np.argsort(-scores)
        else:
            # argpartition gives unsorted top-k; then sort just those
            part = np.argpartition(-scores, top_k - 1)[:top_k]
            order = part[np.argsort(-scores[part])]

        out: list[dict] = []
        for idx in order[:top_k]:
            r = dict(self.records[idx])
            r["_score"] = float(scores[idx])
            r["_rank"] = len(out) + 1
            out.append(r)
        return out

    def bm25_rerank(self, query: str, candidates: list[dict]) -> list[dict]:
        """Token-overlap rerank over candidates' title+body. Boosts literal hits.

        Cheap heuristic — not a full BM25 implementation. Good enough for the
        typical IR query that contains specific identifiers like T1078, CVE-2024-…,
        lsass.exe, etc.
        """
        q_tokens = {t.lower() for t in query.split() if len(t) >= 2}
        if not q_tokens:
            return candidates
        for c in candidates:
            text = (c.get("title", "") + " " + c.get("body", "")).lower()
            hits = sum(1 for t in q_tokens if t in text)
            # combine vector score and literal-hit count
            c["_rerank_score"] = c.get("_score", 0.0) + 0.05 * hits
            c["_literal_hits"] = hits
        candidates.sort(key=lambda c: -c.get("_rerank_score", 0.0))
        for i, c in enumerate(candidates):
            c["_rank"] = i + 1
        return candidates
