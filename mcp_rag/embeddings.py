"""Embedding backends.

Default: sentence-transformers / all-MiniLM-L6-v2 (384-dim, ~80 MB, CPU-fast).
Fallback (CI / minimal install): a deterministic hash-bag toy embedding so the
test suite runs without downloading a model. Real installs swap this out.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Iterable

import numpy as np

DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
TOY_DIM = 384


class Embedder:
    name: str

    def encode(self, texts: list[str]) -> np.ndarray: ...


class SentenceTransformersEmbedder(Embedder):
    def __init__(self, model_name: str = DEFAULT_MODEL) -> None:
        from sentence_transformers import SentenceTransformer  # type: ignore
        self._model = SentenceTransformer(model_name,
                                           device="cpu",
                                           cache_folder=os.environ.get(
                                               "SIFTICS_ST_CACHE",
                                               os.path.expanduser("~/.cache/siftics/st")))
        self.name = model_name

    def encode(self, texts: list[str]) -> np.ndarray:
        vecs = self._model.encode(texts, normalize_embeddings=True,
                                   show_progress_bar=False,
                                   batch_size=32)
        return np.asarray(vecs, dtype=np.float32)


class HashBagEmbedder(Embedder):
    """Deterministic toy embedding — for tests and minimal installs."""
    name = "siftics-hashbag-v1"

    def __init__(self, dim: int = TOY_DIM) -> None:
        self.dim = dim

    def encode(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, t in enumerate(texts):
            tokens = re.findall(r"\w+", t.lower())
            for tok in tokens:
                h = int.from_bytes(hashlib.sha1(tok.encode()).digest()[:4], "big")
                out[i, h % self.dim] += 1.0
        # L2-normalise
        norms = np.linalg.norm(out, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)
        return out / norms


def load_embedder(prefer: str = "sentence-transformers") -> Embedder:
    """Return the best available embedder.

    'sentence-transformers' is the production default; we fall back to the
    deterministic hash-bag if the library isn't installed (so tests run).
    """
    if prefer == "sentence-transformers":
        try:
            return SentenceTransformersEmbedder()
        except Exception:
            return HashBagEmbedder()
    if prefer == "hashbag":
        return HashBagEmbedder()
    raise ValueError(f"unknown embedder: {prefer}")
