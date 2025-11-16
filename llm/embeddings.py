# llm/embeddings.py
# - def fake_embed(text) -> list[float]  # dev/test 전용
# - class Embedder: .embed(text)  # 실제 API adapter 교체 지점
#
# 목적: RAGEngine에 주입되는 embed_fn을 분리해 테스트/운영 전환 용이

"""
Embedding abstraction. Provides:
- fake_embed(text) -> deterministic pseudo-embedding (list[float]) for dev/test
- Embedder class stub for real backends
"""

from typing import List
import hashlib
import math

def _text_to_seed_vector(text: str, dim: int = 128) -> List[float]:
    """
    Deterministic pseudo-embedding: hash text and expand to floats.
    Not semantic, but OK for dev/testing similarity.
    """
    if not text:
        return [0.0] * dim
    h = hashlib.sha256(text.encode("utf-8")).digest()
    # expand h into dim floats
    vec = []
    for i in range(dim):
        idx = i % len(h)
        vec.append(((h[idx] & 0xFF) / 255.0) - 0.5)
    # normalize
    norm = math.sqrt(sum(x*x for x in vec)) or 1.0
    return [x / norm for x in vec]


def fake_embed(text: str) -> List[float]:
    """Public fake embed function."""
    return _text_to_seed_vector(text, dim=128)


class Embedder:
    """
    Embedder abstraction - implement .embed(text) to call real embed service.
    Example: replace with OpenAI / local onnx embeddings later.
    """
    def __init__(self):
        pass

    def embed(self, text: str) -> List[float]:
        # default to fake
        return fake_embed(text)
