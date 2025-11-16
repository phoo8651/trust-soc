# llm/rag/vector_adapter.py
"""
Vector adapter abstraction + simple InMemory adapter for development/testing.

API:
- adapter.add(docs: List[dict]) where doc = {"id","embedding","metadata","text"}
- adapter.search(query_embedding, k) -> list of {"id","score","metadata","text"}
"""

from typing import List, Dict, Any
import math
import heapq


def _cosine(a, b):
    # safe cosine similarity
    da = math.sqrt(sum(x * x for x in a)) or 1e-12
    db = math.sqrt(sum(x * x for x in b)) or 1e-12
    return sum(x * y for x, y in zip(a, b)) / (da * db)


class VectorAdapter:
    """Base/Interface for vector DB adapters."""
    def add(self, docs: List[Dict[str, Any]]):
        raise NotImplementedError()

    def search(self, query_embedding: List[float], k: int = 5) -> List[Dict[str, Any]]:
        raise NotImplementedError()


class InMemoryAdapter(VectorAdapter):
    """
    Simple in-memory adapter. Not persistent; intended for tests/dev.
    Stores entries as dicts with fields: id, embedding, metadata, text
    """
    def __init__(self):
        self._store = []

    def add(self, docs: List[Dict[str, Any]]):
        for d in docs:
            if "id" not in d or "embedding" not in d:
                raise ValueError("doc must include 'id' and 'embedding'")
            self._store.append(d)

    def search(self, query_embedding: List[float], k: int = 5) -> List[Dict[str, Any]]:
        if not self._store:
            return []
        heap = []
        for doc in self._store:
            score = _cosine(query_embedding, doc["embedding"])
            # keep max-heap via negative
            if len(heap) < k:
                heapq.heappush(heap, (score, doc))
            else:
                if score > heap[0][0]:
                    heapq.heapreplace(heap, (score, doc))
        results = sorted(heap, key=lambda x: x[0], reverse=True)
        return [{"id": doc["id"], "score": float(score), "metadata": doc.get("metadata", {}), "text": doc.get("text", "")} for score, doc in results]
