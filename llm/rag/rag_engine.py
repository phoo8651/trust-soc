# llm/rag/rag_engine.py -> RAG 엔진(증거 수집 및 Top-K 선정)
from typing import List, Dict, Any
from .vector_adapter import VectorAdapter, InMemoryAdapter
from .chunker import chunk_logs_by_lines
import time

class RAGEngine:
    def __init__(self, adapter: VectorAdapter):
        self.adapter = adapter

    def index_logs(self, doc_id: str, lines: List[str], embed_fn):
        chunks = chunk_logs_by_lines(lines)
        docs_to_add = []
        now_ts = int(time.time())
        for c in chunks:
            vec = embed_fn(c["text"])
            docs_to_add.append({
                "id": f"{doc_id}:{c['id']}",
                "embedding": vec,
                "metadata": {"doc_id": doc_id, "ts": now_ts, "start": c["start"], "end": c["end"]},
                "text": c["text"]
            })
        self.adapter.add(docs_to_add)

    def retrieve(self, query: str, embed_fn, k: int = 5, recency_weight: float = 0.2):
        q_vec = embed_fn(query)
        hits = self.adapter.search(q_vec, k=k*3)  # overfetch
        # apply recency weighting
        scored = []
        now = int(time.time())
        for h in hits:
            base = float(h["score"])
            ts = h.get("metadata", {}).get("ts", now)
            age = max(1, now - ts)
            recency_bonus = recency_weight * (1.0 / (age/3600 + 1))
            final = base + recency_bonus
            scored.append({**h, "final_score": final})
        scored.sort(key=lambda x: x["final_score"], reverse=True)
        return scored[:k]
