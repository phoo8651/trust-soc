# llm/rag/rag_engine.py
"""
RAG 엔진 통합 버전
- chunking
- embedding
- 벡터 인덱스 생성
- 검색 + recency score
"""

import time
from typing import List, Dict

from llm.rag.chunker import chunk_text_by_chars, chunk_logs_by_lines
from llm.rag.vector_adapter import VectorAdapter
from llm.embeddings import Embedder


class RAGEngine:
    def __init__(self, model_name="all-MiniLM-L6-v2"):
        self.embedder = Embedder()
        self.docs: List[str] = []
        self.metadata: List[Dict] = []
        self.adapter = None
        self.model_name = model_name

    def index_documents(self, doc_id: str, text: str, mode="text"):
        """
        doc_id: 문서 또는 로그 ID
        text: 원본 문서
        mode: "text" | "log"
        """
        ts = int(time.time())

        if mode == "text":
            chunks = chunk_text_by_chars(text, max_chars=800)
        else:
            chunks = chunk_logs_by_lines(text, max_lines=20)

        for ch in chunks:
            self.docs.append(ch)
            self.metadata.append({
                "doc_id": doc_id,
                "ts": ts,
                "text": ch,
            })

        # Build vector index
        self.adapter = VectorAdapter(self.docs, model_name=self.model_name)

    def retrieve(self, query: str, top_k=5, recency_weight=0.2) -> List[Dict]:
        if not self.adapter:
            return []

        results = self.adapter.search(query, top_k=top_k * 3)
        now = int(time.time())
        scored = []

        for rank, (idx, score) in enumerate(results):
            meta = self.metadata[idx]
            age = max(1, now - meta["ts"])
            recency_bonus = recency_weight * (1.0 / (age / 3600 + 1))
            final_score = score + recency_bonus

            scored.append({
                "rank": rank,
                "score": score,
                "final_score": final_score,
                "doc_id": meta["doc_id"],
                "text": meta["text"],
                "ts": meta["ts"],
            })

        scored.sort(key=lambda x: x["final_score"], reverse=True)
        return scored[:top_k]
