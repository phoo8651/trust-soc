"""
llm/rag/vector_adapter.py
- SBERT/FAISS 없이도 동작하는 가벼운 벡터 검색 엔진
- SHA256 기반 pseudo-embedding 생성
- 기존 VectorAdapter 인터페이스(search) 유지
"""
import numpy as np
import hashlib
from typing import List, Tuple


class SimpleHashEmbedder:
    """텍스트를 SHA256 기반 고정 벡터로 변환하는 경량 임베더"""

    @staticmethod
    def embed(text: str) -> np.ndarray:
        h = hashlib.sha256(text.encode()).digest()  # 32 bytes
        vec = np.frombuffer(h, dtype=np.uint8).astype(np.float32)
        return vec / (np.linalg.norm(vec) + 1e-9)


class VectorAdapter:
    """
    SBERT/FAISS 없이 사용 가능한 In-memory Vector Search Adapter.
    RAGEngine에서 기대하는 search() API는 동일하게 유지.
    """

    def __init__(self, docs: List[str], model_name: str = None, index_path: str = None):
        """
        docs: chunked 문서 목록 (List[str])
        """
        self.docs = docs
        self.embeds = []
        self.embedder = SimpleHashEmbedder()

        # 미리 모든 doc embedding 생성
        for txt in docs:
            emb = self.embedder.embed(txt)
            self.embeds.append(emb)

        self.embeds = np.stack(self.embeds, axis=0)

    def search(self, q: str, top_k: int = 3) -> List[Tuple[int, float]]:
        """
        q: query string
        return: [(doc_index, similarity_score), ...]
        """
        if not self.docs:
            return []

        q_emb = self.embedder.embed(q)

        sims = (self.embeds @ q_emb).astype(float)
        idxs = sims.argsort()[::-1][:top_k]

        return [(int(i), float(sims[i])) for i in idxs]
