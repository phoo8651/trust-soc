"""
llm/rag/vector_adapter.py
- 벡터 DB 추상화: FAISS 사용 가능, 없으면 in-memory linear scan fallback
- 간단한 API: build(index_docs: List[str]) and search(query, top_k)
"""
import os
import json
from typing import List, Tuple

# try import faiss & sentence-transformers
_have_faiss = True
try:
    import faiss
except Exception:
    _have_faiss = False

_have_sbert = True
try:
    from sentence_transformers import SentenceTransformer
except Exception:
    _have_sbert = False

class SimpleInMemoryIndex:
    def __init__(self, docs: List[str], model_name: str = "all-MiniLM-L6-v2"):
        if not _have_sbert:
            raise RuntimeError("sentence-transformers not available for in-memory embeddings")
        self.model = SentenceTransformer(model_name)
        self.docs = docs
        self.embeddings = self.model.encode(docs, convert_to_numpy=True)

    def search(self, q: str, top_k: int = 3) -> List[Tuple[int, float]]:
        q_emb = self.model.encode([q], convert_to_numpy=True)[0]
        import numpy as np
        sims = (self.embeddings @ q_emb) / ( (np.linalg.norm(self.embeddings, axis=1) * (np.linalg.norm(q_emb)+1e-12)) )
        idxs = sims.argsort()[::-1][:top_k]
        return [(int(i), float(sims[i])) for i in idxs]

class FaissAdapter:
    def __init__(self, docs: List[str], model_name: str = "all-MiniLM-L6-v2", index_path: str = None):
        if not _have_faiss or not _have_sbert:
            raise RuntimeError("faiss or sentence-transformers missing")
        self.model = SentenceTransformer(model_name)
        import numpy as np
        self.embs = self.model.encode(docs, convert_to_numpy=True)
        dim = self.embs.shape[1]
        self.index = faiss.IndexFlatIP(dim)
        self.index.add(self.embs)
        self.docs = docs
        self.index_path = index_path

    def search(self, q: str, top_k: int = 3):
        import numpy as np
        q_emb = self.model.encode([q], convert_to_numpy=True)
        D, I = self.index.search(q_emb, top_k)
        return [(int(i), float(D[0][j])) for j, i in enumerate(I[0])]

# Factory
class VectorAdapter:
    def __init__(self, docs: List[str], model_name: str = "all-MiniLM-L6-v2", index_path: str = None):
        self.docs = docs
        self.model_name = model_name
        self.index_path = index_path
        if _have_faiss and _have_sbert:
            try:
                self._impl = FaissAdapter(docs, model_name=model_name, index_path=index_path)
            except Exception:
                self._impl = SimpleInMemoryIndex(docs, model_name=model_name)
        elif _have_sbert:
            self._impl = SimpleInMemoryIndex(docs, model_name=model_name)
        else:
            raise RuntimeError("No supported embedding backend found. Install sentence-transformers at minimum.")

    def search(self, q: str, top_k: int = 3):
        return self._impl.search(q, top_k)
