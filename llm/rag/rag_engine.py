# llm/rag/rag_engine.py
"""
RAG 엔진 통합 버전 (기존 기능 유지 + 요약/압축 기능 추가)
- chunking 기반 인덱싱(외부 chunker 재사용)
- 벡터/검색 어댑터는 기존 VectorAdapter를 사용 (이미 분리되어 있음)
- 추가: 간단한 추출적 요약기(scentence scoring) 및 rag_hits 압축(summarize_hits)
"""

import time
from typing import List, Dict, Optional
from collections import defaultdict
import math
import re

from llm.rag.chunker import chunk_text_by_chars, chunk_logs_by_lines
from llm.rag.vector_adapter import VectorAdapter
from llm.embeddings import Embedder

_SENTENCE_SPLIT_RE = re.compile(r'(?<=\.|!|\?|\n)\s+')

class RAGEngine:
    """
    RAGEngine:
    - index_documents(doc_id, text, mode) : 문서/로그 쪼개서 내부 리스트에 저장 + VectorAdapter 구성
    - retrieve(query, top_k, recency_weight) : 기존 검색 결과(인덱스 impl의 search)를 받아 recency 가중치로 정렬
    - summarize_text(text, max_sentences, query): 추출적 요약 (문장 점수 기반)
    - summarize_hits(rag_hits, max_sentences_per_hit, budget_sentences): 여러 RAG hit을 압축하여 프롬프트에 안전하게 넣을 요약 생성
    """

    def __init__(self, model_name="all-MiniLM-L6-v2"):
        self.embedder = Embedder()
        self.docs: List[str] = []
        self.metadata: List[Dict] = []
        self.adapter = None
        self.model_name = model_name

    def index_documents(self, doc_id: str, text: str, mode="text"):
        """
        문서를 받아 chunking 후 내부 docs에 추가하고 VectorAdapter 재생성
        doc_id: 문서 식별자
        text: 원문
        mode: "text" 또는 "log"
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

        # VectorAdapter 재생성(단순 구현)
        self.adapter = VectorAdapter(self.docs, model_name=self.model_name)

    def retrieve(self, query: str, top_k=5, recency_weight=0.2) -> List[Dict]:
        """
        query 기반 검색 결과 반환 (adapter.search 활용 + recency 가중치 적용)
        반환 항목: [{'rank', 'score', 'final_score', 'doc_id', 'text', 'ts'}, ...]
        """
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

    # ----------------------------------------
    # Summarization helpers (extractive)
    # ----------------------------------------
    def _split_sentences(self, text: str) -> List[str]:
        """
        간단한 문장 분할. 너무 짧은 문장 제거.
        """
        sents = [s.strip() for s in _SENTENCE_SPLIT_RE.split(text) if s and len(s.strip()) > 10]
        return sents if sents else [text.strip()]

    def _score_sentence_by_query(self, sentence: str, query_tokens: List[str]) -> float:
        """
        문장 점수 계산 (쿼리 토큰과의 교집합 기반) + 길이 보정
        - query_tokens: 소문자 토큰 리스트
        """
        stoks = re.findall(r"[가-힣a-z0-9]+", sentence.lower())
        if not stoks:
            return 0.0
        overlap = sum(1 for t in stoks if t in query_tokens)
        # 길이 보정: 지나치게 긴 문장에 패널티
        length_penalty = 1.0 / (1 + abs(len(stoks) - 12) / 12)
        return overlap * length_penalty

    def summarize_text(self, text: str, max_sentences: int = 3, query: Optional[str] = None) -> str:
        """
        추출적 요약: 문장을 분할하고, query 기반(있으면) 점수로 정렬해 상위 문장 조합 반환
        - max_sentences: 반환할 문장 개수
        - query: 요약을 쿼리 관점으로 압축하고 싶을 때 사용(예: 검색 쿼리/이벤트 텍스트)
        """
        sents = self._split_sentences(text)
        if not sents:
            return ""

        if query:
            query_tokens = re.findall(r"[가-힣a-z0-9]+", query.lower())
        else:
            query_tokens = []

        scored = []
        for s in sents:
            # 기본 점수: query overlap
            score = self._score_sentence_by_query(s, query_tokens) if query_tokens else (len(s.split()) / 20.0)
            scored.append((score, s))

        # 높은 점수 순으로 정렬 후 선택
        scored.sort(key=lambda x: x[0], reverse=True)
        chosen = [s for _, s in scored[:max_sentences]]

        # 보존 순서를 원문 순서로 맞추기(가독성)
        chosen_sorted = [s for s in sents if s in chosen]
        return " ".join(chosen_sorted)

    def summarize_hits(self, rag_hits: List[Dict], max_sentences_per_hit: int = 2, budget_sentences: int = 6, query: Optional[str] = None):
        """
        여러 RAG hit들을 합쳐 프롬프트에 넣기 적합한 요약 블록을 생성
        - rag_hits: retrieve() 결과 리스트
        - max_sentences_per_hit: 각 hit에서 뽑는 최대 문장 수
        - budget_sentences: 전체 요약에서 허용할 문장 수 합계 (토큰절약 목적)
        - query: 이벤트 텍스트 등, query 기반으로 우선 요약할 때 사용
        반환: [{'doc_id','score','summary'} ...] (요약된 텍스트 포함)
        """
        out = []
        remaining = budget_sentences

        # 우선순위: final_score 내림차순
        hits_sorted = sorted(rag_hits, key=lambda x: x["final_score"], reverse=True)

        for h in hits_sorted:
            if remaining <= 0:
                break
            take = min(max_sentences_per_hit, remaining)
            summary = self.summarize_text(h["text"], max_sentences=take, query=query)
            out.append({
                "doc_id": h["doc_id"],
                "final_score": h["final_score"],
                "summary": summary
            })
            remaining -= len(self._split_sentences(summary))

        return out

    def remove_document(self, doc_id: str):
        """
        문서 제거 스텁(간단 구현)
        - 현재는 docs list에서 doc_id에 해당하는 항목 제거.
        - production: Vector DB/FAISS/Qdrant API 호출로 인덱스에서 제거 필요.
        """
        # meta에서 doc_id가 존재하면 제거(단순)
        new_docs = []
        new_meta = []
        for d, m in zip(self.docs, self.metadata):
            if m.get("doc_id") == doc_id:
                continue
            new_docs.append(d)
            new_meta.append(m)
        self.docs = new_docs
        self.metadata = new_meta

        # re-create adapter if docs remain
        if self.docs:
            self.adapter = VectorAdapter(self.docs, model_name=self.model_name)
        else:
            self.adapter = None
