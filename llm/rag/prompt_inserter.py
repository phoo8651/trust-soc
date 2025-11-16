"""
llm/rag/prompt_inserter.py
- LLM 프롬프트에 RAG 결과(문서 요약/상위-k)를 안전하게 삽입하는 로직.
- 프롬프트 길이, 마스킹(간단) 고려.
"""
from typing import List

def safe_insert_rag_context(base_prompt: str, rag_snippets: List[str], max_chars: int = 3000) -> str:
    """
    base_prompt: 기존 프롬프트 (with placeholders like {rag_context} or event_text/evidence)
    rag_snippets: 검색된 관련 문서 리스트(순서: top1..topk)
    max_chars: RAG block의 최대 문자 길이 (초과 시 자름)

    Returns prompt with a 'RAG Context:' block appended (or injected if placeholder exists).
    """
    if not rag_snippets:
        return base_prompt

    block = "\n\nRAG Context (most relevant docs):\n"
    for i, s in enumerate(rag_snippets, 1):
        block += f"--- doc {i} ---\n"
        # 간단하게 줄바꿈/특수문자 정리
        cleaned = s.replace("\r", " ").strip()
        block += cleaned + "\n\n"

    if len(block) > max_chars:
        block = block[:max_chars] + "\n...[truncated]"

    if "{rag_context}" in base_prompt:
        return base_prompt.replace("{rag_context}", block)
    # otherwise append
    return base_prompt + "\n\n" + block
