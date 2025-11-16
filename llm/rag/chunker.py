"""
llm/rag/chunker.py
- 로그/문서 문자열을 일정 길이(토큰/문자 기준)로 안전하게 분할(chunks)하는 유틸.
- 단순 문자 기반 chunking을 사용 (토큰화를 원하면 추가 모듈 연동 가능).
"""
from typing import List

def chunk_text(text: str, max_chars: int = 1000, overlap: int = 200) -> List[str]:
    """
    긴 텍스트를 max_chars 길이의 청크로 나눔. 청크 사이에 overlap이 있음.
    Returns list of strings.
    """
    if not text:
        return []

    text = text.strip()
    chunks = []
    start = 0
    length = len(text)

    if max_chars <= 0:
        raise ValueError("max_chars must be > 0")

    while start < length:
        end = start + max_chars
        if end >= length:
            chunks.append(text[start:length])
            break

        # try to break at newline/space for nicer chunks
        cut = text.rfind("\n", start, end)
        if cut <= start:
            cut = text.rfind(" ", start, end)
        if cut <= start:
            cut = end

        chunks.append(text[start:cut].strip())
        start = max(start + max_chars - overlap, cut)

    return [c for c in chunks if c]

def chunk_lines(lines: List[str], max_chars: int = 1000, overlap: int = 200) -> List[str]:
    """
    lines 리스트(예: 로그 라인)를 합쳐서 chunk_text에 위임.
    """
    text = "\n".join(lines)
    return chunk_text(text, max_chars=max_chars, overlap=overlap)
