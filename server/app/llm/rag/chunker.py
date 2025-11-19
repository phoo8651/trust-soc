# llm/rag/chunker.py
"""
- 긴 텍스트/로그를 일정 길이로 chunking 하는 유틸.
- RAGEngine 에서 사용하는 chunk_text_by_chars / chunk_logs_by_lines alias 포함.
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


# ---- RAGEngine 호환 alias ----

def chunk_text_by_chars(text: str, max_chars: int = 1000, overlap: int = 200) -> List[str]:
    """
    RAGEngine에서 사용하는 이름. 내부적으로 chunk_text를 호출.
    """
    return chunk_text(text, max_chars=max_chars, overlap=overlap)


def chunk_logs_by_lines(text: str, max_lines: int = 20) -> List[str]:
    """
    RAGEngine에서 사용하는 이름. 로그라인 기반 chunking 래퍼.
    - max_lines 기준으로 자르고, 각 블록은 다시 chunk_text로 처리할 수도 있음.
    """
    if not text:
        return []

    lines = text.splitlines()
    blocks = []
    for i in range(0, len(lines), max_lines):
        block = "\n".join(lines[i:i + max_lines])
        blocks.append(block.strip())

    # 단순 버전: blocks 그대로 반환
    return [b for b in blocks if b]
