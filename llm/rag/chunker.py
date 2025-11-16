# llm/rag/chunker.py
"""
Chunking utilities for logs/texts.

Functions:
- chunk_text_by_chars(text, max_chars=800, overlap=200): yields chunks
- chunk_logs_by_time(log_records, window_seconds): optional (log_records: list of dict with 'ts' and 'text')
"""

from typing import List, Iterable, Dict


def chunk_text_by_chars(text: str, max_chars: int = 800, overlap: int = 200) -> List[str]:
    """Split long text into overlapping chunks by character counts."""
    if max_chars <= 0:
        return [text]
    chunks = []
    start = 0
    L = len(text)
    while start < L:
        end = min(start + max_chars, L)
        chunks.append(text[start:end])
        if end == L:
            break
        start = max(0, end - overlap)
    return chunks


def chunk_logs_by_lines(lines: List[str], max_chars: int = 800, overlap: int = 200) -> List[str]:
    """
    Chunk a list of log lines into text chunks: join lines until reach max_chars.
    Keeps overlap by number of characters.
    """
    buf = ""
    chunks = []
    for line in lines:
        candidate = buf + ("\n" if buf else "") + line
        if len(candidate) <= max_chars:
            buf = candidate
        else:
            if buf:
                chunks.extend(chunk_text_by_chars(buf, max_chars=max_chars, overlap=overlap))
            buf = line
    if buf:
        chunks.extend(chunk_text_by_chars(buf, max_chars=max_chars, overlap=overlap))
    return chunks


def chunk_by_time(records: List[Dict], window_seconds: int = 300) -> List[List[Dict]]:
    """
    Group records by time windows (assumes 'ts' in seconds or epoch).
    Returns list of buckets (each a list of records).
    """
    if not records:
        return []
    sorted_recs = sorted(records, key=lambda r: r.get("ts", 0))
    buckets = []
    cur_bucket = []
    window_start = sorted_recs[0].get("ts", 0)
    for r in sorted_recs:
        ts = r.get("ts", 0)
        if ts - window_start <= window_seconds:
            cur_bucket.append(r)
        else:
            buckets.append(cur_bucket)
            cur_bucket = [r]
            window_start = ts
    if cur_bucket:
        buckets.append(cur_bucket)
    return buckets
