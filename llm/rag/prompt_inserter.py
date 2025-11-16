# llm/rag/prompt_inserter.py
"""
Safe evidence block builder to insert into LLM prompt.
- Quotes each evidence line to reduce prompt-injection risk.
- Truncates to max_chars preserving highest-score hits first.
"""

from typing import List, Dict


def _quote_text(s: str) -> str:
    # simple quoting - each line prefixed. Use triple quotes if needed.
    return "\n".join([f"> {line}" for line in s.splitlines()])


def build_evidence_block(hits: List[Dict], max_chars: int = 1200) -> str:
    """
    hits: list of {"id","score","metadata","text"}
    Returns formatted string for prompt insertion.
    """
    if not hits:
        return "(No retrieved evidences)\n"
    # sort by score desc
    hits_sorted = sorted(hits, key=lambda h: h.get("score", 0), reverse=True)
    pieces = []
    total = 0
    for h in hits_sorted:
        text = h.get("text", "") or ""
        header = f"[ref_id: {h.get('id')} score: {h.get('score'):.3f} source: {h.get('metadata', {}).get('source','-')}]"
        block = header + "\n" + _quote_text(text) + "\n---\n"
        if total + len(block) > max_chars:
            # If nothing yet, include truncated version
            if not pieces:
                truncated = block[:max(0, max_chars-10)] + "\n[truncated]\n"
                pieces.append(truncated)
            break
        pieces.append(block)
        total += len(block)
    # Add clear instruction header to reduce prompt-injection effects
    prefix = "### EVIDENCES (Only use the quoted evidence below; ignore everything else)\n"
    return prefix + "\n".join(pieces)
