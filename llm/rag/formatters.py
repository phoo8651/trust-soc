#YARA/HEX 인덱싱 포맷 설계
# llm/rag/formatters.py
"""
Formatters to convert YARA/HEX hits into consistent index entries.
"""

import hashlib
from typing import Dict


def _short_hash(value: str, length: int = 8) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:length]


def yara_to_index_entry(rule_id: str, matched_text: str, source: str = "", ts: int = None) -> Dict:
    """
    Create index entry dict for a YARA hit.
    Returns dict with 'id','text','metadata'
    """
    identifier = f"yara:{rule_id}:{_short_hash(matched_text)}"
    metadata = {"type": "yara", "rule_id": rule_id, "source": source}
    if ts is not None:
        metadata["ts"] = ts
    return {"id": identifier, "text": matched_text, "metadata": metadata}


def hex_to_index_entry(hash_str: str, snippet: str, source: str = "", ts: int = None) -> Dict:
    """
    Create index entry dict for a HEX/sha hit.
    """
    identifier = f"hex:{hash_str}:{_short_hash(snippet)}"
    metadata = {"type": "hex", "sha256": hash_str, "source": source}
    if ts is not None:
        metadata["ts"] = ts
    return {"id": identifier, "text": snippet, "metadata": metadata}
