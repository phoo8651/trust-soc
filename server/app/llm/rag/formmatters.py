"""
llm/rag/formatters.py
- 다양한 증거(evidence) 타입을 인덱스에 들어갈 문자열 엔트리로 포맷팅
- YARA/HEX/RAW 등 특화 필드 포맷 처리
"""
from typing import Dict

def format_raw_evidence(ev: Dict) -> str:
    """raw log -> readable entry"""
    snippet = ev.get("snippet") or ev.get("data") or ""
    src = ev.get("source", "unknown")
    ref = ev.get("ref_id", "unknown")
    return f"[RAW] ref_id={ref} source={src}\n{snippet}"

def format_yara_evidence(ev: Dict) -> str:
    """yara -> readable entry"""
    rule = ev.get("rule_name", ev.get("rule_id", "yara_rule"))
    src = ev.get("source", "unknown")
    matched = ev.get("matched_strings", [])
    matched_s = ", ".join(matched) if isinstance(matched, (list,tuple)) else str(matched)
    return f"[YARA] rule={rule} source={src}\nmatched: {matched_s}"

def format_hex_evidence(ev: Dict) -> str:
    """hex/dump -> readable entry"""
    return f"[HEX] ref_id={ev.get('ref_id','hex')}\n{ev.get('data','<hex data>')[:1000]}"

def format_evidence_to_doc(ev: Dict) -> str:
    """generic formatter router"""
    t = ev.get("type","raw")
    if t == "raw":
        return format_raw_evidence(ev)
    if t == "yara":
        return format_yara_evidence(ev)
    if t == "hex":
        return format_hex_evidence(ev)
    # fallback
    return f"[EVIDENCE] type={t} ref={ev.get('ref_id','?')}\n{ev.get('snippet') or ev.get('data','')}"
