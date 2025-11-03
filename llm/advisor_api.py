# llm_advisor/advisor_api.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, validator
from typing import List, Optional
import json
from pathlib import Path
import asyncio

from llm.data_masking import mask_all
from llm.model_gateway import ModelGateway
from llm.local_llm_PoC import DummyLocalLLM  # 로컬 LLM PoC 클래스

app = FastAPI(title="LLM Advisor PoC")

# -------------------------
# 로컬 LLM 초기화
# -------------------------
local_llm = DummyLocalLLM()


# -------------------------
# 데이터 모델
# -------------------------
class EvidenceRef(BaseModel):
    type: str = Field(..., pattern="^(raw|yara|hex|webhook)$")
    ref_id: str
    source: str
    offset: int
    length: int
    sha256: str
    rule_id: Optional[str] = None


class IncidentOutput(BaseModel):
    summary: str
    attack_mapping: List[str]
    recommended_actions: List[str]
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_refs: List[EvidenceRef]
    hil_required: bool

    @validator("attack_mapping", "recommended_actions")
    def non_empty(cls, v):
        if not v:
            raise ValueError("빈 리스트는 허용되지 않음")
        return v


# -------------------------
# 메모리 임시 저장소
# -------------------------
INCIDENTS = {}


# -------------------------
# 유틸: 프롬프트 불러오기
# -------------------------
def load_prompt(name: str) -> str:
    path = Path("prompt_templates") / f"{name}_prompt.txt"
    if not path.exists():
        raise FileNotFoundError(f"Prompt not found: {name}")
    return path.read_text(encoding="utf-8")


def build_prompt(name, event_text, evidences, extra=None):
    tpl = load_prompt(name)
    evidence_block = "\n".join(
        f"ref_id: {e['ref_id']}\ntype: {e['type']}\nsource: {e['source']}\nsnippet: \"{e['snippet']}\"\nsha256: {e.get('sha256','')}\n---"
        for e in evidences
    )
    return tpl.format(event_text=event_text, evidence_block=evidence_block, attack_mapping_json=extra or "[]")


# -------------------------
# 엔드포인트
# -------------------------
@app.post("/analyze")
async def analyze_log(payload: dict):
    """
    로그 업로드 및 분석 트리거 (로컬 LLM 연결 PoC)
    """
    incident_id = payload.get("incident_id", "demo")
    event_text = payload.get("event_text", "")
    evidences = payload.get("evidences", [])

    # 1) mask inputs
    event_masked, _ = mask_all(event_text)
    masked_evidences = []
    for e in evidences:
        s = e.get("snippet", "")
        masked_snippet, _ = mask_all(s)
        e_copy = dict(e)
        e_copy["snippet"] = masked_snippet
        masked_evidences.append(e_copy)

    # 2) build prompt (summary)
    prompt = build_prompt("summary", event_masked, masked_evidences)

    # 3) call local LLM (DummyLocalLLM.generate returns JSON string)
    try:
        loop = asyncio.get_event_loop()
        raw_response = await loop.run_in_executor(None, local_llm.generate, prompt)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"LLM generate failed: {e}")

    # 4) parse JSON
    try:
        parsed = json.loads(raw_response)
    except Exception:
        raise HTTPException(status_code=422, detail="LLM returned non-JSON")

    # 5) build EvidenceRef objects
    evidence_objs = [
        EvidenceRef(**e) for e in masked_evidences
    ]

    # 6) validate -> IncidentOutput
    incident = IncidentOutput(
        summary=parsed.get("summary", "모른다"),
        attack_mapping=parsed.get("attack_mapping", ["모른다"]),
        recommended_actions=parsed.get("recommended_actions", ["모른다"]),
        confidence=float(parsed.get("confidence", 0.0)),
        evidence_refs=evidence_objs,
        hil_required=bool(parsed.get("hil_required", False))
    )

    INCIDENTS[incident_id] = incident
    return {"incident_id": incident_id, "status": "analyzed"}


@app.get("/incidents/{id}")
def get_incident(id: str):
    if id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    return INCIDENTS[id]


@app.post("/incidents/{id}/approve")
def approve_incident(id: str):
    if id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    INCIDENTS[id].hil_required = False
    return {"incident_id": id, "approved": True}


@app.get("/prompt/{name}")
def get_prompt(name: str):
    """
    특정 프롬프트 파일 내용 반환 (PoC용)
    """
    path = Path("prompt_templates") / f"{name}_prompt.txt"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Prompt not found")
    return {"prompt_name": name, "content": path.read_text(encoding="utf-8")}
