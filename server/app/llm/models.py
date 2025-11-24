# llm/models.py
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, field_validator


class EvidenceRef(BaseModel):
    """
    output_schema.json 의 evidence_refs 항목과 1:1로 맞춘 모델.
    - type: raw|yara|hex|webhook (enum)
    - ref_id, source, offset, length, sha256, rule_id(optional)
    """
    type: Literal["raw", "yara", "hex", "webhook"]
    ref_id: str
    source: str
    offset: int = Field(ge=0)
    length: int = Field(ge=0)
    sha256: str = Field(min_length=6, max_length=64)
    rule_id: Optional[str] = None


class IncidentAnalysisRequest(BaseModel):
    """
    LLM/엔진 내부에서 사용하는 입력 모델.
    """
    incident_id: str
    event_text: str
    evidences: List[EvidenceRef]


class IncidentOutput(BaseModel):
    """
    LLM 최종 출력 스키마.
    - output_schema.json + 테스트 코드 요구사항에 맞춤
    - incident_id는 외부 응답 스키마에는 없으므로 여기서도 제외
    """
    summary: str
    attack_mapping: List[str] = Field(..., min_items=1)
    recommended_actions: List[str] = Field(..., min_items=1)
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence_refs: List[EvidenceRef] = Field(..., min_items=1)
    hil_required: bool
    status: str = "pending_approval"
    
    @field_validator("summary")
    def not_empty_summary(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("summary must not be empty")
        return v

    @field_validator("attack_mapping", "recommended_actions")
    def no_empty_strings(cls, v: List[str]) -> List[str]:
        if any((not s) or (not s.strip()) for s in v):
            raise ValueError("array items must be non-empty strings")
        return v
