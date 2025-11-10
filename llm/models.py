from pydantic import BaseModel
from typing import List, Optional

class EvidenceRef(BaseModel):
    type: str
    ref_id: str
    source: Optional[str] = None
    offset: Optional[int] = None
    length: Optional[int] = None
    sha256: Optional[str] = None
    snippet: Optional[str] = None

class IncidentAnalysisRequest(BaseModel):
    incident_id: str
    event_text: str
    evidences: List[EvidenceRef]

class EvidenceOutput(BaseModel):
    type: str
    ref_id: str
    relevance_score: Optional[float] = None
    notes: Optional[str] = None

class IncidentOutput(BaseModel):
    incident_id: str
    summary: str
    severity: Optional[str] = None
    attack_mapping: Optional[List[str]] = None
    recommended_actions: Optional[List[str]] = None
    evidences: Optional[List[EvidenceRef]] = None
    confidence: float = 0.0
    hil_required: bool = True
