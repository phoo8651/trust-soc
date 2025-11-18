from datetime import datetime
from typing import Any, Dict, List, Optional, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator


class EvidenceRef(BaseModel):
    type: Literal["raw", "yara", "hex", "webhook"]
    ref_id: str
    source: str
    sha256: str
    offset: int = Field(ge=0)
    length: int = Field(ge=1)
    rule_id: Optional[str] = None

    @field_validator("ref_id", "source", "sha256")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("must not be empty")
        return v

    @model_validator(mode="after")
    def cross_field_checks(self):
        if self.type == "raw":
            if self.offset is None or self.length is None or not self.sha256:
                raise ValueError("raw evidence requires offset/length and sha256")
        return self


def validate_evidence_refs(refs: List[Dict[str, Any]]) -> List[EvidenceRef]:
    validated: List[EvidenceRef] = []
    for ref in refs:
        try:
            validated.append(EvidenceRef(**ref))
        except ValidationError as exc:
            raise ValueError(f"invalid evidence reference: {exc}") from exc
    return validated


class RegisterRequest(BaseModel):
    client_id: str
    host: str
    agent_version: str
    secret_proof: str


class RegisterResponse(BaseModel):
    agent_id: str
    access_token: str
    refresh_token: str
    expires_in: int


class RefreshRequest(BaseModel):
    agent_id: str
    refresh_token: str


class RefreshResponse(BaseModel):
    access_token: str
    expires_in: int


class IngestMeta(BaseModel):
    client_id: str
    host: str


class RecordItem(BaseModel):
    ts: datetime
    source_type: str
    raw_line: str
    tags: Optional[List[str]] = None


class IngestRequest(BaseModel):
    meta: IngestMeta
    agent_id: str
    records: List[RecordItem]


class IngestResponse(BaseModel):
    status: str
    accepted: int


class JobPullJob(BaseModel):
    job_id: str
    type: str
    args: Dict[str, Any]
    approvals_required: int
    approvals_granted: int
    issued_at: Optional[datetime]
    expires_at: Optional[datetime]
    idempotency_key: str
    rate_limit_per_min: Optional[int] = None
    dry_run: bool = False
    signature: Optional[str] = None


class JobPullResponse(BaseModel):
    jobs: List[JobPullJob]


class JobEnqueueRequest(BaseModel):
    job_type: str = "RULES_RELOAD"
    client_id: str
    agent_id: str
    idempotency_key: str
    approvals_required: int = 0
    expires_at: Optional[datetime] = None
    args: Dict[str, Any] = Field(default_factory=dict)
    requested_by: str
    rate_limit_per_min: Optional[int] = None
    dry_run: bool = False


class JobEnqueueResponse(BaseModel):
    job_id: str
    status: str
    signature: str


class JobApprovalRequest(BaseModel):
    job_id: str
    approver: str
    comment: Optional[str] = None


class JobApprovalResponse(BaseModel):
    status: str
    approvals_granted: int


class JobResultRequest(BaseModel):
    job_id: str
    agent_id: str
    success: bool
    output_snippet: Optional[str] = None
    error_detail: Optional[str] = None
    actor: Optional[str] = None


class JobResultResponse(BaseModel):
    status: str
    audit_id: Optional[int] = None


class ExportIncidentResponse(BaseModel):
    incident_id: str
    summary: str
    attack_mapping: List[Dict[str, Any]]
    recommended_actions: List[Dict[str, Any]]
    confidence: float
    status: str
    created_at: datetime


class PolicyResponse(BaseModel):
    global_cfg: Dict[str, Any]
    client_cfg: Dict[str, Any]
    host_cfg: Dict[str, Any]
    effective_cfg: Dict[str, Any]
    signature: str
    etag: str


class PolicyUpdateRequest(BaseModel):
    scope: str
    client_id: Optional[str] = None
    host: Optional[str] = None
    config: Dict[str, Any]
    actor: str


class PolicyUpdateResponse(BaseModel):
    etag: str
    signature: str
