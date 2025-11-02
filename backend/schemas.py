from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

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


class JobPullResponse(BaseModel):
    jobs: List[JobPullJob]


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
