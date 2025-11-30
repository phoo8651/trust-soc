from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Any
from datetime import datetime


class BaseSchema(BaseModel):
    model_config = ConfigDict(extra="ignore")


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
    msg: Optional[str] = None


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


class RenewRequest(BaseSchema):
    agent_id: str
    refresh_token: str


class RenewResponse(BaseSchema):
    access_token: str
    refresh_token: str
    expires_in: int
