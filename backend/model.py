import os
import uuid
from sqlalchemy import Column, String, Integer, Text, Boolean, TIMESTAMP, Numeric, Index, UniqueConstraint, ForeignKey, func
from db import Base

DATABASE_URL = os.getenv("DATABASE_URL", "")
IS_PG = DATABASE_URL.startswith("postgresql")

if IS_PG:
    from sqlalchemy.dialects.postgresql import JSONB as JSONType
    from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
    from sqlalchemy.dialects.postgresql import TSRANGE as TsRangeType
    def Arr(item_type):
        return PG_ARRAY(item_type)
else:
    from sqlalchemy import JSON as JSONType
    TsRangeType = JSONType
    def Arr(item_type):
        return JSONType

class Agent(Base):
    __tablename__ = "agents"
    agent_id = Column(String, primary_key=True, default=lambda: f"agent-{uuid.uuid4()}")
    client_id = Column(String, nullable=False)
    host = Column(String, nullable=False)
    agent_version = Column(String)
    registered_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    refresh_token = Column(Text, nullable=False)
    access_token = Column(Text, nullable=False)
    access_expires = Column(TIMESTAMP(timezone=True), nullable=False)

class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"
    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String, nullable=False)
    agent_id = Column(String, nullable=False)
    idem_key = Column(String, nullable=False)
    nonce = Column(String, nullable=False)
    ts_bucket = Column(String, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    __table_args__ = (
        UniqueConstraint("client_id", "agent_id", "idem_key", name="uq_idem_key"),
        UniqueConstraint("client_id", "agent_id", "nonce", "ts_bucket", name="uq_nonce_bucket"),
        Index("idx_idem_created_at", "created_at"),
    )

class RawLog(Base):
    __tablename__ = "raw_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(TIMESTAMP(timezone=True), nullable=False)
    client_id = Column(String, nullable=False)
    host = Column(String, nullable=False)
    agent_id = Column(String, nullable=False)
    source_type = Column(String, nullable=False)
    raw_line = Column(Text, nullable=False)
    hash_sha256 = Column(String)
    tags = Column(Arr(String), nullable=False, default=list)
    inserted_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    __table_args__ = (
        Index("idx_raw_logs_client_ts", "client_id", "ts"),
        Index("idx_raw_logs_hash", "hash_sha256"),
    )

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(TIMESTAMP(timezone=True), nullable=False)
    client_id = Column(String, nullable=False)
    host = Column(String, nullable=False)
    category = Column(String)
    severity = Column(String)
    summary = Column(Text)
    evidence_refs = Column(JSONType, nullable=False, default=list)
    rule_id = Column(String)
    ml_score = Column(Numeric)
    source_ip_enc = Column(String)
    url_path = Column(String)
    ua_hash = Column(String)
    context = Column(JSONType)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    __table_args__ = (
        Index("idx_events_client_ts", "client_id", "ts"),
        Index("idx_events_rule", "rule_id"),
    )

class Incident(Base):
    __tablename__ = "incidents"
    incident_id = Column(String, primary_key=True, default=lambda: f"inc-{uuid.uuid4()}")
    client_id = Column(String, nullable=False)
    time_window = Column(TsRangeType)
    category = Column(String)
    summary = Column(Text)
    attack_mapping = Column(Arr(String), default=list)
    recommended_actions = Column(Arr(String), default=list)
    confidence = Column(Numeric)
    status = Column(String)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    incident_metadata = Column(JSONType)

class Job(Base):
    __tablename__ = "jobs"
    job_id = Column(String, primary_key=True, default=lambda: f"job-{uuid.uuid4()}")
    client_id = Column(String, nullable=False)
    agent_id = Column(String, nullable=False)
    job_type = Column(String, nullable=False)
    args = Column(JSONType)
    approvals_required = Column(Integer)
    approvals_granted = Column(Integer, default=0)
    expires_at = Column(TIMESTAMP(timezone=True))
    idempotency_key = Column(String, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    status = Column(String, default="pending")
    __table_args__ = (
        Index("idx_jobs_agent_status", "agent_id", "status"),
        Index("idx_jobs_status_created", "status", "created_at"),
    )

class JobResult(Base):
    __tablename__ = "job_results"
    result_id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id"), nullable=False)
    agent_id = Column(String, nullable=False)
    reported_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    success = Column(Boolean)
    output_snippet = Column(Text)
    error_detail = Column(Text)

class JobApproval(Base):
    __tablename__ = "job_approvals"
    approval_id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("jobs.job_id"), nullable=False)
    approver = Column(String, nullable=False)
    comment = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    __table_args__ = (
        UniqueConstraint("job_id", "approver", name="uq_job_approver"),
    )

class Policy(Base):
    __tablename__ = "policies"
    policy_id = Column(Integer, primary_key=True, autoincrement=True)
    scope = Column(String, nullable=False)
    client_id = Column(String)
    host = Column(String)
    config = Column(JSONType, nullable=False)
    etag = Column(String, nullable=False)
    signature = Column(Text, nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())
    __table_args__ = (
        UniqueConstraint("scope", "client_id", "host", name="uq_policy_scope"),
    )

class AuditLog(Base):
    __tablename__ = "audit_logs"
    audit_id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String, nullable=False)
    subject = Column(String, nullable=False)
    action = Column(String, nullable=False)
    context = Column(JSONType)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    __table_args__ = (
        Index("idx_audit_subject", "subject"),
        Index("idx_audit_created", "created_at"),
    )
