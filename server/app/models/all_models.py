import uuid
from sqlalchemy import Column, String, Integer, Text, Boolean, TIMESTAMP, func, BigInteger, Identity, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base

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
    )

class RawLog(Base):
    __tablename__ = "raw_logs"
    # Postgres Partitioning을 고려하여 Identity 사용
    id = Column("id", BigInteger, Identity(always=False), primary_key=True)
    ts = Column(TIMESTAMP(timezone=True), nullable=False)
    client_id = Column(String, nullable=False)
    host = Column(String, nullable=False)
    agent_id = Column(String, nullable=False)
    source_type = Column(String, nullable=False)
    raw_line = Column(Text, nullable=False)
    hash_sha256 = Column(String)
    tags = Column(JSONB)
    inserted_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class Event(Base):
    __tablename__ = "events"
    id = Column("id", BigInteger, Identity(always=False), primary_key=True)
    ts = Column(TIMESTAMP(timezone=True), nullable=False)
    client_id = Column(String, nullable=False)
    host = Column(String, nullable=False)
    category = Column(String)
    severity = Column(String)
    summary = Column(Text)
    evidence_refs = Column(JSONB, nullable=False, default=list)
    rule_id = Column(String)
    context = Column(JSONB)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class Incident(Base):
    __tablename__ = "incidents"
    incident_id = Column(String, primary_key=True, default=lambda: f"inc-{uuid.uuid4()}")
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    client_id = Column(String, nullable=False)
    category = Column(String)
    summary = Column(Text)
    attack_mapping = Column(JSONB)
    recommended_actions = Column(JSONB)
    confidence = Column(Integer)
    status = Column(String)
    incident_metadata = Column(JSONB)

class Job(Base):
    __tablename__ = "jobs"
    job_id = Column(String, primary_key=True, default=lambda: f"job-{uuid.uuid4()}")
    client_id = Column(String, nullable=False)
    agent_id = Column(String, nullable=False)
    job_type = Column(String, nullable=False)
    args = Column(JSONB)
    status = Column(String, default="pending")
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    signature = Column(Text)
    
class Policy(Base):
    __tablename__ = "policies"
    policy_id = Column(Integer, primary_key=True, autoincrement=True)
    scope = Column(String, nullable=False)        
    client_id = Column(String)
    host = Column(String)
    config = Column(JSONB, nullable=False)
    etag = Column(String)
    signature = Column(Text)
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
    context = Column(JSONB)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())