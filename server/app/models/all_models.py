import uuid
from sqlalchemy import Column, String, Integer, Text, Boolean, TIMESTAMP, ForeignKey, func, BigInteger, Identity, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base

class Agent(Base):
    __tablename__ = "agents"
    agent_id = Column(String, primary_key=True, default=lambda: f"agent-{uuid.uuid4()}")
    client_id = Column(String, nullable=False)
    host = Column(String, nullable=False)
    agent_version = Column(String)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=False)
    access_expires = Column(TIMESTAMP(timezone=True), nullable=False)
    registered_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"
    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String, nullable=False)
    agent_id = Column(String, nullable=False)
    idem_key = Column(String, nullable=False)
    nonce = Column(String)
    ts_bucket = Column(String)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    __table_args__ = (UniqueConstraint("client_id", "agent_id", "idem_key", name="uq_idem_key"),)

class RawLog(Base):
    __tablename__ = "raw_logs"
    # Postgres 파티셔닝을 위해 ts를 PK에 포함하거나 Identity 사용 주의 (여기선 심플하게 처리)
    id = Column(BigInteger, Identity(always=False), primary_key=True)
    ts = Column(TIMESTAMP(timezone=True), nullable=False)
    client_id = Column(String, nullable=False)
    host = Column(String)
    agent_id = Column(String)
    source_type = Column(String)
    raw_line = Column(Text)
    hash_sha256 = Column(String)
    # inserted_at = Column(TIMESTAMP(timezone=True), server_default=func.now()) # 파티션 키 이슈로 일단 생략 가능

class Event(Base):
    __tablename__ = "events"
    id = Column(BigInteger, Identity(always=False), primary_key=True)
    ts = Column(TIMESTAMP(timezone=True))
    client_id = Column(String)
    severity = Column(String)
    summary = Column(Text)
    context = Column(JSONB)

class Incident(Base):
    __tablename__ = "incidents"
    incident_id = Column(String, primary_key=True, default=lambda: f"inc-{uuid.uuid4()}")
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    client_id = Column(String)
    summary = Column(Text)
    status = Column(String)
    recommended_actions = Column(JSONB)
    confidence = Column(Integer) # or Float

class Job(Base):
    __tablename__ = "jobs"
    job_id = Column(String, primary_key=True, default=lambda: f"job-{uuid.uuid4()}")
    client_id = Column(String, nullable=False)
    agent_id = Column(String, nullable=False)
    job_type = Column(String, nullable=False)
    args = Column(JSONB)
    status = Column(String, default="pending")
    signature = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class AuditLog(Base):
    __tablename__ = "audit_logs"
    audit_id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String)
    subject = Column(String)
    action = Column(String)
    context = Column(JSONB)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())