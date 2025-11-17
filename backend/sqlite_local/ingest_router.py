import hashlib
import logging
import math
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from auth_core import validate_access
from db import get_db
from metrics import record_e2e_latency
import model
import schemas
from pipeline import (
    build_event_payload,
    build_incident_payload,
    detect_threat,
    normalize_record,
)
from security import apply_rls
from utils_security import (
    verify_timestamp,
    verify_payload_hash,
    make_ts_bucket,
    queue_is_overloaded,
)

router = APIRouter()
logger = logging.getLogger("ingest")

INGEST_WINDOW_SECONDS = int(os.getenv("INGEST_RATE_WINDOW_SECONDS", "60"))
INGEST_RATE_LIMIT_PER_WINDOW = int(os.getenv("INGEST_RATE_LIMIT_PER_WINDOW", "5000"))
INGEST_RETRY_AFTER_BASE = int(os.getenv("INGEST_RETRY_AFTER_SECONDS", "2"))
INGEST_RETRY_AFTER_MAX = int(os.getenv("INGEST_RETRY_AFTER_MAX_SECONDS", "5"))


def _rate_limit_headers(recent_count: int) -> dict:
    overage = max(0, recent_count - INGEST_RATE_LIMIT_PER_WINDOW)
    if overage <= 0:
        retry_after = INGEST_RETRY_AFTER_BASE
    else:
        step = max(1, INGEST_RATE_LIMIT_PER_WINDOW // 5)
        retry_after = INGEST_RETRY_AFTER_BASE + math.ceil(overage / step)
    retry_after = max(1, min(INGEST_RETRY_AFTER_MAX, retry_after))
    return {"Retry-After": str(retry_after)}


@router.post(
    "/ingest/logs",
    response_model=schemas.IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_logs(
    req: Request,
    payload: schemas.IngestRequest,
    db: Session = Depends(get_db),
    authorization: str = Header(..., alias="Authorization"),
    idem_key: str = Header(..., alias="X-Idempotency-Key"),
    req_ts: str = Header(..., alias="X-Request-Timestamp"),
    nonce: str = Header(..., alias="X-Nonce"),
    payload_hash: str = Header(..., alias="X-Payload-Hash"),
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid auth header")
    access_token = authorization.split(" ", 1)[1]

    agent_row = db.query(model.Agent).filter(
        model.Agent.agent_id == payload.agent_id,
        model.Agent.client_id == payload.meta.client_id,
        model.Agent.host == payload.meta.host,
    ).first()

    if not agent_row or not validate_access(access_token, agent_row):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")

    try:
        verify_timestamp(req_ts)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    body_bytes = await req.body()
    try:
        verify_payload_hash(body_bytes, payload_hash)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    ts_bucket = make_ts_bucket(req_ts)

    apply_rls(db, payload.meta.client_id)

    existed = db.query(model.IdempotencyKey).filter_by(
        client_id=payload.meta.client_id,
        agent_id=payload.agent_id,
        idem_key=idem_key,
    ).first()
    if existed:
        return schemas.IngestResponse(status="queued", accepted=0)

    replay = db.query(model.IdempotencyKey).filter_by(
        client_id=payload.meta.client_id,
        agent_id=payload.agent_id,
        nonce=nonce,
        ts_bucket=ts_bucket,
    ).first()
    if replay:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="REPLAY_BLOCKED")

    window_start = datetime.now(timezone.utc) - timedelta(seconds=INGEST_WINDOW_SECONDS)
    recent_count = db.query(model.RawLog).filter(
        model.RawLog.agent_id == payload.agent_id,
        model.RawLog.client_id == payload.meta.client_id,
        model.RawLog.inserted_at >= window_start,
    ).count()

    if recent_count >= INGEST_RATE_LIMIT_PER_WINDOW:
        logger.warning(
            "rate limit for agent %s client %s recent_count=%s",
            payload.agent_id,
            payload.meta.client_id,
            recent_count,
        )
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate_limit",
            headers=_rate_limit_headers(recent_count),
        )

    new_key = model.IdempotencyKey(
        client_id=payload.meta.client_id,
        agent_id=payload.agent_id,
        idem_key=idem_key,
        nonce=nonce,
        ts_bucket=ts_bucket,
    )
    db.add(new_key)

    if queue_is_overloaded():
        logger.warning("simulated queue overload for agent %s", payload.agent_id)
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="backpressure",
            headers=_rate_limit_headers(recent_count + 1),
        )

    if not payload.records:
        db.commit()
        return schemas.IngestResponse(status="queued", accepted=0)

    raw_rows = []
    prepared = []
    for rec in payload.records:
        raw_hash = hashlib.sha256(rec.raw_line.encode("utf-8", errors="ignore")).hexdigest()
        raw_rows.append(
            model.RawLog(
                ts=rec.ts,
                client_id=payload.meta.client_id,
                host=payload.meta.host,
                agent_id=payload.agent_id,
                source_type=rec.source_type,
                raw_line=rec.raw_line,
                tags=rec.tags,
                hash_sha256=raw_hash,
            )
        )
        normalized = normalize_record(payload.meta, rec)
        outcome = detect_threat(normalized, rec)
        prepared.append((rec, normalized, outcome))
        record_e2e_latency(rec.ts)

    db.add_all(raw_rows)
    db.flush(raw_rows)

    events = []
    incidents = []
    audits = []

    for raw_row, (rec, normalized, outcome) in zip(raw_rows, prepared):
        event_payload = build_event_payload(
            payload.meta,
            rec,
            raw_row.id,
            normalized,
            outcome,
        )
        events.append(
            model.Event(
                ts=rec.ts,
                client_id=payload.meta.client_id,
                host=payload.meta.host,
                category=event_payload["category"],
                severity=event_payload["severity"],
                summary=event_payload["summary"],
                evidence_refs=event_payload["evidence_refs"],
                rule_id=event_payload["rule_id"],
                ml_score=event_payload["ml_score"],
                source_ip_enc=event_payload["source_ip_enc"],
                url_path=event_payload["url_path"],
                ua_hash=event_payload["ua_hash"],
                context=event_payload["context"],
            )
        )

        incident_payload = build_incident_payload(
            payload.meta,
            outcome,
            normalized,
            payload.agent_id,
        )
        incident_row = model.Incident(
            incident_id=incident_payload["incident_id"],
            client_id=payload.meta.client_id,
            summary=incident_payload["summary"],
            category=incident_payload["category"],
            attack_mapping=incident_payload["attack_mapping"],
            recommended_actions=incident_payload["recommended_actions"],
            confidence=incident_payload["confidence"],
            status=incident_payload["status"],
            incident_metadata=incident_payload["incident_metadata"],
        )
        incidents.append(incident_row)

        audits.append(
            model.AuditLog(
                actor=payload.agent_id,
                subject=incident_row.incident_id,
                action="incident_generated",
                context={
                    "client_id": payload.meta.client_id,
                    "host": payload.meta.host,
                    "rule_id": event_payload["rule_id"],
                    "severity": event_payload["severity"],
                },
            )
        )

    if events:
        db.add_all(events)
    if incidents:
        db.add_all(incidents)
    if audits:
        db.add_all(audits)

    db.commit()

    return schemas.IngestResponse(status="queued", accepted=len(raw_rows))
