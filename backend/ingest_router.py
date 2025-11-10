import hashlib
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session
from db import get_db
import model, schemas
from auth_core import validate_access
from pipeline import process_record
from utils_security import (
    verify_timestamp,
    verify_payload_hash,
    make_ts_bucket,
    queue_is_overloaded,
)

router = APIRouter()
logger = logging.getLogger("ingest")

BACKPRESSURE_WINDOW_SECONDS = 30 #테스트용 설정
BACKPRESSURE_MAX_RECORDS = 50 #테스트용 설정
BACKPRESSURE_RETRY_AFTER_SECONDS = 1 #테스트용 설정

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
        raise HTTPException(status_code=401, detail="invalid auth header")
    access_token = authorization.split(" ", 1)[1]

    agent_row = db.query(model.Agent).filter(
        model.Agent.agent_id == payload.agent_id,
        model.Agent.client_id == payload.meta.client_id,
        model.Agent.host == payload.meta.host,
    ).first()

    if not agent_row or not validate_access(access_token, agent_row):
        raise HTTPException(status_code=401, detail="unauthorized")

    try:
        verify_timestamp(req_ts)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    body_bytes = await req.body()
    try:
        verify_payload_hash(body_bytes, payload_hash)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    ts_bucket = make_ts_bucket(req_ts)

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

    window_start = datetime.now(timezone.utc) - timedelta(seconds=BACKPRESSURE_WINDOW_SECONDS)
    recent_count = db.query(model.RawLog).filter(
        model.RawLog.agent_id == payload.agent_id,
        model.RawLog.client_id == payload.meta.client_id,
        model.RawLog.inserted_at >= window_start,
    ).count()

    if recent_count > BACKPRESSURE_MAX_RECORDS:
        logger.warning(
            "backpressure for agent %s client %s recent_count=%s",
            payload.agent_id,
            payload.meta.client_id,
            recent_count,
        )
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="backpressure",
            headers={"Retry-After": str(BACKPRESSURE_RETRY_AFTER_SECONDS)},
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
            headers={"Retry-After": str(BACKPRESSURE_RETRY_AFTER_SECONDS)},
        )

    accepted_count = 0
    for rec in payload.records:
        raw_hash = hashlib.sha256(rec.raw_line.encode("utf-8", errors="ignore")).hexdigest()
        raw_row = model.RawLog(
            ts=rec.ts,
            client_id=payload.meta.client_id,
            host=payload.meta.host,
            agent_id=payload.agent_id,
            source_type=rec.source_type,
            raw_line=rec.raw_line,
            tags=rec.tags,
            hash_sha256=raw_hash,
        )
        db.add(raw_row)
        db.flush([raw_row])

        event_payload, incident_payload = process_record(
            payload.meta,
            rec,
            raw_row.id,
            payload.agent_id,
        )

        event_row = model.Event(
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
        db.add(event_row)

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
        db.add(incident_row)

        db.add(
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

        accepted_count += 1

    db.commit()

    return schemas.IngestResponse(status="queued", accepted=accepted_count)
