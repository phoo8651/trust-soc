import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.all_models import Job, JobResult, AuditLog
from app.schemas.all_schemas import (
    JobEnqueueRequest,
    JobEnqueueResponse,
    JobPullResponse,
    JobResultRequest,
    JobResultResponse,
)
from app.core.crypto import compute_job_signature

router = APIRouter()
logger = logging.getLogger("jobs")

ALLOWED_AGENT_COMMANDS = {
    "RULES_RELOAD",
    "UPDATE_CONFIG",
    "reload_agent",
    "ping",
    "BLOCK_IP",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_args(job) -> dict:
    return job.args or {}


@router.get("/agent/jobs/pull", response_model=JobPullResponse)
def pull_jobs(
    agent_id: str = Query(...),
    db: Session = Depends(get_db),
):
    """
    Agent가 대기 중인 명령을 가져가는 엔드포인트
    """
    now = _utcnow()

    # 대기 중(pending/ready)인 Job 조회
    jobs = (
        db.query(Job)
        .filter(
            Job.agent_id == agent_id,
            Job.status.in_(("ready", "pending")),
        )
        .all()
    )

    deliverables = []
    for job in jobs:
        # 만료된 Job 처리
        if job.expires_at and job.expires_at < now:
            job.status = "expired"
            continue

        # 승인 대기 중인 Job 처리
        if (job.approvals_required or 0) > (job.approvals_granted or 0):
            continue

        args = _safe_args(job)
        if not job.signature:
            job.signature = compute_job_signature(job.job_type, args)

        deliverables.append(
            {
                "job_id": job.job_id,
                "type": job.job_type,
                "args": args,
                "approvals_required": job.approvals_required or 0,
                "approvals_granted": job.approvals_granted or 0,
                "issued_at": job.created_at,
                "expires_at": job.expires_at,
                "idempotency_key": job.idempotency_key,
                "rate_limit_per_min": job.rate_limit_per_min,
                "dry_run": bool(job.dry_run),
                "signature": job.signature,
            }
        )

        # 상태 업데이트 (Delivered)
        job.status = "delivered"
        job.last_delivered_at = now

        db.add(
            AuditLog(
                actor="system",
                subject=job.job_id,
                action="job_delivered",
                context={"agent_id": agent_id, "job_type": job.job_type},
            )
        )

    db.commit()
    return {"jobs": deliverables}


@router.post("/agent/jobs/result", response_model=JobResultResponse)
def post_job_result(
    body: JobResultRequest,
    db: Session = Depends(get_db),
):
    """
    Agent가 명령 수행 결과를 보고하는 엔드포인트
    """
    job = db.query(Job).filter(Job.job_id == body.job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")

    jr = JobResult(
        job_id=body.job_id,
        agent_id=body.agent_id,
        success=body.success,
        output_snippet=body.output_snippet,
        error_detail=body.error_detail,
    )
    db.add(jr)

    job.status = "done" if body.success else "error"

    db.add(
        AuditLog(
            actor=body.agent_id,
            subject=job.job_id,
            action="job_result",
            context={"success": body.success},
        )
    )
    db.commit()

    return {"status": "recorded"}
