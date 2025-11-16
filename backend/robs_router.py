import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from auth_core import compute_job_signature, verify_job_signature
from db import get_db
import model
import schemas
from security import SecurityContext, apply_rls, get_security_context, require_role

router = APIRouter()
logger = logging.getLogger("jobs")

ALLOWED_AGENT_COMMANDS = {"RULES_RELOAD"}
DEFAULT_COMMAND_TTL_SECONDS = 600


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_args(job) -> dict:
    return job.args or {}


def _compute_command_hash(job_type: str, args: dict) -> str:
    canonical = json.dumps({"type": job_type, "args": args}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@router.post(
    "/agent/jobs/enqueue",
    response_model=schemas.JobEnqueueResponse,
    status_code=status.HTTP_201_CREATED,
)
def enqueue_job(
    body: schemas.JobEnqueueRequest,
    db: Session = Depends(get_db),
    ctx: SecurityContext = Depends(get_security_context),
):
    require_role(ctx, "SOC_ADMIN")
    apply_rls(db, ctx.tenant_id)
    if ctx.tenant_id != body.client_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
    if body.job_type not in ALLOWED_AGENT_COMMANDS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="job type not supported")

    existing = (
        db.query(model.Job)
        .filter(
            model.Job.client_id == body.client_id,
            model.Job.agent_id == body.agent_id,
            model.Job.idempotency_key == body.idempotency_key,
            model.Job.client_id == ctx.tenant_id,
        )
        .first()
    )
    if existing:
        signature = existing.signature or compute_job_signature(existing.job_type, _safe_args(existing))
        existing.signature = signature
        db.commit()
        return schemas.JobEnqueueResponse(job_id=existing.job_id, status="duplicate", signature=signature)

    args = body.args or {}
    signature = compute_job_signature(body.job_type, args)
    expires_at = body.expires_at or (_utcnow() + timedelta(seconds=DEFAULT_COMMAND_TTL_SECONDS))
    status_val = "pending" if (body.approvals_required or 0) > 0 else "ready"
    job = model.Job(
        client_id=body.client_id,
        agent_id=body.agent_id,
        job_type=body.job_type,
        args=args,
        approvals_required=body.approvals_required,
        approvals_granted=0,
        expires_at=expires_at,
        idempotency_key=body.idempotency_key,
        rate_limit_per_min=body.rate_limit_per_min,
        dry_run=body.dry_run,
        signature=signature,
        status=status_val,
        command_hash=_compute_command_hash(body.job_type, args),
    )
    db.add(job)
    db.flush()

    db.add(
        model.AuditLog(
            actor=body.requested_by,
            subject=job.job_id,
            action="job_enqueued",
            context={
                "job_type": body.job_type,
                "approvals_required": body.approvals_required,
                "rate_limit_per_min": body.rate_limit_per_min,
                "dry_run": body.dry_run,
            },
        )
    )
    db.commit()

    return schemas.JobEnqueueResponse(job_id=job.job_id, status=job.status, signature=signature)


@router.get("/agent/jobs/pull", response_model=schemas.JobPullResponse)
def pull_jobs(
    agent_id: str = Query(...),
    db: Session = Depends(get_db),
    ctx: SecurityContext = Depends(get_security_context),
):
    require_role(ctx, "AGENT")
    apply_rls(db, ctx.tenant_id)
    now = _utcnow()
    jobs = (
        db.query(model.Job)
        .filter(
            model.Job.agent_id == agent_id,
            model.Job.client_id == ctx.tenant_id,
            model.Job.status.in_(("ready", "pending")),
            model.Job.job_type.in_(tuple(ALLOWED_AGENT_COMMANDS)),
        )
        .all()
    )

    deliverables = []
    for job in jobs:
        if job.expires_at and job.expires_at < now:
            job.status = "expired"
            logger.info("job %s expired before delivery", job.job_id)
            continue

        required = job.approvals_required or 0
        granted = job.approvals_granted or 0
        if granted < required:
            job.status = "pending"
            continue

        args = _safe_args(job)
        if job.signature:
            if not verify_job_signature(job.job_type, args, job.signature):
                job.status = "invalid_signature"
                logger.error("job %s failed signature verification", job.job_id)
                continue
        else:
            job.signature = compute_job_signature(job.job_type, args)
            logger.warning("job %s missing signature; issuing derived signature", job.job_id)

        deliverables.append(
            {
                "job_id": job.job_id,
                "type": job.job_type,
                "args": args,
                "approvals_required": required,
                "approvals_granted": granted,
                "issued_at": job.created_at,
                "expires_at": job.expires_at,
                "idempotency_key": job.idempotency_key,
                "rate_limit_per_min": job.rate_limit_per_min,
                "dry_run": bool(job.dry_run),
                "signature": job.signature,
            }
        )
        job.status = "delivered"
        job.last_delivered_at = now
        job.command_hash = _compute_command_hash(job.job_type, args)
        db.add(
            model.AuditLog(
                actor="system",
                subject=job.job_id,
                action="job_delivered",
                context={"agent_id": agent_id, "job_type": job.job_type},
            )
        )

    db.commit()

    return {"jobs": deliverables}


@router.post("/agent/jobs/approve", response_model=schemas.JobApprovalResponse)
def approve_job(
    body: schemas.JobApprovalRequest,
    db: Session = Depends(get_db),
    ctx: SecurityContext = Depends(get_security_context),
):
    require_role(ctx, "SOC_ADMIN")
    apply_rls(db, ctx.tenant_id)
    job = (
        db.query(model.Job)
        .filter(model.Job.job_id == body.job_id, model.Job.client_id == ctx.tenant_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="job not found")
    if job.client_id != ctx.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
    if job.job_type not in ALLOWED_AGENT_COMMANDS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="job type not supported")

    if job.status not in ("pending", "ready"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="job not approvable")

    approval = model.JobApproval(job_id=job.job_id, approver=body.approver, comment=body.comment)
    db.add(approval)

    granted = (job.approvals_granted or 0) + 1
    job.approvals_granted = granted
    db.add(
        model.AuditLog(
            actor=body.approver,
            subject=job.job_id,
            action="job_approved",
            context={"comment": body.comment},
        )
    )

    required = job.approvals_required or 0
    if granted >= required:
        job.status = "ready"

    db.commit()
    return {"status": "ok", "approvals_granted": granted}


@router.post("/agent/jobs/result", response_model=schemas.JobResultResponse)
def post_job_result(
    body: schemas.JobResultRequest,
    db: Session = Depends(get_db),
    ctx: SecurityContext = Depends(get_security_context),
):
    require_role(ctx, "AGENT")
    apply_rls(db, ctx.tenant_id)
    job = (
        db.query(model.Job)
        .filter(model.Job.job_id == body.job_id, model.Job.client_id == ctx.tenant_id)
        .first()
    )

    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="job not found")
    if job.client_id != ctx.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant mismatch")
    if job.job_type not in ALLOWED_AGENT_COMMANDS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="job type not supported")

    if job.agent_id != body.agent_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent mismatch")

    jr = model.JobResult(
        job_id=body.job_id,
        agent_id=body.agent_id,
        success=body.success,
        output_snippet=body.output_snippet,
        error_detail=body.error_detail,
    )
    db.add(jr)

    job.status = "done" if body.success else "error"
    actor = ctx.actor_id or body.actor or body.agent_id
    audit_entry = model.AuditLog(
        actor=actor,
        subject=job.job_id,
        action="job_result",
        context={
            "success": body.success,
            "agent_id": body.agent_id,
            "job_type": job.job_type,
            "dry_run": bool(job.dry_run),
        },
    )
    db.add(audit_entry)

    db.commit()

    return {"status": "recorded", "audit_id": audit_entry.audit_id}
