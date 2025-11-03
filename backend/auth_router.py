import logging
import os
import uuid
from datetime import timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from db import get_db
import model, schemas
from auth_core import issue_tokens

router = APIRouter()
logger = logging.getLogger("auth")
BOOTSTRAP_SECRET = os.getenv("AGENT_BOOTSTRAP_SECRET")

@router.post(
    "/auth/register",
    response_model=schemas.RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_agent(body: schemas.RegisterRequest, db: Session = Depends(get_db)):
    if not body.secret_proof:
        raise HTTPException(status_code=400, detail="missing bootstrap secret")
    if BOOTSTRAP_SECRET and body.secret_proof != BOOTSTRAP_SECRET:
        raise HTTPException(status_code=401, detail="invalid bootstrap secret")

    access_token, refresh_token, expires_at, ttl_seconds = issue_tokens()

    agent_id = f"agent-{uuid.uuid4()}"
    row = model.Agent(
        agent_id=agent_id,
        client_id=body.client_id,
        host=body.host,
        agent_version=body.agent_version,
        refresh_token=refresh_token,
        access_token=access_token,
        access_expires=expires_at.astimezone(timezone.utc),
    )
    db.add(row)
    db.add(
        model.AuditLog(
            actor="agent-bootstrap",
            subject=agent_id,
            action="agent_registered",
            context={
                "client_id": body.client_id,
                "host": body.host,
                "agent_version": body.agent_version,
            },
        )
    )
    db.commit()

    logger.info("registered agent %s for client %s host %s", agent_id, body.client_id, body.host)

    return schemas.RegisterResponse(
        agent_id=agent_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ttl_seconds,
    )

@router.post(
    "/auth/token/refresh",
    response_model=schemas.RefreshResponse,
    status_code=status.HTTP_200_OK,
)
def refresh_token(body: schemas.RefreshRequest, db: Session = Depends(get_db)):
    agent = db.query(model.Agent).filter(
        model.Agent.agent_id == body.agent_id
    ).first()

    if not agent or agent.refresh_token != body.refresh_token:
        raise HTTPException(status_code=401, detail="invalid refresh token")

    new_access, _new_refresh, new_exp, ttl_seconds = issue_tokens()
    agent.access_token = new_access
    agent.access_expires = new_exp.astimezone(timezone.utc)
    db.add(
        model.AuditLog(
            actor=body.agent_id,
            subject=body.agent_id,
            action="access_token_rotated",
            context={"reason": "refresh_endpoint"},
        )
    )
    db.commit()

    logger.info("rotated access token for agent %s", body.agent_id)

    return schemas.RefreshResponse(
        access_token=new_access,
        expires_in=ttl_seconds,
    )
