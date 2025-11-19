import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from auth_core import compute_etag, compute_policy_signature
from db import get_db
import model
import schemas
from security import SecurityContext, get_security_context, require_role, apply_rls

router = APIRouter()
logger = logging.getLogger("policy")

DEFAULT_GLOBAL_POLICY: Dict[str, Dict] = {
    "sampling": {"default_rate": 0.1},
    "masking": {"rules": ["ip", "user_id"]},
    "crypto": {"type": "AES-GCM", "enabled": True},
}
DEFAULT_CLIENT_POLICY: Dict[str, Dict] = {}
DEFAULT_HOST_POLICY: Dict[str, Dict] = {}

def _deep_merge(base: Dict, overlay: Dict) -> Dict:
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = _deep_merge(base[k], v)
        else:
            base[k] = v
    return base

def _lookup_policy(db: Session, scope: str, client_id: str, host: str) -> Dict:
    q = db.query(model.Policy).filter(model.Policy.scope == scope)
    if scope in ("client", "host"):
        q = q.filter(model.Policy.client_id == client_id)
    if scope == "host":
        q = q.filter(model.Policy.host == host)
    record = q.first()

    if not record:
        defaults = {"global": DEFAULT_GLOBAL_POLICY, "client": DEFAULT_CLIENT_POLICY, "host": DEFAULT_HOST_POLICY}
        cfg = deepcopy(defaults[scope])
        etag = compute_etag({"scope": scope, "config": cfg})
        return {"config": cfg, "etag": etag}

    cfg = deepcopy(record.config or {})
    etag = record.etag or compute_etag({"scope": scope, "config": cfg})
    return {"config": cfg, "etag": etag}

def _normalize_etag(val: Optional[str]) -> Optional[str]:
    if not val:
        return val
    v = val.strip()
    if v.startswith("W/"):
        v = v[2:]
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return v

@router.get("/policy", response_model=schemas.PolicyResponse)
def get_policy(
    client_id: str = Query(...),
    host: str = Query(...),
    db: Session = Depends(get_db),
    resp: Response = None,
    ctx: SecurityContext = Depends(get_security_context),
    inm: Optional[str] = Header(None, alias="If-None-Match"),
):
    require_role(ctx, "POLICY_READ")

    if ctx.tenant_id != client_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "client_id mismatch with header tenant")

    apply_rls(db, ctx.tenant_id)

    g = _lookup_policy(db, "global", client_id, host)
    c = _lookup_policy(db, "client", client_id, host)
    h = _lookup_policy(db, "host",   client_id, host)

    effective_cfg = _deep_merge(_deep_merge(deepcopy(g["config"]), c["config"]), h["config"])
    issued_at = datetime.now(timezone.utc).isoformat()

    sources = {"global": g["etag"], "client": c["etag"], "host": h["etag"]}
    stable_payload = {"client_id": client_id, "host": host, "policy": effective_cfg, "sources": sources}
    etag_val = compute_etag(stable_payload)

    signature_payload = {"issued_at": issued_at, **stable_payload}
    signature = compute_policy_signature(signature_payload)

    header_etag = f'W/"{etag_val}"'
    if inm and _normalize_etag(inm) == etag_val:
        return Response(status_code=304, headers={"ETag": header_etag, "X-Policy-Issued-At": issued_at})

    if resp is not None:
        resp.headers["ETag"] = header_etag
        resp.headers["X-Policy-Issued-At"] = issued_at

    logger.debug("policy issued tenant=%s client=%s host=%s etag=%s", ctx.tenant_id, client_id, host, etag_val)
    return {
        "global_cfg": g["config"],
        "client_cfg": c["config"],
        "host_cfg":   h["config"],
        "effective_cfg": effective_cfg,
        "signature":  signature,
        "etag":       etag_val,
    }

@router.post("/policy", response_model=schemas.PolicyUpdateResponse, status_code=status.HTTP_202_ACCEPTED)
def update_policy(
    body: schemas.PolicyUpdateRequest,
    db: Session = Depends(get_db),
    ctx: SecurityContext = Depends(get_security_context),
):
    require_role(ctx, "POLICY_WRITE")
    apply_rls(db, ctx.tenant_id)

    scope = body.scope
    if scope not in ("global", "client", "host"):
        raise HTTPException(status_code=400, detail="invalid scope")
    if scope in ("client", "host") and not body.client_id:
        raise HTTPException(status_code=400, detail="client_id required for scope")
    if scope == "host" and not body.host:
        raise HTTPException(status_code=400, detail="host required for host scope")

    if scope in ("client", "host") and ctx.tenant_id != body.client_id:
        raise HTTPException(status_code=400, detail="client_id mismatch with header tenant")

    q = db.query(model.Policy).filter(model.Policy.scope == scope)
    q = q.filter(model.Policy.client_id.is_(body.client_id) if body.client_id else model.Policy.client_id.is_(None))
    q = q.filter(model.Policy.host.is_(body.host) if body.host else model.Policy.host.is_(None))
    record = q.first()

    payload_for_etag = {"scope": scope, "client_id": body.client_id, "host": body.host, "config": body.config}
    etag = compute_etag(payload_for_etag)
    signature = compute_policy_signature(
        {"issued_at": datetime.now(timezone.utc).isoformat(),
         "client_id": body.client_id, "host": body.host, "policy": body.config, "scope": scope}
    )

    if record:
        record.config = body.config
        record.etag = etag
        record.signature = signature
    else:
        db.add(model.Policy(
            scope=scope, client_id=body.client_id, host=body.host,
            config=body.config, etag=etag, signature=signature
        ))

    db.add(model.AuditLog(
        actor=body.actor,
        subject=f"policy:{scope}:{body.client_id or 'global'}:{body.host or '*'}",
        action="policy_updated",
        context={"etag": etag},
    ))
    db.commit()
    return {"etag": etag, "signature": signature}
