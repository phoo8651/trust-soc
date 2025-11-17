import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Header, Query, Response, Request
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
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def _lookup_policy(db: Session, scope: str, client_id: str, host: str) -> Dict:
    """
    policies(scope, client_id, host) → {config, etag}
    DB 없으면 폴백 기본값과 그에 대한 etag 생성
    """
    query = db.query(model.Policy).filter(model.Policy.scope == scope)
    if scope in ("client", "host"):
        query = query.filter(model.Policy.client_id == client_id)
    if scope == "host":
        query = query.filter(model.Policy.host == host)

    record = query.first()
    if not record:
        default_map = {
            "global": DEFAULT_GLOBAL_POLICY,
            "client": DEFAULT_CLIENT_POLICY,
            "host": DEFAULT_HOST_POLICY,
        }
        cfg = deepcopy(default_map[scope])
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
    apply_rls(db, ctx.tenant_id)


    global_entry = _lookup_policy(db, "global", client_id, host)
    client_entry = _lookup_policy(db, "client", client_id, host)
    host_entry = _lookup_policy(db, "host", client_id, host)


    effective_cfg = _deep_merge(deepcopy(global_entry["config"]), client_entry["config"])
    effective_cfg = _deep_merge(effective_cfg, host_entry["config"])

    issued_at = datetime.now(timezone.utc).isoformat()


    sources = {
        "global": global_entry["etag"],
        "client": client_entry["etag"],
        "host": host_entry["etag"],
    }
    stable_payload = {
        "client_id": client_id,
        "host": host,
        "policy": effective_cfg,
        "sources": sources,
    }
    etag_val = compute_etag(stable_payload)  


    signature_payload = {"issued_at": issued_at, **stable_payload}
    signature = compute_policy_signature(signature_payload)


    header_etag = f'W/"{etag_val}"'
    if inm and _normalize_etag(inm) == etag_val:
        return Response(
            status_code=304,
            headers={"ETag": header_etag, "X-Policy-Issued-At": issued_at},
        )


    if resp is not None:
        resp.headers["ETag"] = header_etag
        resp.headers["X-Policy-Issued-At"] = issued_at

    logger.debug(
        "policy issued tenant=%s client=%s host=%s etag=%s",
        ctx.tenant_id, client_id, host, etag_val
    )


    return {
        "global_cfg": global_entry["config"],
        "client_cfg": client_entry["config"],
        "host_cfg": host_entry["config"],
        "effective_cfg": effective_cfg,
        "signature": signature,
        "etag": etag_val,
    }
