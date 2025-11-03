# -*- coding: utf-8 -*-
import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from auth_core import compute_etag, compute_policy_signature
from db import get_db
import model
import schemas

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


def _lookup_policy(
    db: Session,
    scope: str,
    client_id: str,
    host: str,
) -> Dict:
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


@router.get("/policy", response_model=schemas.PolicyResponse)
def get_policy(
    client_id: str = Query(...),
    host: str = Query(...),
    db: Session = Depends(get_db),
    resp: Response = None,
):
    global_entry = _lookup_policy(db, "global", client_id, host)
    client_entry = _lookup_policy(db, "client", client_id, host)
    host_entry = _lookup_policy(db, "host", client_id, host)

    effective_cfg = _deep_merge(deepcopy(global_entry["config"]), client_entry["config"])
    effective_cfg = _deep_merge(effective_cfg, host_entry["config"])

    issued_at = datetime.now(timezone.utc).isoformat()
    signature_payload = {
        "issued_at": issued_at,
        "client_id": client_id,
        "host": host,
        "policy": effective_cfg,
        "sources": {
            "global": global_entry["etag"],
            "client": client_entry["etag"],
            "host": host_entry["etag"],
        },
    }
    signature = compute_policy_signature(signature_payload)
    etag_val = compute_etag(signature_payload)

    if resp is not None:
        resp.headers["ETag"] = etag_val
        resp.headers["X-Policy-Issued-At"] = issued_at

    logger.debug(
        "policy issued for client=%s host=%s etag=%s", client_id, host, etag_val
    )

    return {
        "global_cfg": global_entry["config"],
        "client_cfg": client_entry["config"],
        "host_cfg": host_entry["config"],
        "effective_cfg": effective_cfg,
        "signature": signature,
        "etag": etag_val,
    }
