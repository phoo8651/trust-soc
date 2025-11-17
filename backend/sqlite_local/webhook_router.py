import hashlib
import hmac
import json
import os
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from db import get_db

router = APIRouter()

_SIGNING_VERSION = "v0"
_MAX_TS_SKEW = 60 * 5  


@router.post("/webhook/slack")
async def slack_callback(
    request: Request,
    slack_signature: str = Header(..., alias="X-Slack-Signature"),
    slack_ts: str = Header(..., alias="X-Slack-Request-Timestamp"),
    db: Session = Depends(get_db),
):
    secret = os.getenv("SLACK_SIGNING_SECRET")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="slack signing secret not configured",
        )

    try:
        ts_int = int(slack_ts)
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid slack timestamp")

    if abs(int(time.time()) - ts_int) > _MAX_TS_SKEW:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="slack timestamp too old")

    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8")
    basestring = f"{_SIGNING_VERSION}:{slack_ts}:{body_text}"
    expected_sig = f"{_SIGNING_VERSION}=" + hmac.new(
        secret.encode("utf-8"),
        basestring.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, slack_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid slack signature")

    payload = json.loads(body_text) if body_text else {}

    
    return {"status": "ok", "received": payload.get("type", "unknown")}
