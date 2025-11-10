# coding: utf-8
from __future__ import annotations
from typing import Dict, Any
from datetime import datetime, timedelta, timezone
import secrets, hmac, hashlib, base64, json

def _now() -> datetime:
    return datetime.now(timezone.utc)

def issue_tokens(subject: str, ttl_minutes: int = 60) -> Dict[str, Any]:
    """간단한 토큰 발급 (MVP)"""
    access  = secrets.token_urlsafe(24)
    refresh = secrets.token_urlsafe(32)
    exp = _now() + timedelta(minutes=ttl_minutes)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": int(ttl_minutes * 60),
        "subject": subject,
        "exp": int(exp.timestamp()),
    }

def compute_etag(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()

def compute_policy_signature(policy: Dict[str, Any], key: bytes = b"demo-secret") -> str:
    msg = json.dumps(policy, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.b64encode(sig).decode("ascii").rstrip("=")

def validate_access(token: str) -> bool:
    return isinstance(token, str) and len(token) >= 16
