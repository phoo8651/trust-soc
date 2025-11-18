import binascii
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

try:
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey
except ImportError:
    SigningKey = None  
    HexEncoder = None  


def _canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _load_secret(env_key: str, fallback: str) -> str:
    val = os.getenv(env_key)
    if val:
        return val
    return fallback


def _load_ed25519_key(env_key: str) -> Optional["SigningKey"]:
    if SigningKey is None:
        return None
    seed_hex = os.getenv(env_key)
    if not seed_hex:
        return None
    try:
        seed_bytes = bytes.fromhex(seed_hex)
    except ValueError:
        try:
            seed_bytes = binascii.a2b_base64(seed_hex)
        except binascii.Error:
            return None
    if len(seed_bytes) not in (32, 64):
        return None
    try:
        return SigningKey(seed_bytes[:32])
    except Exception:
        return None


ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "3600"))
POLICY_SIGNING_SECRET = _load_secret("POLICY_SIGNING_SECRET", "dev-policy-secret")
JOB_SIGNING_SECRET = _load_secret("JOB_SIGNING_SECRET", "dev-job-secret")
_POLICY_SIGNING_KEY_ED25519 = _load_ed25519_key("POLICY_SIGNING_KEY_ED25519")
_JOB_SIGNING_KEY_ED25519 = _load_ed25519_key("JOB_SIGNING_KEY_ED25519")


def issue_tokens() -> Tuple[str, str, datetime, int]:
    now = datetime.now(timezone.utc)
    access = f"acc_{uuid.uuid4()}"
    refresh = f"rft_{uuid.uuid4()}"
    expires_at = now + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS)
    return access, refresh, expires_at, ACCESS_TOKEN_TTL_SECONDS


def _to_aware_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def validate_access(token_from_header: str, db_agent_row) -> bool:
    if not token_from_header:
        return False
    if getattr(db_agent_row, "access_token", None) != token_from_header:
        return False
    exp = _to_aware_utc(getattr(db_agent_row, "access_expires", None))
    now = datetime.now(timezone.utc)
    if exp and exp < now:
        return False
    return True


def _sign_with_ed25519(signing_key: Optional["SigningKey"], canonical: str) -> Optional[str]:
    if signing_key is None:
        return None
    signature = signing_key.sign(canonical.encode("utf-8")).signature
    return "ed25519:" + signature.hex()


def compute_policy_signature(policy_payload: Dict[str, Any]) -> str:
    canonical = _canonical_json(policy_payload)
    ed_sig = _sign_with_ed25519(_POLICY_SIGNING_KEY_ED25519, canonical)
    if ed_sig:
        if HexEncoder and _POLICY_SIGNING_KEY_ED25519:
            verify_key = _POLICY_SIGNING_KEY_ED25519.verify_key.encode(encoder=HexEncoder).decode()
            return f"{ed_sig}|vk:{verify_key}"
        return ed_sig
    digest = hmac.new(
        POLICY_SIGNING_SECRET.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"sigv1:{digest}"


def compute_etag(payload: Dict[str, Any]) -> str:
    canonical = _canonical_json(payload)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"W/\"{digest}\""


def compute_job_signature(job_type: str, args: Dict[str, Any]) -> str:
    payload = {"type": job_type, "args": args}
    canonical = _canonical_json(payload)
    ed_sig = _sign_with_ed25519(_JOB_SIGNING_KEY_ED25519, canonical)
    if ed_sig:
        return ed_sig

    digest = hmac.new(
        JOB_SIGNING_SECRET.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"cmdsig:{digest}"


def verify_job_signature(job_type: str, args: Dict[str, Any], signature: str) -> bool:
    if not signature:
        return False
    expected = compute_job_signature(job_type, args)
    return hmac.compare_digest(signature, expected)
