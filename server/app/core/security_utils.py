import hashlib
import hmac
from datetime import datetime, timezone

MAX_SKEW_SEC = 300

def verify_timestamp(ts_str: str):
    if not ts_str: raise ValueError("Missing timestamp")
    try:
        req_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError: raise ValueError("Invalid timestamp format")
    
    delta = abs((datetime.now(timezone.utc) - req_time).total_seconds())
    if delta > MAX_SKEW_SEC: raise ValueError("Timestamp skew too large")

def verify_payload_hash(body_bytes: bytes, header_hash: str):
    if not header_hash: raise ValueError("Missing hash header")
    try:
        algo, hexval = header_hash.split(":", 1)
    except ValueError: raise ValueError("Invalid hash format")
    
    if algo.lower() != "sha256": raise ValueError("Unsupported algo")
    
    computed = hashlib.sha256(body_bytes).hexdigest()
    if not hmac.compare_digest(computed, hexval.lower()):
        raise ValueError("Payload hash mismatch")