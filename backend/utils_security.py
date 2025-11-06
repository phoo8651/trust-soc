from datetime import datetime, timezone
import hashlib
import random
import os

MAX_SKEW_SEC = 300  

def verify_timestamp(ts_str: str):
    req_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    delta = abs((now - req_time).total_seconds())
    if delta > MAX_SKEW_SEC:
        raise ValueError("timestamp skew too large")

def verify_payload_hash(body_bytes: bytes, header_hash: str):
    algo, hexval = header_hash.split(":", 1)
    if algo != "sha256":
        raise ValueError("unsupported hash algo")
    h = hashlib.sha256(body_bytes).hexdigest()
    if h != hexval:
        raise ValueError("payload hash mismatch")

def make_ts_bucket(ts_str: str) -> str:
  
    return ts_str[:16]

def queue_is_overloaded() -> bool:

    if os.getenv("FORCE_QUEUE_OVERLOAD") == "1":
        return True
    try:
        probability = float(os.getenv("QUEUE_OVERLOAD_PROB", "0"))
    except ValueError:
        probability = 0.0
    probability = max(0.0, min(1.0, probability))
    return random.random() < probability
