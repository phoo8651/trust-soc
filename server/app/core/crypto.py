import os
import base64
import json
from typing import Any, Dict, Optional
from .config import settings

# AES-GCM
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

# Ed25519
try:
    from nacl.signing import SigningKey
except ImportError:
    SigningKey = None

class Encryptor:
    def __init__(self):
        self._aes = None
        if settings.AES_GCM_KEY_HEX and AESGCM:
            try:
                self._aes = AESGCM(bytes.fromhex(settings.AES_GCM_KEY_HEX).ljust(32, b'\0'))
            except: pass
            
    def encrypt(self, val: str) -> Optional[str]:
        if not self._aes or not val: return None
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, val.encode(), None)
        return base64.b64encode(nonce + ct).decode('ascii')

encryptor = Encryptor()

_JOB_KEY = None
if SigningKey and os.getenv("JOB_SIGNING_KEY_ED25519"):
    try: _JOB_KEY = SigningKey(bytes.fromhex(os.getenv("JOB_SIGNING_KEY_ED25519")))
    except: pass

def compute_job_signature(job_type: str, args: Dict) -> str:
    payload = {"type": job_type, "args": args or {}}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    
    if _JOB_KEY:
        return "ed25519:" + _JOB_KEY.sign(canonical.encode()).signature.hex()
        
    import hmac, hashlib
    digest = hmac.new(settings.JOB_SIGNING_SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return f"cmdsig:{digest}"