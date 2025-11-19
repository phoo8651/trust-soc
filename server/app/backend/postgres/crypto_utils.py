import base64
import os
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  
    AESGCM = None  


class FieldEncryptor:
    def __init__(self):
        key_hex = os.getenv("AES_GCM_KEY_HEX")
        self._aes: Optional["AESGCM"] = None
        if key_hex and AESGCM:
            key_bytes = bytes.fromhex(key_hex)
            if len(key_bytes) in (16, 24, 32):
                self._aes = AESGCM(key_bytes.ljust(32, b"\x00"))
        self._enabled = bool(self._aes)

    def encrypt(self, value: str) -> Optional[str]:
        if not self._enabled or not self._aes:
            return None
        nonce = os.urandom(12)
        ciphertext = self._aes.encrypt(nonce, value.encode("utf-8"), None)
        return base64.b64encode(nonce + ciphertext).decode("ascii")


_ENCRYPTOR = FieldEncryptor()


def maybe_encrypt(value: str) -> Optional[str]:
    return _ENCRYPTOR.encrypt(value)
