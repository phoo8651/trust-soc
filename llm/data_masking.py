# llm_advisor/data_masking.py
import re
from typing import Tuple

# 정규식 패턴들 (간단/실용적 버전)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
HEX_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
API_KEY_RE = re.compile(r"\b(?:api_key|apikey|secret|token|bearer)[=: ]?([A-Za-z0-9\-\._]+)\b", flags=re.IGNORECASE)
URL_PARAM_RE = re.compile(r"([?&][^=&#]+)=([^\s&#]+)")

def mask_all(text: str, preserve_some: bool = False) -> Tuple[str, bool]:
    """
    텍스트 내 민감 정보 마스킹
    returns (masked_text, was_masked_flag)
    """
    orig = text
    masked = text

    # API keys / tokens (capture value, replace with [REDACTED_TOKEN])
    masked = API_KEY_RE.sub(lambda m: m.group(0).replace(m.group(1), "[REDACTED_TOKEN]"), masked)

    # 이메일
    masked = EMAIL_RE.sub("[EMAIL]", masked)

    # IPv4
    masked = IPV4_RE.sub("[IP]", masked)

    # hex-like hashes (sha1/sha256 etc.)
    masked = HEX_HASH_RE.sub("[HASH]", masked)

    # URL param values -> keep keys but mask values (e.g. ?token=[REDACTED])
    def _mask_param(m):
        return f"{m.group(1)}=[REDACTED]"
    masked = URL_PARAM_RE.sub(_mask_param, masked)

    return masked, (masked != orig)

# 단위테스트용 간단 함수
if __name__ == "__main__":
    t = "User login from 1.2.3.4 email: foo@example.com token=abcd1234abcd1234abcd1234"
    print(mask_all(t))
