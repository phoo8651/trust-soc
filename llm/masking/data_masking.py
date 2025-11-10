# llm/masking/data_masking.py

import re
import hashlib

def hash_text(value: str, length: int = 6) -> str:
    """짧은 해시 생성 (SHA256 기반)"""
    return hashlib.sha256(value.encode()).hexdigest()[:length]

def mask_ip(text: str) -> str:
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ipv6_pattern = re.compile(r'\b(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\b')

    text = ipv4_pattern.sub(lambda m: f"<IP_REDACTED:{hash_text(m.group())}>", text)
    text = ipv6_pattern.sub(lambda m: f"<IP_REDACTED:{hash_text(m.group())}>", text)
    return text

def mask_email(text: str) -> str:
    email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
    return email_pattern.sub(lambda m: f"<EMAIL_REDACTED:{hash_text(m.group())}>", text)

def mask_user_account(text: str) -> str:
    user_pattern = re.compile(r'\buser[:=]\s*([a-zA-Z0-9_]+)\b', re.IGNORECASE)
    return user_pattern.sub(lambda m: f"user={m.group(1)[0]}***", text)

def mask_secret_tokens(text: str) -> str:
    token_pattern = re.compile(r'(?:api[_-]?key|token|password|secret)[=:]\s*([\w-]{8,})', re.IGNORECASE)
    return token_pattern.sub(lambda m: f"<SECRET_REDACTED:{len(m.group(1))}>", text)

def mask_rrn(text: str) -> str:
    rrn_pattern = re.compile(r'\b\d{6}-[1-4]\d{6}\b')
    return rrn_pattern.sub("<RRN_REDACTED>", text)

def mask_all(input_text: str):
    """모든 규칙을 적용한 통합 마스킹, 두 개의 값 반환"""
    masked = input_text
    masked = mask_ip(masked)
    masked = mask_email(masked)
    masked = mask_user_account(masked)
    masked = mask_secret_tokens(masked)
    masked = mask_rrn(masked)
    # 두 번째 값은 로깅이나 추후 확장용 빈 dict
    return masked, {}


def validate_masked(text: str) -> bool:
    """
    마스킹 규칙이 적용되었는지 검증
    """
    patterns = [
        r"<IP_REDACTED:\w+>",
        r"<EMAIL_REDACTED:\w+>",
        r"user=.\*\*\*",
        r"<SECRET_REDACTED:\d+>",
        r"<RRN_REDACTED>"
    ]
    return not any(re.search(p, text) for p in patterns)