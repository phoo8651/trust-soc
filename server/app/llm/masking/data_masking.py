# llm/masking/data_masking.py
import re
import hashlib

def hash_text(value: str, length: int = 6) -> str:
    """문자열을 SHA256 해싱 후 앞 length글자만 사용"""
    return hashlib.sha256(value.encode()).hexdigest()[:length]


def mask_ip(text: str) -> str:
    """IPv4 / IPv6 자동 마스킹"""
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ipv6_pattern = re.compile(r'\b(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\b')
    text = ipv4_pattern.sub(lambda m: f"<IP_REDACTED:{hash_text(m.group())}>", text)
    text = ipv6_pattern.sub(lambda m: f"<IP_REDACTED:{hash_text(m.group())}>", text)
    return text


def mask_email(text: str) -> str:
    """이메일 마스킹"""
    email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
    return email_pattern.sub(lambda m: f"<EMAIL_REDACTED:{hash_text(m.group())}>", text)


def mask_user_account(text: str) -> str:
    """user=<account> 패턴 마스킹"""
    user_pattern = re.compile(r'\buser[:=]\s*([a-zA-Z0-9_]+)\b', re.IGNORECASE)
    return user_pattern.sub(lambda m: f"user={m.group(1)[0]}***", text)


def mask_secret_tokens(text: str) -> str:
    """API KEY, TOKEN, PASSWORD 등 민감 비밀값 마스킹"""
    token_pattern = re.compile(r'(?:api[_-]?key|token|password|secret)[=:]\s*([\w-]{8,})', re.IGNORECASE)
    return token_pattern.sub(lambda m: f"<SECRET_REDACTED:{len(m.group(1))}>", text)


def mask_rrn(text: str) -> str:
    """주민등록번호"""
    rrn_pattern = re.compile(r'\b\d{6}-[1-4]\d{6}\b')
    return rrn_pattern.sub("<RRN_REDACTED>", text)


def mask_all(input_text: str):
    """모든 민감 정보 자동 마스킹"""
    masked = input_text
    masked = mask_ip(masked)
    masked = mask_email(masked)
    masked = mask_user_account(masked)
    masked = mask_secret_tokens(masked)
    masked = mask_rrn(masked)
    return masked, {}  # meta={}


def validate_masked(text: str) -> bool:
    """
    마스킹되지 않은 민감 정보가 남아있는지 검사
    - 남아 있으면 False
    """
    sensitive_raw_patterns = [
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',      
        r'[\w\.-]+@[\w\.-]+\.\w+',           
        r'\buser[:=]\s*[a-zA-Z0-9_]+\b',     
        r'(?:api[_-]?key|token|password|secret)[=:]\s*[\w-]{8,}',  
        r'\b\d{6}-[1-4]\d{6}\b'
    ]

    for p in sensitive_raw_patterns:
        if re.search(p, text, flags=re.IGNORECASE):
            return False  # 위험
    
    return True  # 안전
