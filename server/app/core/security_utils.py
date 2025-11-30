import hashlib
import hmac
from datetime import datetime, timezone, timedelta

MAX_SKEW_SEC = 300


def verify_timestamp(ts_str: str):
    """
    요청 타임스탬프(ts_str)가 유효한지 검증합니다.
    서버의 로컬 타임존(KST 등)과 관계없이 UTC 기준으로 변환하여 비교합니다.
    """
    if not ts_str:
        raise ValueError("Missing timestamp")

    try:
        # 1. ISO 포맷 파싱 (Z를 +00:00으로 치환하여 파싱 호환성 확보)
        req_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

        # 2. Timezone 정보가 없는 경우(Naive), UTC로 가정하고 설정
        if req_time.tzinfo is None:
            req_time = req_time.replace(tzinfo=timezone.utc)

        # 3. [핵심] 입력받은 시간을 강제로 UTC로 변환
        # (만약 입력이 KST(+09:00)였다면, 자동으로 -9시간 되어 UTC로 바뀜)
        req_time_utc = req_time.astimezone(timezone.utc)

    except ValueError:
        raise ValueError("Invalid timestamp format")

    # 4. 현재 서버 시간도 UTC로 가져옴 (서버가 KST여도 UTC 시간이 나옴)
    now_utc = datetime.now(timezone.utc)

    # 5. 시간 차이 계산
    delta = abs((now_utc - req_time_utc).total_seconds())

    if delta > MAX_SKEW_SEC:
        raise ValueError(
            f"Timestamp skew too large: {int(delta)}s (Server: {now_utc}, Req: {req_time_utc})"
        )


def verify_payload_hash(body: bytes, header_hash: str):
    if not header_hash:
        raise ValueError("Missing hash header")
    try:
        algo, hexval = header_hash.split(":", 1)
    except ValueError:
        raise ValueError("Invalid hash format")

    if algo.lower() != "sha256":
        raise ValueError("Unsupported algo")

    computed = hashlib.sha256(body).hexdigest()
    if not hmac.compare_digest(computed, hexval.lower()):
        raise ValueError("Payload hash mismatch")
