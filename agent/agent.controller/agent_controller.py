"""
Agent Controller
역할:
- 주기적으로 Control Server(API)를 폴링하여
  해당 에이전트(agent_id)에 대한 명령을 가져온다.
- 지원 명령:
    - ping
    - reload_agent        : systemctl restart otel-agent
    - update_config       : remote 설정 파일 갱신 후 reload
- 각 명령 처리 후 /ack API로 결과를 보고한다.
보안:
- Bearer 토큰 + (옵션) HMAC-SHA256 서명
- HMAC_SECRET 이 설정된 경우:
    GET /commands, POST /ack 요청에
    X-Request-Timestamp, X-Nonce, X-Idempotency-Key,
    X-Payload-Hash, X-Signature 헤더를 추가.

개선 사항:
- CONTROLLER_URL, AGENT_TOKEN 을 필수 환경변수로 강제
- update_config 의 otel_fragment 크기 제한 (MAX_FRAGMENT_SIZE)
- HMAC_SECRET 미설정 시 경고 로그
"""

import os
import time
import json
import socket
import subprocess
from typing import Any, Dict, List

import requests
import hmac
import hashlib
import uuid
from dotenv import load_dotenv

# ─────────────────────────────────────────────────────────────
# 1. 환경 변수 로드
# ─────────────────────────────────────────────────────────────
# 실제 .env 파일 경로를 지정합니다.
load_dotenv("/home/last/lastagent/etc/.env")


def require_env(name: str) -> str:
    """필수 환경 변수가 없으면 프로세스를 종료합니다."""
    value = os.getenv(name)
    if not value:
        print(f"[FATAL] 필수 환경변수 {name}가 설정되지 않았습니다.")
        exit(1)
    return value


# 식별자 설정
AGENT_ID = require_env("AGENT_ID")
CLIENT_ID = require_env("CLIENT_ID")  # 서버의 Tenant Middleware 통과용

# 서버 접속 정보
CONTROLLER_URL = require_env("CONTROLLER_URL")  # 예: http://192.168.x.x:8000
AGENT_TOKEN = require_env("AGENT_TOKEN")  # Bearer Token
HMAC_SECRET = os.getenv("HMAC_SECRET")  # 서명용 비밀키 (옵션이지만 권장)

# 설정값
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "10"))
MAX_FRAGMENT_SIZE = int(os.getenv("MAX_FRAGMENT_SIZE", str(200 * 1024)))


def log(msg: str) -> None:
    """로그 출력 유틸리티"""
    print(f"[CTRL][{AGENT_ID}] {msg}", flush=True)


# ─────────────────────────────────────────────────────────────
# 2. 보안 헤더 생성 (서버의 auth_core.py / security_utils.py 대응)
# ─────────────────────────────────────────────────────────────
def make_signed_headers(method: str, path: str, body_bytes: bytes) -> Dict[str, str]:
    """
    서버가 요구하는 인증 헤더와 무결성 검증 헤더를 생성합니다.
    """
    headers = {
        "Authorization": f"Bearer {AGENT_TOKEN}",
        "Content-Type": "application/json",
        "X-Client-Id": CLIENT_ID,  # [중요] Multi-tenancy 식별자
        "X-Agent-Id": AGENT_ID,
    }

    # HMAC 서명 생성 (Replay Attack 방지 및 무결성 검증)
    ts = str(int(time.time()))
    nonce = str(uuid.uuid4())
    # body가 없으면 빈 bytes로 해시
    payload_hash = hashlib.sha256(body_bytes or b"").hexdigest()

    headers.update(
        {
            "X-Request-Timestamp": ts,
            "X-Nonce": nonce,
            "X-Payload-Hash": f"sha256:{payload_hash}",
        }
    )

    if HMAC_SECRET:
        # 서명 메시지 구성: METHOD + PATH + TS + NONCE + HASH
        msg = "\n".join([method.upper(), path, ts, nonce, payload_hash])
        sig = hmac.new(
            HMAC_SECRET.encode("utf-8"),
            msg.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        headers["X-Signature"] = sig

    return headers


# ─────────────────────────────────────────────────────────────
# 3. 명령 가져오기 (Polling)
# ─────────────────────────────────────────────────────────────
def fetch_commands() -> List[Dict[str, Any]]:
    """
    서버의 Job Queue에서 대기 중인 명령을 가져옵니다.
    Endpoint: GET /agent/jobs/pull
    """
    path = "/agent/jobs/pull"
    url = f"{CONTROLLER_URL}{path}"

    # GET 요청이므로 Body는 없음
    headers = make_signed_headers("GET", path, b"")
    params = {"agent_id": AGENT_ID}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
    except Exception as e:
        log(f"네트워크 오류 (fetch_commands): {e}")
        return []

    if resp.status_code == 204:  # No Content
        return []

    if resp.status_code != 200:
        log(f"명령 조회 실패: status={resp.status_code}, body={resp.text[:100]}")
        return []

    try:
        data = resp.json()
        # 서버 응답 구조: {"jobs": [...]}
        cmds = data.get("jobs", [])
        if cmds:
            log(f"명령 {len(cmds)}개 수신됨.")
        return cmds
    except Exception as e:
        log(f"JSON 파싱 오류: {e}")
        return []


# ─────────────────────────────────────────────────────────────
# 4. 결과 보고 (Ack)
# ─────────────────────────────────────────────────────────────
def ack_command(job_id: str, status: str, message: str = "") -> None:
    """
    명령 수행 결과를 서버에 보고합니다.
    Endpoint: POST /agent/jobs/result
    """
    path = "/agent/jobs/result"
    url = f"{CONTROLLER_URL}{path}"

    # 서버의 JobResultRequest 스키마에 맞춤
    payload = {
        "job_id": job_id,
        "agent_id": AGENT_ID,
        "success": (status == "ok"),
        "output_snippet": message[:1000],  # 너무 길면 자름
        "error_detail": message if status != "ok" else None,
    }

    body = json.dumps(payload).encode("utf-8")
    headers = make_signed_headers("POST", path, body)

    try:
        resp = requests.post(url, headers=headers, data=body, timeout=5)
        if resp.status_code != 200:
            log(f"결과 보고 실패 ({job_id}): status={resp.status_code}")
    except Exception as e:
        log(f"결과 보고 중 오류 ({job_id}): {e}")


# ─────────────────────────────────────────────────────────────
# 5. 명령 실행 로직
# ─────────────────────────────────────────────────────────────
def apply_update_config(args: Dict[str, Any]) -> str:
    """원격 설정 파일 업데이트 및 에이전트 리로드"""
    fragment = args.get("otel_fragment")
    if not fragment:
        return "설정 내용(otel_fragment)이 없습니다."

    if len(fragment.encode("utf-8")) > MAX_FRAGMENT_SIZE:
        return f"설정 파일이 너무 큽니다. (Max {MAX_FRAGMENT_SIZE} bytes)"

    remote_dir = "/etc/secure-log-agent/remote.d"
    remote_cfg = os.path.join(remote_dir, "remote.yaml")

    try:
        os.makedirs(remote_dir, exist_ok=True)
        with open(remote_cfg, "w") as f:
            f.write(fragment)

        # 설정 적용을 위해 서비스 리로드
        subprocess.run(["systemctl", "reload", "otel-agent.service"], check=True)
        return f"설정 업데이트 및 리로드 완료 ({remote_cfg})"
    except Exception as e:
        raise RuntimeError(f"설정 적용 실패: {e}")


def apply_reload_agent() -> str:
    """에이전트 서비스 재시작"""
    subprocess.run(["systemctl", "restart", "otel-agent.service"], check=True)
    return "otel-agent 서비스 재시작 완료"


def apply_block_ip(args: Dict[str, Any]) -> str:
    """(LLM 자동 대응) IP 차단 명령 수행"""
    target_ip = args.get("ip") or args.get("src_ip")
    if not target_ip:
        return "차단할 IP 정보가 없습니다."

    # 예시: iptables를 사용한 차단 (root 권한 필요)
    # 실제 운영 시에는 화이트리스트 체크 등 안전장치 필요
    cmd = ["iptables", "-A", "INPUT", "-s", target_ip, "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True)
        return f"IP 차단 적용됨: {target_ip}"
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"IP 차단 실패: {e}")


def execute_job(job: Dict[str, Any]) -> str:
    """Job 타입에 따른 분기 처리"""
    job_type = job.get(
        "type"
    )  # 서버: job_type 필드 (API 응답은 type으로 올 수 있음, 확인 필요)
    # 서버 응답 구조: {"job_id": "...", "type": "...", "args": {...}}
    if not job_type:
        job_type = job.get("job_type")  # 필드명 호환성

    args = job.get("args") or {}

    if job_type == "ping":
        return "pong"
    elif job_type == "RULES_RELOAD" or job_type == "reload_agent":
        return apply_reload_agent()
    elif job_type == "UPDATE_CONFIG" or job_type == "update_config":
        return apply_update_config(args)
    elif job_type == "BLOCK_IP":
        return apply_block_ip(args)
    else:
        return f"알 수 없는 명령 타입: {job_type}"


# ─────────────────────────────────────────────────────────────
# 6. 메인 루프
# ─────────────────────────────────────────────────────────────
def main() -> None:
    log(
        f"Agent Controller 시작됨. (Server: {CONTROLLER_URL}, Agent: {AGENT_ID}, Client: {CLIENT_ID})"
    )

    if not HMAC_SECRET:
        log("[WARN] HMAC_SECRET가 설정되지 않았습니다. 보안 수준이 낮습니다.")

    while True:
        jobs = fetch_commands()

        for job in jobs:
            job_id = job.get("job_id")
            try:
                log(f"명령 실행 중: {job.get('type')} (ID: {job_id})")
                result_msg = execute_job(job)
                log(f"명령 성공: {result_msg}")
                ack_command(job_id, "ok", result_msg)
            except Exception as e:
                err_msg = f"명령 실행 실패: {str(e)}"
                log(err_msg)
                ack_command(job_id, "error", err_msg)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
