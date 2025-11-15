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


def require_env(name: str) -> str:
    """필수 환경변수 로딩. 없으면 FATAL 종료."""
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"[FATAL] required env {name} is not set")
    return value


def get_agent_id() -> str:
    """AGENT_ID 환경변수 우선, 없으면 hostname 사용."""
    env_id = os.getenv("AGENT_ID")
    if env_id:
        return env_id
    return socket.gethostname()


AGENT_ID = get_agent_id()
CONTROLLER_URL = require_env("CONTROLLER_URL")
AGENT_TOKEN = require_env("AGENT_TOKEN")
HMAC_SECRET = os.getenv("HMAC_SECRET")  # 없으면 HMAC 비활성
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "10"))

# update_config 시 최대 허용 otel_fragment 크기 (bytes)
MAX_FRAGMENT_SIZE = int(os.getenv("MAX_FRAGMENT_SIZE", str(200 * 1024)))  # 200KB 기본

BASE_HEADERS = {
    "Authorization": f"Bearer {AGENT_TOKEN}",
    "Content-Type": "application/json",
    "X-Agent-Id": AGENT_ID,
}


def log(msg: str) -> None:
    print(f"[CTRL][{AGENT_ID}] {msg}", flush=True)


def make_signed_headers(method: str, path: str, body_bytes: bytes) -> Dict[str, str]:
    """
    Control API 요청용 헤더 생성.
    - Base: Bearer + X-Agent-Id
    - HMAC_SECRET 이 설정된 경우 추가 보안 헤더 포함.
    """
    headers = dict(BASE_HEADERS)

    if not HMAC_SECRET:
        return headers

    ts = str(int(time.time()))
    nonce = str(uuid.uuid4())
    idem = str(uuid.uuid4())

    payload_hash = hashlib.sha256(body_bytes or b"").hexdigest()
    msg = "\n".join(
        [method.upper(), path, ts, nonce, payload_hash]
    )
    sig = hmac.new(
        HMAC_SECRET.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    headers.update(
        {
            "X-Request-Timestamp": ts,
            "X-Nonce": nonce,
            "X-Idempotency-Key": idem,
            "X-Payload-Hash": payload_hash,
            "X-Signature": sig,
        }
    )
    return headers


def fetch_commands() -> List[Dict[str, Any]]:
    """Control Server에서 pending 명령 목록 조회."""
    path = f"/api/agents/{AGENT_ID}/commands"
    url = f"{CONTROLLER_URL}{path}"
    body = b""  # GET 이므로 바디 없음
    headers = make_signed_headers("GET", path, body)

    try:
        resp = requests.get(url, headers=headers, timeout=5)
    except Exception as e:
        log(f"fetch_commands error: {e}")
        return []

    if resp.status_code == 204:
        return []

    if resp.status_code != 200:
        log(f"fetch_commands unexpected status={resp.status_code}, body={resp.text[:200]}")
        return []

    try:
        data = resp.json()
    except Exception as e:
        log(f"fetch_commands invalid json: {e}")
        return []

    cmds = data.get("commands", [])
    if cmds:
        log(f"fetched {len(cmds)} command(s)")
    return cmds


def ack_command(cmd_id: str, status: str, message: str = "") -> None:
    """명령 처리 결과를 Control Server에 보고."""
    path = f"/api/agents/{AGENT_ID}/commands/{cmd_id}/ack"
    url = f"{CONTROLLER_URL}{path}"
    payload = {"status": status, "message": message}
    body = json.dumps(payload).encode("utf-8")
    headers = make_signed_headers("POST", path, body)

    try:
        resp = requests.post(url, headers=headers, data=body, timeout=5)
        if resp.status_code != 200:
            log(f"ack {cmd_id} failed: status={resp.status_code}, body={resp.text[:200]}")
    except Exception as e:
        log(f"ack {cmd_id} error: {e}")


def apply_update_config(payload: Dict[str, Any]) -> str:
    """update_config 명령 처리."""
    fragment = payload.get("otel_fragment")
    if not fragment:
        return "no otel_fragment provided"

    fragment_bytes = fragment.encode("utf-8")
    if len(fragment_bytes) > MAX_FRAGMENT_SIZE:
        return f"otel_fragment too large (> {MAX_FRAGMENT_SIZE} bytes)"

    remote_dir = "/etc/secure-log-agent/remote.d"
    remote_cfg = os.path.join(remote_dir, "remote.yaml")

    os.makedirs(remote_dir, exist_ok=True)

    with open(remote_cfg, "w") as f:
        f.write(fragment)

    subprocess.run(["systemctl", "reload", "otel-agent.service"], check=False)
    return f"updated {remote_cfg} and reloaded otel-agent"


def apply_reload_agent() -> str:
    """otel-agent 재시작."""
    subprocess.run(["systemctl", "restart", "otel-agent.service"], check=False)
    return "restarted otel-agent"


def apply_ping() -> str:
    """헬스 확인용 ping."""
    return "pong"


def apply_command(cmd: Dict[str, Any]) -> str:
    """단일 명령 실행."""
    ctype = cmd.get("type")
    payload = cmd.get("payload") or {}

    if ctype == "ping":
        return apply_ping()
    elif ctype == "reload_agent":
        return apply_reload_agent()
    elif ctype == "update_config":
        return apply_update_config(payload)
    else:
        return f"unknown command type: {ctype}"


def main() -> None:
    if not HMAC_SECRET:
        log("[WARN] HMAC_SECRET is not set. Control traffic is only protected by Bearer token.")

    log(
        f"Agent Controller started. controller={CONTROLLER_URL}, "
        f"interval={POLL_INTERVAL}s, hmac={'on' if HMAC_SECRET else 'off'}, "
        f"max_fragment={MAX_FRAGMENT_SIZE} bytes"
    )

    while True:
        cmds = fetch_commands()
        for cmd in cmds:
            cmd_id = cmd.get("id", "")
            try:
                result_msg = apply_command(cmd)
                log(f"cmd {cmd_id} success: {result_msg}")
                ack_command(cmd_id, "ok", result_msg)
            except Exception as e:
                err = f"cmd {cmd_id} error: {e}"
                log(err)
                ack_command(cmd_id, "error", err)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
