#!/usr/bin/env python3
"""
Secure Forwarder (HMAC Gate) for Logs

역할:
- otel-agent 로부터 로컬에서 /v1/logs 요청을 받는다.
    - Authorization: Bearer LOCAL_TOKEN (에이전트 전용 토큰)
- 요청 바디(OTLP/HTTP JSON)를 파싱해서,
  솔루션 서버 ingest/logs 가 기대하는 형태로 변환하여 전송한다.

데이터 흐름:
  otel-agent --(LOCAL_TOKEN)--> secure-forwarder
  secure-forwarder --(LOG_TOKEN + 헤더들)--> ingest-server (/ingest/logs)

주의:
- UTF-8 (한글/이모지 포함) 바디를 bytes 로 보내지 않으면
  'latin-1 codec' 에러가 발생하므로, 반드시 json.dumps(..., ensure_ascii=False).encode("utf-8") 사용.
"""

import os
import json
import time
import hashlib
import socket
import requests

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime, timezone
from dotenv import load_dotenv

# ───────────────── 환경 변수 로드 ─────────────────

# ★ 여기 경로는 지금 구조에 맞춰서 /home/agent/etc/.env 로 변경 ★
ENV_PATH = "/home/agent/etc/.env"
load_dotenv(ENV_PATH)

LISTEN_PORT = int(os.getenv("LISTEN_PORT", "19000"))
LISTEN_HOST = os.getenv("LISTEN_HOST", "127.0.0.1")

# 로컬 인증 (otel-agent -> forwarder)
LOCAL_TOKEN = os.getenv("LOCAL_TOKEN")                # dev_agent_token

# 업스트림(솔루션 서버) 설정
UPSTREAM_URL = os.getenv("UPSTREAM_URL")              # http://192.168.67.131:30080/ingest/logs
LOG_TOKEN    = os.getenv("UPSTREAM_LOG_TOKEN")        # dev_log_token
HMAC_SECRET  = os.getenv("HMAC_SECRET")               # 현재는 사용 안함 (필요시 확장)

# 식별자
AGENT_ID  = os.getenv("AGENT_ID", "unknown")
CLIENT_ID = os.getenv("CLIENT_ID", "default")

# ───────────────── 유틸 ─────────────────

def log(msg: str) -> None:
    print(f"[FWD] {msg}", flush=True)

# ───────────────── OTLP → 서버 스키마 변환 ─────────────────

def transform_otlp(otlp_data: dict):
    """
    OTLP/HTTP JSON 구조에서 우리가 쓰는 ingest payload 형태로 변환.
    """
    records = []
    try:
        resource_logs = otlp_data.get("resourceLogs", [])
        for rl in resource_logs:
            for sl in rl.get("scopeLogs", []):
                for lr in sl.get("logRecords", []):
                    # 1) 타임스탬프
                    ts_nano = int(lr.get("timeUnixNano", time.time_ns()))
                    ts_iso = datetime.fromtimestamp(ts_nano / 1e9, timezone.utc).isoformat()

                    # 2) 메시지 본문
                    body = lr.get("body", {})
                    raw_msg = body.get("stringValue", str(body))

                    records.append({
                        "ts": ts_iso,
                        "source_type": "agent-filelog",
                        "raw_line": raw_msg,
                        "tags": ["otel"],
                    })
    except Exception as e:
        log(f"Transform Error: {e}")
        return None

    if not records:
        return None

    payload = {
        "meta": {
            "client_id": CLIENT_ID,
            "host": socket.gethostname(),
        },
        "agent_id": AGENT_ID,
        "records": records,
    }
    return payload

# ───────────────── 서버로 전송 ─────────────────

def send_to_server(payload: dict) -> bool:
    """
    ingest/logs 엔드포인트로 payload 전송.
    UTF-8 bytes 로 보내서 latin-1 문제를 피한다.
    """
    # 1) UTF-8 JSON 바이트
    body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    # 2) 타임스탬프 & 해시 (ingest 서버에서 검증)
    ts = str(int(time.time()))                      # unix timestamp (sec)
    p_hash = hashlib.sha256(body_bytes).hexdigest() # sha256 hex

    headers = {
        "Authorization": f"Bearer {LOG_TOKEN}",
        "Content-Type": "application/json",

        # IngestController 가 보는 헤더 이름
        "x-request-timestamp": ts,
        "x-payload-hash": p_hash,
        "x-client-id": CLIENT_ID,
    }

    try:
        resp = requests.post(UPSTREAM_URL, data=body_bytes, headers=headers, timeout=5)
        log(f"Upstream status: {resp.status_code}")
        if resp.status_code not in (200, 202):
            log(f"Upstream response body: {resp.text}")
        return resp.status_code in (200, 202)
    except Exception as e:
        log(f"Upstream Error: {e}")
        return False

# ───────────────── HTTP 핸들러 (/v1/logs) ─────────────────

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 1) 경로 체크
        if self.path != "/v1/logs":
            self.send_response(404)
            self.end_headers()
            return

        # 2) 로컬 인증 (Bearer LOCAL_TOKEN)
        auth_header = self.headers.get("Authorization", "")
        if auth_header != f"Bearer {LOCAL_TOKEN}":
            log("Local Unauthorized Access")
            self.send_response(401)
            self.end_headers()
            return

        # 3) 요청 바디 읽기
        try:
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len)
            otlp_json = json.loads(post_body)
        except Exception as e:
            log(f"Bad Request body: {e}")
            self.send_response(400)
            self.end_headers()
            return

        # 4) 변환 및 업스트림 전송
        server_payload = transform_otlp(otlp_json)
        if server_payload:
            if send_to_server(server_payload):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
                log(f"Forwarded {len(server_payload['records'])} logs")
            else:
                # 업스트림 장애 -> OTEL 이 재시도하도록 503
                self.send_response(503)
                self.end_headers()
        else:
            # 변환할 레코드가 없으면 그냥 OK
            self.send_response(200)
            self.end_headers()

    # noisy 로그 줄이기
    def log_message(self, format, *args):
        return

# ───────────────── Threaded 서버 ─────────────────

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def main():
    server = ThreadedHTTPServer((LISTEN_HOST, LISTEN_PORT), RequestHandler)
    log(f"Secure Forwarder listening on {LISTEN_HOST}:{LISTEN_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

if __name__ == "__main__":
    main()
