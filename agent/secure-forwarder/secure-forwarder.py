#!/usr/bin/env python3
"""
Secure Forwarder (HTTP Proxy for Logs)
- 역할: OTEL Agent의 로그를 받아 솔루션 서버의 /ingest/logs 로 전송
- 경로: /home/last/lastagent/forwarder/secure-forwarder.py
"""

import os
import json
import time
import hashlib
import hmac
import requests
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime, timezone
from dotenv import load_dotenv

# 1. 환경 변수 로드
load_dotenv("/home/last/lastagent/etc/.env")

# 로컬 리슨 설정 (OTEL Agent가 보낼 곳)
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 19000

# 인증 및 서버 정보
LOCAL_TOKEN = os.getenv("LOCAL_TOKEN")  # 로컬 인증용
UPSTREAM_URL = os.getenv("UPSTREAM_URL")  # ★ 핵심: .../ingest/logs 주소
LOG_TOKEN = os.getenv("UPSTREAM_LOG_TOKEN")  # 서버 인증 토큰
CLIENT_ID = os.getenv("CLIENT_ID", "default")
AGENT_ID = os.getenv("AGENT_ID", "unknown")


def log(msg):
    print(f"[FWD] {msg}", flush=True)


# 2. 데이터 변환 (OTLP -> IngestRequest 스키마)
def transform_otlp(otlp_data):
    server_records = []
    try:
        resource_logs = otlp_data.get("resourceLogs", [])
        for rl in resource_logs:
            for sl in rl.get("scopeLogs", []):
                for lr in sl.get("logRecords", []):
                    # 타임스탬프 변환
                    ts_nano = int(lr.get("timeUnixNano", time.time_ns()))
                    ts_iso = datetime.fromtimestamp(
                        ts_nano / 1e9, timezone.utc
                    ).isoformat()

                    # 로그 본문 추출
                    body = lr.get("body", {})
                    raw_msg = body.get("stringValue", str(body))

                    server_records.append(
                        {
                            "ts": ts_iso,
                            "source_type": "agent-filelog",
                            "raw_line": raw_msg,
                            "tags": ["otel"],
                        }
                    )
    except Exception as e:
        log(f"Transform Error: {e}")
        return None

    if not server_records:
        return None

    # 서버가 요구하는 IngestRequest 포맷
    return {
        "meta": {"client_id": CLIENT_ID, "host": socket.gethostname()},
        "agent_id": AGENT_ID,
        "records": server_records,
    }


# 3. 서버(/ingest/logs)로 전송
def forward_to_server(payload):
    # JSON 공백 제거 (해시 일관성 유지)
    body_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    body_bytes = body_json.encode("utf-8")

    ts = datetime.now(timezone.utc).isoformat()
    nonce = str(time.time())
    # Payload 무결성 검증용 해시
    payload_hash = hashlib.sha256(body_bytes).hexdigest()

    headers = {
        "Authorization": f"Bearer {LOG_TOKEN}",
        "Content-Type": "application/json",
        "X-Client-Id": CLIENT_ID,
        "X-Request-Timestamp": ts,
        "X-Payload-Hash": f"sha256:{payload_hash}",
        "X-Nonce": nonce,
        "X-Idempotency-Key": hashlib.md5((ts + nonce).encode()).hexdigest(),
    }

    try:
        # ★ 여기서 UPSTREAM_URL (/ingest/logs)로 전송합니다.
        resp = requests.post(UPSTREAM_URL, data=body_bytes, headers=headers, timeout=5)

        if resp.status_code in [200, 202]:
            return True
        else:
            log(f"Server Error ({resp.status_code}): {resp.text}")
            return False
    except Exception as e:
        log(f"Network Error: {e}")
        return False


# 4. HTTP 요청 핸들러
class LogHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 로컬 인증 확인
        if self.headers.get("Authorization", "") != f"Bearer {LOCAL_TOKEN}":
            self.send_response(401)
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length)
            otlp_json = json.loads(data)

            # 변환 및 전송
            server_payload = transform_otlp(otlp_json)

            if server_payload:
                if forward_to_server(server_payload):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"status":"ok"}')
                    log(
                        f"Forwarded {len(server_payload['records'])} logs to /ingest/logs"
                    )
                else:
                    self.send_response(503)
                    self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()

        except Exception as e:
            log(f"Handler Error: {e}")
            self.send_response(400)
            self.end_headers()

    def log_message(self, format, *args):
        return


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main():
    log(f"Secure Forwarder listening on {LISTEN_HOST}:{LISTEN_PORT}")
    log(f"Target Server URL: {UPSTREAM_URL}")  # 시작 시 타겟 URL 확인용 로그
    server = ThreadedHTTPServer((LISTEN_HOST, LISTEN_PORT), LogHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
