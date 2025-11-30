#!/usr/bin/env python3
# /home/last/lastagent/forwarder/secure-forwarder.py

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

# 로컬 리슨 설정
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 19000

# 인증 및 서버 정보
LOCAL_TOKEN = os.getenv("LOCAL_TOKEN")  # OTEL -> Forwarder 인증용
UPSTREAM_URL = os.getenv("UPSTREAM_URL")  # Server 주소
LOG_TOKEN = os.getenv("UPSTREAM_LOG_TOKEN")  # Server 인증용 토큰
CLIENT_ID = os.getenv("CLIENT_ID", "default")
AGENT_ID = os.getenv("AGENT_ID", "unknown")


def log(msg):
    print(f"[FWD] {msg}", flush=True)


# 2. 데이터 변환 (OTLP JSON -> Server Format)
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

    return {
        "meta": {"client_id": CLIENT_ID, "host": socket.gethostname()},
        "agent_id": AGENT_ID,
        "records": server_records,
    }


# 3. 솔루션 서버로 전송
def forward_to_server(payload):
    # JSON 공백 제거하여 해시 일관성 유지
    body_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    body_bytes = body_json.encode("utf-8")

    ts = datetime.now(timezone.utc).isoformat()
    nonce = str(time.time())
    payload_hash = hashlib.sha256(body_bytes).hexdigest()

    # 헤더 구성
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
        resp = requests.post(UPSTREAM_URL, data=body_bytes, headers=headers, timeout=5)
        if resp.status_code in [200, 202]:
            return True
        else:
            log(f"Server Error: {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        log(f"Network Error: {e}")
        return False


# 4. HTTP 요청 핸들러 (OTEL 데이터를 받음)
class LogHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 로컬 토큰 검증
        auth_header = self.headers.get("Authorization", "")
        if auth_header != f"Bearer {LOCAL_TOKEN}":
            self.send_response(401)
            self.end_headers()
            return

        try:
            # 데이터 수신
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length)
            otlp_json = json.loads(data)

            # 변환
            server_payload = transform_otlp(otlp_json)

            if server_payload:
                # 서버로 전송 시도
                if forward_to_server(server_payload):
                    # 성공: OTEL에게 200 OK (잘 받았음)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"status":"ok"}')
                    log(f"Forwarded {len(server_payload['records'])} logs")
                else:
                    # 실패: OTEL에게 503 (나중에 다시 보내라)
                    self.send_response(503)
                    self.end_headers()
            else:
                # 변환할 데이터 없음 (빈 로그)
                self.send_response(200)
                self.end_headers()

        except Exception as e:
            log(f"Handler Error: {e}")
            self.send_response(400)
            self.end_headers()

    # 기본 로그 출력 끄기
    def log_message(self, format, *args):
        return


# 멀티스레드 서버
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main():
    log(f"Starting Secure Forwarder on {LISTEN_HOST}:{LISTEN_PORT}")
    server = ThreadedHTTPServer((LISTEN_HOST, LISTEN_PORT), LogHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
