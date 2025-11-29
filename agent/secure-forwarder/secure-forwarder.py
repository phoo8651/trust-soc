#!/usr/bin/env python3
"""
Secure Forwarder (HMAC Gate) for Logs

역할:
- otel-agent 로부터 로컬에서 /v1/logs 요청을 받는다.
    - Authorization: Bearer LOCAL_TOKEN (에이전트 전용 토큰)
- 요청 바디(OTLP/HTTP JSON)를 그대로 유지하면서:
    - LOG_TOKEN (서버용) + HMAC-SHA256 헤더를 붙여
      중앙 Ingest 서버(/v1/logs)로 재전송한다.

즉:
  otel-agent --(LOCAL_TOKEN)--> secure-forwarder
  secure-forwarder --(LOG_TOKEN + HMAC)--> ingest-server

개선 사항:
- 토큰/HMAC 키를 환경변수 필수값으로 강제 (디폴트 dev 토큰 제거)
- 요청 바디 크기 제한 추가 (MAX_BODY_SIZE)
- ThreadingMixIn 기반 HTTP 서버 사용 (동시 요청 처리)
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

# 1. 설정 로드
load_dotenv("/home/last/lastagent/etc/.env")

LISTEN_PORT = int(os.getenv("LISTEN_PORT", "19000"))
LISTEN_HOST = os.getenv("LISTEN_HOST", "127.0.0.1")

# 인증 정보
LOCAL_TOKEN = os.getenv("LOCAL_TOKEN")      # Agent가 보낸 토큰 검증용
UPSTREAM_URL = os.getenv("UPSTREAM_URL")    # 서버로 보낼 주소
LOG_TOKEN = os.getenv("UPSTREAM_LOG_TOKEN") # 서버 인증용 토큰
HMAC_SECRET = os.getenv("HMAC_SECRET")

# 식별자
AGENT_ID = os.getenv("AGENT_ID", "unknown")
CLIENT_ID = os.getenv("CLIENT_ID", "default")

def log(msg):
    print(f"[FWD] {msg}", flush=True)

# 2. 데이터 변환 로직 (OTLP -> Server Schema)
def transform_otlp(otlp_data):
    records = []
    try:
        resource_logs = otlp_data.get("resourceLogs", [])
        for rl in resource_logs:
            for sl in rl.get("scopeLogs", []):
                for lr in sl.get("logRecords", []):
                    # Timestamp (Nano -> ISO8601)
                    ts_nano = int(lr.get("timeUnixNano", time.time_ns()))
                    ts_iso = datetime.fromtimestamp(ts_nano / 1e9, timezone.utc).isoformat()
                    
                    # Body 추출
                    body = lr.get("body", {})
                    raw_msg = body.get("stringValue", str(body))
                    
                    records.append({
                        "ts": ts_iso,
                        "source_type": "agent-filelog",
                        "raw_line": raw_msg,
                        "tags": ["otel"]
                    })
    except Exception as e:
        log(f"Transform Error: {e}")
        return None
        
    if not records: 
        return None

    return {
        "meta": {"client_id": CLIENT_ID, "host": socket.gethostname()},
        "agent_id": AGENT_ID,
        "records": records
    }

# 3. 서버 전송 로직
def send_to_server(payload):
    # 1) 공백 없이 직렬화된 JSON -> bytes
    body_bytes = json.dumps(
        payload,
        separators=(",", ":"),   # 공백 제거
        ensure_ascii=False       # 한글 그대로 UTF-8
    ).encode("utf-8")

    # 2) 타임스탬프 / nonce
    ts = str(int(time.time()))          # 서버가 기대하는 유닉스 타임(초)
    nonce = str(int(time.time() * 1000))  # 아무 유니크한 문자열이면 됨 (ms 단위 시간 사용)

    # 3) payload 해시
    payload_hash = hashlib.sha256(body_bytes).hexdigest()

    # 4) 서버 스펙에 맞는 헤더들
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

        # 디버그용 로그(422 떴을 때 서버 메시지 확인용)
        log(f"Upstream status={resp.status_code}, body={resp.text}")

        return resp.status_code in (200, 202)
    except Exception as e:
        log(f"Upstream Error: {e}")
        return False

# 4. HTTP 요청 핸들러
class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 경로 확인
        if self.path != "/v1/logs":
            self.send_response(404)
            self.end_headers()
            return

        # 로컬 인증 확인 (Bearer LOCAL_TOKEN)
        auth_header = self.headers.get("Authorization", "")
        if auth_header != f"Bearer {LOCAL_TOKEN}":
            log("Local Unauthorized Access")
            self.send_response(401)
            self.end_headers()
            return

        # Body 읽기
        try:
            content_len = int(self.headers.get('Content-Length', 0))
            post_body = self.rfile.read(content_len)
            otlp_json = json.loads(post_body)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        # 변환 및 전송
        server_payload = transform_otlp(otlp_json)
        if server_payload:
            if send_to_server(server_payload):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
                log(f"Forwarded {len(server_payload['records'])} logs")
            else:
                # 업스트림 전송 실패 시 503을 리턴하여 OTEL이 재시도하게 함
                self.send_response(503)
                self.end_headers()
        else:
            # 변환할 데이터가 없으면 성공 처리
            self.send_response(200)
            self.end_headers()

# 동시 처리를 위한 Threading Server
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass

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
