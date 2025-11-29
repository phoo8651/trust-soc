#!/usr/bin/env python3
"""
Secure Forwarder (HMAC Gate) for Logs

- 로컬에서 /v1/logs(Authorization: Bearer LOCAL_TOKEN) 를 받고
- OTLP JSON → 서버 스키마로 변환 후
- /ingest/logs 로 JWT + 헤더 세팅해서 전송
"""

import os
import json
import time
import hashlib
import requests
import socket

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime, timezone
from dotenv import load_dotenv

# 1. 설정 로드 (.env)
load_dotenv("/home/last/lastagent/etc/.env")

LISTEN_PORT = int(os.getenv("LISTEN_PORT", "19000"))
LISTEN_HOST = os.getenv("LISTEN_HOST", "127.0.0.1")

LOCAL_TOKEN   = os.getenv("LOCAL_TOKEN")
UPSTREAM_URL  = os.getenv("UPSTREAM_URL")
LOG_TOKEN     = os.getenv("UPSTREAM_LOG_TOKEN")   # JWT
HMAC_SECRET   = os.getenv("HMAC_SECRET")

CLIENT_ID     = os.getenv("CLIENT_ID", "default")
AGENT_ID      = os.getenv("AGENT_ID", "unknown")

def log(msg: str) -> None:
    print(f"[FWD] {msg}", flush=True)

# 2. OTLP → 서버 ingest 스키마 변환
def transform_otlp(otlp_data: dict):
    records = []
    try:
        for rl in otlp_data.get("resourceLogs", []):
            for sl in rl.get("scopeLogs", []):
                for lr in sl.get("logRecords", []):
                    ts_nano = int(lr.get("timeUnixNano", time.time_ns()))
                    ts_iso = datetime.fromtimestamp(ts_nano / 1e9, timezone.utc).isoformat()

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

    return {
        "meta": {"client_id": CLIENT_ID, "host": socket.gethostname()},
        "agent_id": AGENT_ID,
        "records": records,
    }

# 3. ingest/logs 호출 (422 방지: 헤더 정확히 맞추기)
def send_to_server(payload: dict) -> bool:
    body_bytes = json.dumps(payload).encode("utf-8")

    # 서버 verify_timestamp 가 기대하는 값: 유닉스 타임(초) 문자열
    ts = str(int(time.time()))

    # payload hash
    payload_hash = hashlib.sha256(body_bytes).hexdigest()

    # nonce / idempotency-key
    nonce = hashlib.md5(os.urandom(16)).hexdigest()
    idem_key = hashlib.md5((ts + nonce).encode()).hexdigest()

    headers = {
        "Authorization": f"Bearer {LOG_TOKEN}",      # JWT
        "Content-Type": "application/json",
        "X-Client-Id": CLIENT_ID,
        "X-Request-Timestamp": ts,
        "X-Payload-Hash": f"sha256:{payload_hash}", # 서버 쪽 구현에 맞춤
        "X-Nonce": nonce,
        "X-Idempotency-Key": idem_key,
    }

    try:
        resp = requests.post(UPSTREAM_URL, data=body_bytes, headers=headers, timeout=5)
        log(f"Upstream {UPSTREAM_URL} → {resp.status_code}")
        if resp.status_code in (200, 202):
            return True
        else:
            log(f"Response body: {resp.text}")
            return False
    except Exception as e:
        log(f"Upstream Error: {e}")
        return False

# 4. 로컬 HTTP 핸들러
class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/logs":
            self.send_response(404)
            self.end_headers()
            return

        auth_header = self.headers.get("Authorization", "")
        if auth_header != f"Bearer {LOCAL_TOKEN}":
            log("Local Unauthorized")
            self.send_response(401)
            self.end_headers()
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            otlp_json = json.loads(body)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        payload = transform_otlp(otlp_json)
        if not payload:
            self.send_response(200)
            self.end_headers()
            return

        if send_to_server(payload):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(503)
            self.end_headers()

    def log_message(self, format, *args):
        # 기본 access log는 조용히
        return

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
