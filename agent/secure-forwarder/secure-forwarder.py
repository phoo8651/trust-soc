#!/usr/bin/env python3
"""
Secure Forwarder (HMAC Gate) for Logs

- otel-agent -> (LOCAL_TOKEN) -> secure-forwarder (/v1/logs)
- secure-forwarder -> (JWT + 헤더들) -> solution-server /ingest/logs
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

# 1. 설정 로드 (.env)
load_dotenv("/home/last/lastagent/etc/.env")

LISTEN_PORT = int(os.getenv("LISTEN_PORT", "19000"))
LISTEN_HOST = os.getenv("LISTEN_HOST", "127.0.0.1")

LOCAL_TOKEN   = os.getenv("LOCAL_TOKEN")            # otel-agent -> forwarder 인증
UPSTREAM_URL  = os.getenv("UPSTREAM_URL")           # http://192.168.67.131:30080/ingest/logs
LOG_TOKEN     = os.getenv("UPSTREAM_LOG_TOKEN")     # ingest/logs JWT
HMAC_SECRET   = os.getenv("HMAC_SECRET")

AGENT_ID   = os.getenv("AGENT_ID", "unknown")
CLIENT_ID  = os.getenv("CLIENT_ID", "default") or AGENT_ID

def log(msg: str):
    print(f"[FWD] {msg}", flush=True)

# 2. OTLP → 서버 records 형태로 변환
def transform_otlp(otlp_data: dict):
    records = []
    try:
        resource_logs = otlp_data.get("resourceLogs", [])
        for rl in resource_logs:
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
        "meta": {
            "client_id": CLIENT_ID,
            "host": socket.gethostname(),
        },
        "agent_id": AGENT_ID,
        "records": records,
    }

# 3. solution-server /ingest/logs 로 전송
def send_to_server(payload: dict) -> bool:
    body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    # ↑ 공백 제거 (서버 쪽이 body_bytes 기준으로 hash 를 만들기 때문에 맞춰줌)

    # 헤더 조건 (서버 피드백 기준)
    ts = str(int(time.time()))
    payload_hash = hashlib.sha256(body_bytes).hexdigest()
    nonce = str(time.time())

    headers = {
        "Authorization": f"Bearer {LOG_TOKEN}",
        "Content-Type": "application/json",
        "X-Client-Id": CLIENT_ID,
        "X-Request-Timestamp": ts,
        "X-Payload-Hash": f"sha256:{payload_hash}",
        "X-Nonce": nonce,
        "X-Idempotency-Key": hashlib.md5((ts + nonce).encode()).hexdigest(),
    }

    # HMAC_SECRET 을 정말 쓰고 싶으면 여기서 X-Signature 같은 걸 추가하도록
    # (현재 서버 코드에서 안 쓰면 생략해도 됨)

    try:
        resp = requests.post(UPSTREAM_URL, data=body_bytes, headers=headers, timeout=5)
        log(f"Upstream status={resp.status_code}")
        return resp.status_code in (200, 202)
    except Exception as e:
        log(f"Upstream Error: {e}")
        return False

# 4. 로컬 HTTP 핸들러 (otel-agent -> forwarder)
class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/logs":
            self.send_response(404)
            self.end_headers()
            return

        auth_header = self.headers.get("Authorization", "")
        if auth_header != f"Bearer {LOCAL_TOKEN}":
            log("Local Unauthorized Access")
            self.send_response(401)
            self.end_headers()
            return

        try:
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len)
            otlp_json = json.loads(post_body)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        server_payload = transform_otlp(otlp_json)
        if server_payload:
            if send_to_server(server_payload):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
                log(f"Forwarded {len(server_payload['records'])} logs")
            else:
                self.send_response(503)
                self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()

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
