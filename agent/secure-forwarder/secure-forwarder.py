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
"""

import os
import http.server
import socketserver
import requests
import hmac
import hashlib
import time
import uuid


LOCAL_TOKEN = os.getenv("LOCAL_TOKEN", "dev_agent_token")
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "http://127.0.0.1:8000/v1/logs")
UPSTREAM_LOG_TOKEN = os.getenv("UPSTREAM_LOG_TOKEN", "dev_log_token")
HMAC_SECRET = os.getenv("HMAC_SECRET", "super_secret_hmac_key")

LISTEN_HOST = os.getenv("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "19000"))


def make_hmac_headers(method: str, path: str, body: bytes) -> dict:
    ts = str(int(time.time()))
    nonce = str(uuid.uuid4())
    payload_hash = hashlib.sha256(body or b"").hexdigest()
    msg = "\n".join([method.upper(), path, ts, nonce, payload_hash])
    sig = hmac.new(
        HMAC_SECRET.encode("utf-8"),
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return {
        "X-Request-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Idempotency-Key": str(uuid.uuid4()),
        "X-Payload-Hash": payload_hash,
        "X-Signature": sig,
    }


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "SecureForwarder/1.0"

    def log_message(self, fmt, *args):
        # 조용히 하고 싶으면 pass
        print("[FWD]", fmt % args)

    def do_POST(self):
        if self.path != "/v1/logs":
            self.send_error(404, "Not Found")
            return

        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {LOCAL_TOKEN}":
            self.send_error(401, "invalid local token")
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)

        # upstream 헤더 구성: LOG_TOKEN + HMAC
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {UPSTREAM_LOG_TOKEN}",
        }
        headers.update(make_hmac_headers("POST", "/v1/logs", body))

        try:
            resp = requests.post(UPSTREAM_URL, data=body, headers=headers, timeout=5)
        except Exception as e:
            print("[FWD] upstream error:", e)
            self.send_error(502, "upstream error")
            return

        # upstream 응답을 그대로 전달
        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            # 너무 과한 헤더는 스킵하고 Content-Type 정도만
            if k.lower() in ("content-type",):
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp.content)


def main():
    with socketserver.TCPServer((LISTEN_HOST, LISTEN_PORT), Handler) as httpd:
        print(f"[FWD] listening on {LISTEN_HOST}:{LISTEN_PORT}, upstream={UPSTREAM_URL}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
