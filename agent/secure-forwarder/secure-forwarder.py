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
import http.server
import socketserver
import requests
import hmac
import hashlib
import time
import uuid
from typing import Dict


# 최대 허용 바디 크기 (bytes), 기본 5MB
MAX_BODY_SIZE = int(os.getenv("MAX_BODY_SIZE", str(5 * 1024 * 1024)))


def require_env(name: str) -> str:
    """필수 환경변수 로딩. 없으면 즉시 종료."""
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"[FATAL] required env {name} is not set")
    return value


# === 환경변수 (필수) ===
LOCAL_TOKEN = require_env("LOCAL_TOKEN")
UPSTREAM_URL = require_env("UPSTREAM_URL")
UPSTREAM_LOG_TOKEN = require_env("UPSTREAM_LOG_TOKEN")
HMAC_SECRET = require_env("HMAC_SECRET")

# === 환경변수 (선택) ===
LISTEN_HOST = os.getenv("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "19000"))


def make_hmac_headers(method: str, path: str, body: bytes) -> Dict[str, str]:
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
        # 너무 시끄러우면 pass 로 바꿔도 됨
        print("[FWD]", fmt % args)

    def do_POST(self):
        if self.path != "/v1/logs":
            self.send_error(404, "Not Found")
            return

        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {LOCAL_TOKEN}":
            self.send_error(401, "invalid local token")
            return

        length_header = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(length_header)
        except ValueError:
            self.send_error(400, "invalid Content-Length")
            return

        if length < 0:
            self.send_error(400, "invalid Content-Length")
            return

        if length > MAX_BODY_SIZE:
            self.send_error(413, "payload too large")
            return

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
            if k.lower() in ("content-type",):
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp.content)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    print(
        f"[FWD] listening on {LISTEN_HOST}:{LISTEN_PORT}, "
        f"upstream={UPSTREAM_URL}, max_body={MAX_BODY_SIZE} bytes"
    )
    with ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
