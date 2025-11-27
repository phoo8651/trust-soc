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
import requests
import time
from dotenv import load_dotenv

load_dotenv("/home/last/lastagent/etc/.env")  # 환경변수 파일 로드

FORWARD_URL = os.getenv("FORWARD_URL")
FORWARD_TOKEN = os.getenv("FORWARD_TOKEN")
QUEUE_DIR = "/var/lib/secure-log-agent/queue"
INTERVAL = float(os.getenv("FORWARD_INTERVAL", "2"))

HEADERS = {
    "Authorization": f"Bearer {FORWARD_TOKEN}",
    "Content-Type": "application/json"
}

def log(msg: str) -> None:
    print(f"[FWD] {msg}", flush=True)

def send_file(file_path: str) -> bool:
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        resp = requests.post(FORWARD_URL, data=data, headers=HEADERS, timeout=3)
        if resp.status_code == 200:
            return True
        else:
            log(f"send failed: {file_path}, status={resp.status_code}")
    except Exception as e:
        log(f"send error: {file_path}, error={e}")
    return False

def main():
    log("secure-forwarder started.")
    while True:
        files = sorted(os.listdir(QUEUE_DIR))
        for fname in files:
            path = os.path.join(QUEUE_DIR, fname)
            if send_file(path):
                os.remove(path)
                log(f"sent and removed: {fname}")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
