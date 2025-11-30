#!/usr/bin/env bash
set -euo pipefail

#
# lastagent 통합 설치 스크립트 (Final Fix)
# - 디렉토리/파일 자동 생성 (forwarder, agent, otel_storage)
# - 서비스 권한 및 경로 문제 해결
#

# ───────────── 기본 설정 ─────────────

LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"

AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"

ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# 솔루션 서버 정보 (NodePort 30080 사용)
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="30080"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"

REGISTER_PATH="/auth/register"
REGISTER_URL="${CONTROLLER_URL}${REGISTER_PATH}"

CLIENT_ID="default"
AGENT_VERSION="1"

# [입력 확인]
if [ -z "${BOOTSTRAP_SECRET:-}" ]; then
    echo "❌ Error: BOOTSTRAP_SECRET 환경변수가 설정되지 않았습니다."
    echo "💡 사용법: sudo BOOTSTRAP_SECRET=\"웹콘솔_키값\" ./command.sh"
    exit 1
fi

# ───────────── Helper 함수 ─────────────

log()   { echo "[*] $*"; }
error() { echo "[ERROR] $*" >&2; }

# ───────────── 설치 시작 ─────────────

log "agent 설치 시작"

if [[ "${EUID}" -ne 0 ]]; then
  error "root 권한이 필요합니다. sudo로 실행하세요."
  exit 1
fi

# 1. 디렉토리 구조 생성 (누락되었던 폴더들 포함)
log "디렉토리 생성 중..."
mkdir -p "${REPO_DIR}/etc"
mkdir -p "${REPO_DIR}/venv"
mkdir -p "${REPO_DIR}/forwarder"  # [중요] 누락되었던 폴더
mkdir -p "${REPO_DIR}/agent"      # [중요] 누락되었던 폴더
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib

# 버퍼 디렉토리 생성 및 권한 설정
mkdir -p /var/lib/secure-log-agent/otel_storage

# 시스템 계정 생성
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  log "시스템 계정 ${AGENT_USER} 생성"
  useradd --system --no-create-home \
    --home "${AGENT_HOME}" \
    --shell /usr/sbin/nologin \
    "${AGENT_USER}"
fi

# 필수 패키지 설치
apt-get update
apt-get install -y python3 python3-venv curl jq

# Python venv 생성
if [[ ! -f "${REPO_DIR}/venv/bin/activate" ]]; then
  log "Python venv 생성: ${REPO_DIR}/venv"
  python3 -m venv "${REPO_DIR}/venv"
fi

# venv 패키지 설치
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

# ───────────── 파일 생성 (코드 주입) ─────────────

log "Python 소스 코드 및 설정 파일 생성 중..."

# 1. secure-forwarder.py 생성
cat <<'EOF' > "${REPO_DIR}/forwarder/secure-forwarder.py"
#!/usr/bin/env python3
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

load_dotenv("/home/last/lastagent/etc/.env")

LISTEN_PORT = int(os.getenv("LISTEN_PORT", "19000"))
LISTEN_HOST = os.getenv("LISTEN_HOST", "127.0.0.1")
LOCAL_TOKEN = os.getenv("LOCAL_TOKEN")
UPSTREAM_URL = os.getenv("UPSTREAM_URL")
LOG_TOKEN = os.getenv("UPSTREAM_LOG_TOKEN")
CLIENT_ID = os.getenv("CLIENT_ID", "default")
AGENT_ID = os.getenv("AGENT_ID", "unknown")

def log(msg):
    print(f"[FWD] {msg}", flush=True)

def transform_otlp(otlp_data):
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
                        "tags": ["otel"]
                    })
    except Exception as e:
        log(f"Transform Error: {e}")
        return None
    if not records: return None
    return {"meta": {"client_id": CLIENT_ID, "host": socket.gethostname()}, "agent_id": AGENT_ID, "records": records}

def send_to_server(payload):
    body_bytes = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode("utf-8")
    ts = datetime.now(timezone.utc).isoformat()
    nonce = str(time.time())
    p_hash = hashlib.sha256(body_bytes).hexdigest()
    headers = {
        "Authorization": f"Bearer {LOG_TOKEN}",
        "Content-Type": "application/json",
        "X-Client-Id": CLIENT_ID,
        "X-Request-Timestamp": ts,
        "X-Payload-Hash": f"sha256:{p_hash}",
        "X-Nonce": nonce,
        "X-Idempotency-Key": hashlib.md5((ts + nonce).encode()).hexdigest()
    }
    try:
        resp = requests.post(UPSTREAM_URL, data=body_bytes, headers=headers, timeout=5)
        if resp.status_code in [200, 202]: return True
        log(f"Upstream Failed: {resp.status_code} - {resp.text}")
        return False
    except Exception as e:
        log(f"Network Error: {e}")
        return False

class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/logs":
            self.send_response(404); self.end_headers(); return
        if self.headers.get("Authorization", "") != f"Bearer {LOCAL_TOKEN}":
            self.send_response(401); self.end_headers(); return
        try:
            length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(length))
            payload = transform_otlp(data)
            if payload and send_to_server(payload):
                self.send_response(200); self.wfile.write(b'{"status":"ok"}')
                log(f"Forwarded {len(payload['records'])} logs")
            else:
                self.send_response(503)
        except Exception as e:
            log(f"Handler Error: {e}")
            self.send_response(400)
        self.end_headers()
    def log_message(self, format, *args): return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer): daemon_threads = True

if __name__ == "__main__":
    log(f"Secure Forwarder listening on {LISTEN_HOST}:{LISTEN_PORT}")
    ThreadedHTTPServer((LISTEN_HOST, LISTEN_PORT), RequestHandler).serve_forever()
EOF

# 2. agent_controller.py 생성
cat <<'EOF' > "${REPO_DIR}/agent/agent_controller.py"
import os, time, json, socket, subprocess, requests, hmac, hashlib, uuid
from typing import Any, Dict, List
from dotenv import load_dotenv

load_dotenv("/home/last/lastagent/etc/.env")

AGENT_ID = os.getenv("AGENT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CONTROLLER_URL = os.getenv("CONTROLLER_URL")
AGENT_TOKEN = os.getenv("AGENT_TOKEN")
HMAC_SECRET = os.getenv("HMAC_SECRET")
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "10"))

def log(msg): print(f"[CTRL][{AGENT_ID}] {msg}", flush=True)

def make_headers(method, path, body):
    headers = {"Authorization": f"Bearer {AGENT_TOKEN}", "Content-Type": "application/json", "X-Agent-Id": AGENT_ID, "X-Client-Id": CLIENT_ID}
    if HMAC_SECRET:
        ts = str(int(time.time())); nonce = str(uuid.uuid4()); idem = str(uuid.uuid4())
        phash = hashlib.sha256(body or b"").hexdigest()
        sig = hmac.new(HMAC_SECRET.encode(), "\n".join([method.upper(), path, ts, nonce, phash]).encode(), hashlib.sha256).hexdigest()
        headers.update({"X-Request-Timestamp": ts, "X-Nonce": nonce, "X-Idempotency-Key": idem, "X-Payload-Hash": phash, "X-Signature": sig})
    return headers

def fetch_commands():
    path = "/agent/jobs/pull"
    try:
        resp = requests.get(f"{CONTROLLER_URL}{path}", headers=make_headers("GET", path, b""), params={"agent_id": AGENT_ID}, timeout=5)
        if resp.status_code == 200: return resp.json().get("jobs", [])
    except Exception as e: log(f"Fetch error: {e}")
    return []

def ack(job_id, status, msg=""):
    path = "/agent/jobs/result"
    payload = {"job_id": job_id, "agent_id": AGENT_ID, "success": status=="ok", "output_snippet": msg[:1000], "error_detail": msg if status!="ok" else None}
    body = json.dumps(payload).encode()
    try: requests.post(f"{CONTROLLER_URL}{path}", headers=make_headers("POST", path, body), data=body, timeout=5)
    except Exception as e: log(f"Ack error: {e}")

def execute(job):
    jtype = job.get("job_type"); args = job.get("args", {})
    if jtype == "ping": return "pong"
    if jtype == "BLOCK_IP":
        ip = args.get("ip") or args.get("src_ip")
        if ip:
             # 실제 차단 로직 (iptables 예시)
             # subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
             return f"Blocked IP {ip}"
    return "unknown command"

def main():
    log("Controller started")
    while True:
        for job in fetch_commands():
            jid = job.get("job_id")
            try:
                res = execute(job)
                log(f"Job {jid} success: {res}")
                ack(jid, "ok", res)
            except Exception as e:
                log(f"Job {jid} failed: {e}")
                ack(jid, "error", str(e))
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__": main()
EOF

# 3. agent.yaml 생성
cat <<EOF > "${ETC_DIR}/agent.yaml"
extensions:
  health_check: {}
  file_storage:
    directory: /var/lib/secure-log-agent/otel_storage
    create_directory: true

receivers:
  filelog:
    include:
      - /var/log/nginx/access.log
      - /var/log/text4shell/application.log
    start_at: end
    storage: file_storage

processors:
  batch:
    timeout: 1s
    send_batch_size: 1024
  transform/pii_mask:
    error_mode: ignore
    log_statements:
      - context: log
        statements:
          - replace_pattern(body, "([0-9]{1,3}\\\\.){3}[0-9]{1,3}", "[ip_redacted]")

exporters:
  otlphttp:
    endpoint: \${env:INGEST_ENDPOINT}
    logs_endpoint: /v1/logs
    headers:
      Authorization: "Bearer \${env:INGEST_TOKEN}"
    sending_queue:
      enabled: true
      storage: file_storage
    retry_on_failure:
      enabled: true

service:
  extensions: [health_check, file_storage]
  pipelines:
    logs:
      receivers: [filelog]
      processors: [transform/pii_mask, batch]
      exporters: [otlphttp]
EOF

# 4. 서비스 파일 생성 (경로 의존성 제거)
cat <<EOF > "${SYSTEMD_DIR}/secure-forwarder.service"
[Unit]
Description=Secure Log Forwarder
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${REPO_DIR}/forwarder
EnvironmentFile=${ETC_DIR}/.env
ExecStart=${REPO_DIR}/venv/bin/python ${REPO_DIR}/forwarder/secure-forwarder.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > "${SYSTEMD_DIR}/agent-controller.service"
[Unit]
Description=Agent Controller
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${REPO_DIR}/agent
EnvironmentFile=${ETC_DIR}/.env
ExecStart=${REPO_DIR}/venv/bin/python ${REPO_DIR}/agent/agent_controller.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > "${SYSTEMD_DIR}/otel-agent.service"
[Unit]
Description=OTEL Agent
After=network-online.target

[Service]
Type=simple
User=${AGENT_USER}
WorkingDirectory=${AGENT_HOME}
EnvironmentFile=${ETC_DIR}/.env
PermissionsStartOnly=true
ExecStartPre=/usr/bin/mkdir -p /var/lib/secure-log-agent/otel_storage
ExecStartPre=/usr/bin/chown -R ${AGENT_USER}:nogroup /var/lib/secure-log-agent

ExecStart=/usr/local/bin/otelcol-contrib --config=${AGENT_HOME}/agent.yaml
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

# ───────────── .env 생성 (/auth/register) ─────────────

ENV_FILE="${ETC_DIR}/.env"

if [[ -f "${ENV_FILE}" ]]; then
  log "기존 .env 파일 있음 → 재사용합니다: ${ENV_FILE}"
else
  log ".env 파일 없음 → 서버 /auth/register 로 agent 등록 시도..."

  HOSTNAME_VALUE="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -z "${HOSTNAME_VALUE}" ]] && HOSTNAME_VALUE="$(hostname)"

  JSON_PAYLOAD=$(cat <<EOF
{
  "client_id": "${CLIENT_ID}",
  "host": "${HOSTNAME_VALUE}",
  "agent_version": "${AGENT_VERSION}",
  "secret_proof": "${BOOTSTRAP_SECRET}"
}
EOF
)

  RESPONSE=$(
    curl -sS -w "\n%{http_code}" -X POST "${REGISTER_URL}" \
      -H "Content-Type: application/json" \
      -d "${JSON_PAYLOAD}"
  ) || {
    error "/auth/register 요청 실패"
    exit 1
  }

  HTTP_STATUS=$(echo "${RESPONSE}" | tail -n1)
  BODY=$(echo "${RESPONSE}" | sed '$d')

  if [[ "${HTTP_STATUS}" != "200" && "${HTTP_STATUS}" != "201" ]]; then
    error "HTTP status: ${HTTP_STATUS}"
    error "Body: ${BODY}"
    exit 1
  fi

  log "[*] 등록 성공!"

  TOKEN=$(echo "${BODY}" | jq -r '.access_token // empty')
  AGENT_ID=$(echo "${BODY}" | jq -r '.agent_id // empty')
  LOCAL_TOKEN_VAL=$(python3 -c "import secrets; print(secrets.token_hex(16))")

  cat <<EOF > "${ENV_FILE}"
CLIENT_ID=${CLIENT_ID}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${TOKEN}
HMAC_SECRET=super_secret_hmac_key
CONTROLLER_URL=http://${CONTROLLER_HOST}:${CONTROLLER_PORT}
UPSTREAM_URL=http://${CONTROLLER_HOST}:${CONTROLLER_PORT}/ingest/logs
UPSTREAM_LOG_TOKEN=${TOKEN}
POLL_INTERVAL=5
LISTEN_HOST=127.0.0.1
LISTEN_PORT=19000
LOCAL_TOKEN=${LOCAL_TOKEN_VAL}
INGEST_ENDPOINT=http://127.0.0.1:19000
INGEST_TOKEN=${LOCAL_TOKEN_VAL}
EOF

  chmod 600 "${ENV_FILE}"
  chown root:root "${ENV_FILE}"
  log ".env 생성 완료"
fi

# 설정 파일 배포
cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"
chown -R "${AGENT_USER}:nogroup" "${AGENT_HOME}" /var/lib/otelcol-contrib /var/lib/secure-log-agent
chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# 서비스 시작
systemctl daemon-reload
systemctl enable otel-agent secure-forwarder agent-controller
systemctl restart otel-agent secure-forwarder agent-controller

echo
log "설치 완료. 서비스 상태:"
systemctl --no-pager status otel-agent secure-forwarder agent-controller | grep "Active:"