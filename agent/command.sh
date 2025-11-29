#!/usr/bin/env bash
set -euo pipefail

# lastagent 설치 스크립트 (에이전트 스택 전체 설치)
#  - .env 자동 생성
#  - ingest log 환경변수 포함
#  - systemd 서비스 등록 및 시작

# ───────────── 기본 설정 ─────────────
LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"
ETC_DIR="${REPO_DIR}/etc"
AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"
SYSTEMD_DIR="/etc/systemd/system"

BOOTSTRAP_SECRET="dev"
AGENT_VERSION="0.1.0"
CLIENT_ID="default"

# ▶ 컨트롤러 서버 주소
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="8000"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"
REGISTER_PATH="/api/agent-register"
REGISTER_URL="${CONTROLLER_URL}${REGISTER_PATH}"

# ▶ Ingest Log 전송 설정
UPSTREAM_URL="http://192.168.67.131:30080/v1/logs"
UPSTREAM_LOG_TOKEN="dev_log_token"
HMAC_SECRET="super_secret_hmac_key"

# ───────────── Helper 함수 ─────────────
log() { echo "[*] $*"; }
error() { echo "[ERROR] $*" >&2; }

install_service_unit() {
  local src="$1"
  local dst="$2"
  local name="$3"
  if [[ -f "$dst" ]]; then
    log "${name} 서비스 이미 존재 → 덮어쓰지 않음"
  else
    log "${name} 서비스 설치 → ${dst}"
    cp "$src" "$dst"
  fi
}

# ───────────── 설치 시작 ─────────────
log "에이전트 설치 시작"

# 1. Root 확인
if [[ "${EUID}" -ne 0 ]]; then
  error "root 권한으로 실행 필요 (sudo)"
  exit 1
fi

# 2. 디렉터리 생성
mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${REPO_DIR}/venv"
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib
mkdir -p /var/lib/secure-log-agent/queue

# 3. 시스템 계정 생성
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  log "시스템 계정 ${AGENT_USER} 생성"
  useradd --system --no-create-home --home "${AGENT_HOME}" --shell /usr/sbin/nologin "${AGENT_USER}"
fi

# 4. 패키지 설치
apt-get update
apt-get install -y python3 python3-venv curl jq

# 5. Python venv + pip 패키지
if [[ ! -d "${REPO_DIR}/venv" ]]; then
  log "venv 생성"
  python3 -m venv "${REPO_DIR}/venv"
fi

source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

# 6. .env 자동 생성
if [[ -f "${ETC_DIR}/.env" ]]; then
  log ".env 파일 존재 → 재사용"
else
  log ".env 생성 중 (서버에 agent 등록 요청 중)"

  HOSTNAME=$(hostname)

  JSON_PAYLOAD=$(cat <<EOF
{
  "client_id": "${CLIENT_ID}",
  "host": "${HOSTNAME}",
  "agent_version": "${AGENT_VERSION}",
  "secret_proof": "${BOOTSTRAP_SECRET}"
}
EOF
)

  RESPONSE=$(curl -sS --fail -X POST "${REGISTER_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}") || {
      error "agent-register 실패 → ${REGISTER_URL} 확인 필요"
      exit 1
    }

  TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token // empty')
  AGENT_ID=$(echo "${RESPONSE}" | jq -r '.agent_id // empty')
  REFRESH_TOKEN=$(echo "${RESPONSE}" | jq -r '.refresh_token // empty')
  EXPIRES_IN=$(echo "${RESPONSE}" | jq -r '.expires_in // 3600')

  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    error "access_token 없음. 응답: ${RESPONSE}"
    exit 1
  fi

  cat <<EOF > "${ETC_DIR}/.env"
# 에이전트 인증 정보
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${TOKEN}
AGENT_REFRESH_TOKEN=${REFRESH_TOKEN}
AGENT_TOKEN_EXPIRES_IN=${EXPIRES_IN}

# Ingest 로그 전송 정보
UPSTREAM_URL=${UPSTREAM_URL}
UPSTREAM_LOG_TOKEN=${UPSTREAM_LOG_TOKEN}
HMAC_SECRET=${HMAC_SECRET}
LISTEN_HOST=127.0.0.1
LISTEN_PORT=19000
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  log ".env 생성 완료 → ${ETC_DIR}/.env"
fi

# 7. agent.yaml 확인
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  error "agent.yaml 없음 → ${ETC_DIR}/agent.yaml"
  exit 1
fi

# 8. agent.yaml 복사 및 권한
cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"

chown -R "${AGENT_USER}:nogroup" \
  "${AGENT_HOME}" \
  /var/lib/otelcol-contrib \
  /var/lib/secure-log-agent

chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# 9. 서비스 유닛 설치
install_service_unit "${ETC_DIR}/otel-agent.service" \
  "${SYSTEMD_DIR}/otel-agent.service" \
  "otel-agent"

install_service_unit "${REPO_DIR}/forwarder/secure-forwarder.service" \
  "${SYSTEMD_DIR}/secure-forwarder.service" \
  "secure-forwarder"

install_service_unit "${REPO_DIR}/agent/agent-controller.service" \
  "${SYSTEMD_DIR}/agent-controller.service" \
  "agent-controller"

# 10. 서비스 시작
systemctl daemon-reload
systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

# 11. 상태 요약
echo
log "서비스 상태:"
systemctl --no-pager --full status otel-agent.service         | sed -n '1,8p'
systemctl --no-pager --full status secure-forwarder.service   | sed -n '1,8p'
systemctl --no-pager --full status agent-controller.service   | sed -n '1,8p'

echo
log "설치 완료."
