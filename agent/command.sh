#!/usr/bin/env bash
set -euo pipefail

#
# lastagent 설치 스크립트
#  - 에이전트 스택(secure-forwarder, agent-controller, otel-agent)을 한 번에 설치/등록
#  - .env 자동 생성 (/auth/register 로 agent 등록)
#  - 이미 설치된 service 유닛은 "덮어쓰지 않도록" 구성
#

# ────────────── 기본 환경 설정 ──────────────

LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"

AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"

ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# 솔루션 서버 정보
BOOTSTRAP_SECRET="dev"
AGENT_VERSION=1              # 서버 쪽에서 숫자 1 정도만 기대 → 정수로 보냄
CLIENT_ID="default"

# ★ 서버 NodePort = 30080, register API 는 /auth/register
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="30080"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"
REGISTER_PATH="/auth/register"
REGISTER_URL="${CONTROLLER_URL}${REGISTER_PATH}"

# ────────────── Helper 함수 ──────────────

log() {
  echo "[*] $*"
}

error() {
  echo "[ERROR] $*" >&2
}

install_service_unit() {
  local src="$1"
  local dst="$2"
  local name="$3"

  if [[ -f "$dst" ]]; then
    log "${name} service 이미 존재 → 덮어쓰지 않습니다: ${dst}"
  else
    log "${name} service 신규 설치 → ${dst}"
    cp "$src" "$dst"
  fi
}

# ────────────── 설치 시작 ──────────────

log "agent 설치 시작"

if [[ "${EUID}" -ne 0 ]]; then
  error "root 권한이 필요합니다. sudo로 실행하세요."
  exit 1
fi

mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${REPO_DIR}/venv"
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib
mkdir -p /var/lib/secure-log-agent/queue

if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  log "시스템 계정 ${AGENT_USER} 생성"
  useradd --system --no-create-home \
    --home "${AGENT_HOME}" \
    --shell /usr/sbin/nologin \
    "${AGENT_USER}"
fi

apt-get update
apt-get install -y python3 python3-venv curl jq

if [[ ! -d "${REPO_DIR}/venv" ]]; then
  log "Python venv 생성: ${REPO_DIR}/venv"
  python3 -m venv "${REPO_DIR}/venv"
fi

# venv 안에 필요한 패키지 설치/업데이트
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

# ────────────── .env 자동 생성 ──────────────
if [[ -f "${ETC_DIR}/.env" ]]; then
  log "기존 .env 파일 있으므로 재사용합니다: ${ETC_DIR}/.env"
else
  log ".env 파일 없음 → 서버 /auth/register 로 agent 등록 시도 중..."

  # 이 서버의 IP (첫 번째 항목) → host 필드로 사용
  AGENT_IP=$(hostname -I | awk '{print $1}')

  # 서버 요구 스키마:
  # { "client_id": "...", "host": "<ip>", "agent_version": 1 }
  JSON_PAYLOAD=$(cat <<EOF
{
  "client_id": "${CLIENT_ID}",
  "host": "${AGENT_IP}",
  "agent_version": ${AGENT_VERSION}
}
EOF
)

  log "POST ${REGISTER_URL}"
  RESPONSE=$(curl -sS --fail -X POST "${REGISTER_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}") || {
      error "agent-register 요청 실패. 서버/포트/방화벽을 확인하세요. (${REGISTER_URL})"
      exit 1
    }

  TOKEN=$(echo "${RESPONSE}"        | jq -r '.access_token   // empty')
  AGENT_ID=$(echo "${RESPONSE}"     | jq -r '.agent_id      // empty')
  REFRESH_TOKEN=$(echo "${RESPONSE}"| jq -r '.refresh_token // empty')
  EXPIRES_IN=$(echo "${RESPONSE}"   | jq -r '.expires_in    // 3600')

  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    error "서버 응답에 access_token 없음. 응답: ${RESPONSE}"
    exit 1
  fi

  cat <<EOF > "${ETC_DIR}/.env"
# lastagent 자동 등록으로 생성된 파일

# agent-controller 설정
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${TOKEN}
AGENT_REFRESH_TOKEN=${REFRESH_TOKEN}
AGENT_TOKEN_EXPIRES_IN=${EXPIRES_IN}

# secure-forwarder 설정
UPSTREAM_URL=http://${CONTROLLER_HOST}:30080/ingest/logs
UPSTREAM_LOG_TOKEN=dev_log_token
HMAC_SECRET=super_secret_hmac_key
LOCAL_TOKEN=dev_agent_token
LISTEN_HOST=127.0.0.1
LISTEN_PORT=19000
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  log ".env 생성 완료 → ${ETC_DIR}/.env"
fi

# 7. agent.yaml 존재 확인
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  error "agent.yaml 이 없습니다: ${ETC_DIR}/agent.yaml"
  exit 1
fi

cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"

chown -R "${AGENT_USER}:nogroup" \
  "${AGENT_HOME}" \
  /var/lib/otelcol-contrib \
  /var/lib/secure-log-agent

chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# 9. systemd 유닛 설치
install_service_unit "${ETC_DIR}/otel-agent.service" \
  "${SYSTEMD_DIR}/otel-agent.service" \
  "otel-agent"

install_service_unit "${REPO_DIR}/forwarder/secure-forwarder.service" \
  "${SYSTEMD_DIR}/secure-forwarder.service" \
  "secure-forwarder"

install_service_unit "${REPO_DIR}/agent/agent-controller.service" \
  "${SYSTEMD_DIR}/agent-controller.service" \
  "agent-controller"

# 10. systemd 적용 및 시작
systemctl daemon-reload
systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

# 12. 상태 요약
echo
log "서비스 상태 요약:"
systemctl --no-pager --full status otel-agent.service       | sed -n '1,8p'
systemctl --no-pager --full status secure-forwarder.service | sed -n '1,8p'
systemctl --no-pager --full status agent-controller.service | sed -n '1,8p'

echo
log "설치 완료. 서비스 실행 중입니다."
