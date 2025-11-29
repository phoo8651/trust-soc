#!/usr/bin/env bash
set -euo pipefail

#
# lastagent 설치 스크립트 (최종 버전)
# - 에이전트 스택(secure-forwarder, agent-controller, otel-agent) 설치/등록
# - 솔루션 서버에 agent-register 호출 → .env 자동 생성
# - 이미 설치된 systemd 유닛은 덮어쓰지 않음
#

# ────────────── 기본 환경 설정 ──────────────

LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"

AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"

ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# 솔루션 서버 정보
BOOTSTRAP_SECRET="dev"          # 지금은 사용 안 하지만 남겨둠
CLIENT_ID="default"             # 서버에서 정의한 client_id
AGENT_VERSION_NUM=1             # 숫자 1

# ★ 솔루션 서버 NodePort = 30080
CONTROLLER_HOST="192.168.67.131"
NODEPORT="30080"

# register 엔드포인트 경로 (백엔드 설정에 맞게 하나만 사용)
REGISTER_PATH="/api/agent-register"
#REGISTER_PATH="/agent-register"

CONTROLLER_URL="http://${CONTROLLER_HOST}:${NODEPORT}"
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

# 시스템 계정 생성
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  log "시스템 계정 ${AGENT_USER} 생성"
  useradd --system --no-create-home \
    --home "${AGENT_HOME}" \
    --shell /usr/sbin/nologin \
    "${AGENT_USER}"
fi

# 패키지 설치
apt-get update
apt-get install -y python3 python3-venv curl jq

# venv 생성
if [[ ! -d "${REPO_DIR}/venv" ]]; then
  log "Python venv 생성: ${REPO_DIR}/venv"
  python3 -m venv "${REPO_DIR}/venv"
fi

# venv 패키지 설치
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

# ────────────── .env 자동 생성 ──────────────
# 이미 .env 가 있으면 재사용, 없으면 서버에 agent-register 요청

if [[ -f "${ETC_DIR}/.env" ]]; then
  log "기존 .env 파일 있으므로 재사용합니다: ${ETC_DIR}/.env"
else
  log ".env 파일 없음 → 서버에 agent register 요청 시도 중..."

  # 에이전트 서버 IP (hostname 말고 실제 IP)
  HOST_IP=$(hostname -I | awk '{print $1}')

  JSON_PAYLOAD=$(cat <<EOF
{
  "client_id": "${CLIENT_ID}",
  "host": "${HOST_IP}",
  "agent_version": ${AGENT_VERSION_NUM}
}
EOF
)

  log "POST ${REGISTER_URL}"
  RESPONSE=$(curl -sS --fail -X POST "${REGISTER_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}") || {
      error "agent-register 요청 실패. 서버/포트/경로/방화벽을 확인하세요. (${REGISTER_URL})"
      exit 1
    }

  # 응답 값 파싱
  AGENT_ID=$(echo "${RESPONSE}" | jq -r '.agent_id // empty')
  TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token // empty')
  REFRESH_TOKEN=$(echo "${RESPONSE}" | jq -r '.refresh_token // empty')
  EXPIRES_IN=$(echo "${RESPONSE}" | jq -r '.expires_in // 3600')

  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    error "서버 응답에 access_token 없음. 응답: ${RESPONSE}"
    exit 1
  fi

  cat <<EOF > "${ETC_DIR}/.env"
# lastagent 자동 등록으로 생성된 파일

# agent-controller 설정
CONTROLLER_URL=${CONTROLLER_URL}
CLIENT_ID=${CLIENT_ID}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${TOKEN}
AGENT_REFRESH_TOKEN=${REFRESH_TOKEN}
AGENT_TOKEN_EXPIRES_IN=${EXPIRES_IN}

# secure-forwarder 설정 (솔루션 서버 NodePort 경유)
UPSTREAM_URL=http://${CONTROLLER_HOST}:${NODEPORT}/ingest/logs
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

# ────────────── agent.yaml 복사 ──────────────

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

# ────────────── systemd 유닛 설치 ──────────────

install_service_unit "${ETC_DIR}/otel-agent.service" \
  "${SYSTEMD_DIR}/otel-agent.service" \
  "otel-agent"

install_service_unit "${REPO_DIR}/forwarder/secure-forwarder.service" \
  "${SYSTEMD_DIR}/secure-forwarder.service" \
  "secure-forwarder"

install_service_unit "${REPO_DIR}/agent/agent-controller.service" \
  "${SYSTEMD_DIR}/agent-controller.service" \
  "agent-controller"

# ────────────── systemd 적용 및 서비스 시작 ──────────────

systemctl daemon-reload
systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

# ────────────── 상태 요약 ──────────────
echo
log "서비스 상태 요약:"
systemctl --no-pager --full status otel-agent.service         | sed -n '1,8p'
systemctl --no-pager --full status secure-forwarder.service   | sed -n '1,8p'
systemctl --no-pager --full status agent-controller.service   | sed -n '1,8p'

echo
log "설치 완료. 서비스 실행 중입니다."
