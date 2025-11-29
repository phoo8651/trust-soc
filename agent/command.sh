#!/usr/bin/env bash
set -euo pipefail

#
# lastagent 설치 스크립트
# - secure-forwarder, agent-controller, otel-agent 설치 및 .env 자동 생성
#

# ───────────── 기본 설정 ─────────────
LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"

AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"

ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# 컨트롤러 서버 정보
BOOTSTRAP_SECRET="dev"
AGENT_VERSION="0.1.0"
CLIENT_ID="default"

CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="30080"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"
REGISTER_PATH="/api/agent-register"
REGISTER_URL="${CONTROLLER_URL}${REGISTER_PATH}"

# ───────────── 함수 ─────────────
log() { echo "[*] $*"; }
error() { echo "[ERROR] $*" >&2; }

install_service_unit() {
  local src="$1"
  local dst="$2"
  local name="$3"

  if [[ -f "$dst" ]]; then
    log "${name} service 이미 존재 → 덮어쓰지 않습니다: ${dst}"
  else
    log "${name} service 설치 → ${dst}"
    cp "$src" "$dst"
  fi
}

# ───────────── 설치 시작 ─────────────

log "Agent 설치 시작"

if [[ "${EUID}" -ne 0 ]]; then
  error "root 권한 필요. sudo로 실행하세요."
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

# 필수 패키지 설치
apt-get update
apt-get install -y python3 python3-venv curl jq

# venv 설치
if [[ ! -d "${REPO_DIR}/venv" ]]; then
  log "venv 생성: ${REPO_DIR}/venv"
  python3 -m venv "${REPO_DIR}/venv"
fi

# 패키지 설치
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

# ───── .env 생성 또는 재사용 ─────
if [[ -f "${ETC_DIR}/.env" ]]; then
  log "기존 .env 사용: ${ETC_DIR}/.env"
else
  log ".env 없음 → 서버에 등록 시도"

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

  log "POST ${REGISTER_URL}"
  RESPONSE=$(curl -sS --fail -X POST "${REGISTER_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}") || {
      error "agent-register 실패. 서버 확인 요망. (${REGISTER_URL})"
      exit 1
    }

  TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token // empty')

  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    error "access_token 없음. 응답: ${RESPONSE}"
    exit 1
  fi

  cat <<EOF > "${ETC_DIR}/.env"
# ───── 에이전트 환경 변수 ─────
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_TOKEN=${TOKEN}

# ───── secure-forwarder 설정 ─────
UPSTREAM_URL=http://${CONTROLLER_HOST}:${CONTROLLER_PORT}/v1/logs
UPSTREAM_LOG_TOKEN=dev_log_token
HMAC_SECRET=super_secret_hmac_key
LISTEN_HOST=127.0.0.1
LISTEN_PORT=19000
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  log ".env 생성 완료"
fi

# ───── agent.yaml 확인 및 복사 ─────
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  error "agent.yaml 없음: ${ETC_DIR}/agent.yaml"
  exit 1
fi

cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"

chown -R "${AGENT_USER}:nogroup" \
  "${AGENT_HOME}" \
  /var/lib/otelcol-contrib \
  /var/lib/secure-log-agent

chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# ───── 서비스 유닛 설치 ─────
install_service_unit "${ETC_DIR}/otel-agent.service" \
  "${SYSTEMD_DIR}/otel-agent.service" "otel-agent"

install_service_unit "${REPO_DIR}/forwarder/secure-forwarder.service" \
  "${SYSTEMD_DIR}/secure-forwarder.service" "secure-forwarder"

install_service_unit "${REPO_DIR}/agent/agent-controller.service" \
  "${SYSTEMD_DIR}/agent-controller.service" "agent-controller"

# ───── systemd 반영 및 enable ─────
systemctl daemon-reload
systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

# ───── 재시작 (테스트 후 사용) ─────
# systemctl restart otel-agent.service
# systemctl restart secure-forwarder.service
# systemctl restart agent-controller.service

# ───── 상태 요약 ─────
echo
log "서비스 상태 요약:"
systemctl --no-pager --full status otel-agent.service       | sed -n '1,8p'
systemctl --no-pager --full status secure-forwarder.service | sed -n '1,8p'
systemctl --no-pager --full status agent-controller.service | sed -n '1,8p'

echo
log "설치 완료. 서비스 실행중중"
