#!/usr/bin/env bash
set -euo pipefail

#
# lastagent 설치 스크립트
#  - secure-forwarder / agent-controller / otel-agent 한 번에 설치
#  - /auth/register 로 에이전트 등록 → JWT / agent_id 받아서 .env 생성
#

########## 기본 설정 ##########

LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"

AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"

ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# 솔루션 서버 정보
BOOTSTRAP_SECRET="dev"
AGENT_VERSION="1"          # 서버 코드가 숫자 기대한다 해서 1 로 고정
CLIENT_ID="default"

# 서버 NodePort: 30080, 에이전트 등록 엔드포인트: /auth/register
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="30080"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"
REGISTER_PATH="/auth/register"
REGISTER_URL="${CONTROLLER_URL}${REGISTER_PATH}"

########## 헬퍼 ##########

log()    { echo "[*] $*" ; }
error()  { echo "[ERROR] $*" >&2 ; }

install_service_unit() {
  local src="$1" dst="$2" name="$3"
  if [[ -f "$dst" ]]; then
    log "${name} service 이미 존재 → 덮어쓰지 않음: ${dst}"
  else
    log "${name} service 신규 설치 → ${dst}"
    cp "$src" "$dst"
  fi
}

########## 설치 시작 ##########

log "agent 설치 시작"

if [[ "${EUID}" -ne 0 ]]; then
  error "root 권한이 필요합니다. sudo 로 실행하세요."
  exit 1
fi

mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${REPO_DIR}/venv"
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib
mkdir -p /var/lib/secure-log-agent/queue

# 에이전트용 시스템 계정
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  log "시스템 계정 ${AGENT_USER} 생성"
  useradd --system --no-create-home \
    --home "${AGENT_HOME}" \
    --shell /usr/sbin/nologin \
    "${AGENT_USER}"
fi

apt-get update
apt-get install -y python3 python3-venv curl jq

# venv
if [[ ! -d "${REPO_DIR}/venv" ]]; then
  log "Python venv 생성: ${REPO_DIR}/venv"
  python3 -m venv "${REPO_DIR}/venv"
fi

source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

########## .env 자동 생성 (JWT 포함) ##########

if [[ -f "${ETC_DIR}/.env" ]]; then
  log "기존 .env 발견 → 그대로 사용: ${ETC_DIR}/.env"
else
  log ".env 없음 → 서버 /auth/register 로 agent 등록 시도"

  HOSTNAME=$(hostname)

  JSON_PAYLOAD=$(cat <<EOF
{
  "client_id": "${CLIENT_ID}",
  "host": "${HOSTNAME}",
  "agent_version": ${AGENT_VERSION},
  "secret_proof": "${BOOTSTRAP_SECRET}"
}
EOF
)

  log "POST ${REGISTER_URL}"
  RESPONSE=$(curl -sS --fail -X POST "${REGISTER_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}") || {
      error "agent-register 요청 실패. 서버/포트/방화벽 확인 필요. (${REGISTER_URL})"
      exit 1
    }

  TOKEN=$(echo "${RESPONSE}"        | jq -r '.access_token // empty')
  AGENT_ID=$(echo "${RESPONSE}"     | jq -r '.agent_id // empty')
  REFRESH_TOKEN=$(echo "${RESPONSE}"| jq -r '.refresh_token // empty')
  EXPIRES_IN=$(echo "${RESPONSE}"   | jq -r '.expires_in // 3600')

  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    error "서버 응답에 access_token 없음. 응답: ${RESPONSE}"
    exit 1
  fi

  # 이 TOKEN 을 **컨트롤러 + ingest 로그 둘 다**에서 사용
  cat <<EOF > "${ETC_DIR}/.env"
# agent-controller 설정
CONTROLLER_URL=${CONTROLLER_URL}
CLIENT_ID=${CLIENT_ID}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${TOKEN}
AGENT_REFRESH_TOKEN=${REFRESH_TOKEN}
AGENT_TOKEN_EXPIRES_IN=${EXPIRES_IN}

# secure-forwarder 설정
UPSTREAM_URL=http://${CONTROLLER_HOST}:30080/ingest/logs
UPSTREAM_LOG_TOKEN=${TOKEN}          # ← 여기 중요: 고정 dev 토큰 대신 JWT
HMAC_SECRET=super_secret_hmac_key    # 서버와 맞춰 쓰거나, 필요 없으면 검증 쪽에서 미사용 처리
LOCAL_TOKEN=dev_agent_token          # otel-agent 와 맞춰야 하는 로컬 토큰
LISTEN_HOST=127.0.0.1
LISTEN_PORT=19000
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  log ".env 생성 완료 → ${ETC_DIR}/.env"
fi

########## agent.yaml 복사 ##########

if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  error "agent.yaml 이 없음: ${ETC_DIR}/agent.yaml"
  exit 1
fi

cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"

chown -R "${AGENT_USER}:nogroup" \
  "${AGENT_HOME}" \
  /var/lib/otelcol-contrib \
  /var/lib/secure-log-agent

chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

########## systemd 유닛 설치 ##########

install_service_unit "${ETC_DIR}/otel-agent.service" \
  "${SYSTEMD_DIR}/otel-agent.service" \
  "otel-agent"

install_service_unit "${REPO_DIR}/forwarder/secure-forwarder.service" \
  "${SYSTEMD_DIR}/secure-forwarder.service" \
  "secure-forwarder"

install_service_unit "${REPO_DIR}/agent/agent-controller.service" \
  "${SYSTEMD_DIR}/agent-controller.service" \
  "agent-controller"

systemctl daemon-reload
systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

echo
log "서비스 상태 요약:"
systemctl --no-pager --full status otel-agent.service       | sed -n '1,8p'
systemctl --no-pager --full status secure-forwarder.service | sed -n '1,8p'
systemctl --no-pager --full status agent-controller.service | sed -n '1,8p'
echo
log "설치 완료. 서비스 실행 중입니다."
