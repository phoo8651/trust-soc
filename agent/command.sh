#!/usr/bin/env bash
set -euo pipefail

#
# lastagent 설치 / 등록 스크립트 (최종)
#
# - .env 없으면 /auth/register 로 에이전트 등록
# - 응답 토큰으로 /home/last/lastagent/etc/.env 생성
# - otel-agent / secure-forwarder / agent-controller 서비스 설치 및 시작
#

########################################
# 0. 기본 경로/계정 설정
########################################

LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"

AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"

ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

########################################
# 1. 솔루션 서버 & 에이전트 메타 정보
########################################

# 솔루션 서버(NodePort 기준)
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="30080"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"

# 에이전트 등록 API
REGISTER_PATH="/auth/register"
REGISTER_URL="${CONTROLLER_URL}${REGISTER_PATH}"

# 로그 인게스트 API
INGEST_PATH="/ingest/logs"
INGEST_URL="${CONTROLLER_URL}${INGEST_PATH}"

# 에이전트 메타 정보
CLIENT_ID="default"
AGENT_VERSION="1"         # 서버 스키마상 string
BOOTSTRAP_SECRET="dev"    # secret_proof 로 사용 (서버와 합의된 값)

# forwarder 기본 설정
LOCAL_TOKEN="dev_agent_token"
HMAC_SECRET="super_secret_hmac_key"
LISTEN_HOST="127.0.0.1"
LISTEN_PORT="19000"

########################################
# 2. Helper 함수
########################################

log()   { echo "[*] $*"; }
error() { echo "[ERROR] $*" >&2; }

install_service_unit() {
  local src="$1"
  local dst="$2"
  local name="$3"

  if [[ -f "${dst}" ]]; then
    log "${name} service 이미 존재 → 덮어쓰지 않습니다: ${dst}"
  else
    log "${name} service 신규 설치 → ${dst}"
    cp "${src}" "${dst}"
  fi
}

########################################
# 3. 설치 준비
########################################

log "agent 설치 시작"

# root 권한 확인
if [[ "${EUID}" -ne 0 ]]; then
  error "root 권한이 필요합니다. sudo 로 실행하세요."
  exit 1
fi

# 디렉터리 준비
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

# venv 설정
if [[ ! -d "${REPO_DIR}/venv" ]]; then
  log "Python venv 생성: ${REPO_DIR}/venv"
  python3 -m venv "${REPO_DIR}/venv"
fi

source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

########################################
# 4. /auth/register 로 에이전트 등록 → .env 생성
########################################

if [[ -f "${ETC_DIR}/.env" ]]; then
  log "기존 .env 파일이 있습니다 → 재사용: ${ETC_DIR}/.env"
else
  log ".env 없음 → 서버에 /auth/register 로 agent 등록 시도..."

  # host 값: 가능하면 IP, 없으면 hostname
  HOST_VALUE=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  if [[ -z "${HOST_VALUE}" ]]; then
    HOST_VALUE="$(hostname)"
  fi

  # 서버 문서 기준 필드: client_id, host, agent_version, secret_proof
  JSON_PAYLOAD=$(cat <<EOF
{
  "client_id": "${CLIENT_ID}",
  "host": "${HOST_VALUE}",
  "agent_version": "${AGENT_VERSION}",
  "secret_proof": "${BOOTSTRAP_SECRET}"
}
EOF
)

  log "▶ POST ${REGISTER_URL}"
  log "  payload: ${JSON_PAYLOAD}"

  # 바디 + HTTP 코드 함께 받기
  RAW_RESPONSE=$(curl -sS -X POST "${REGISTER_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}" \
    -w "HTTPSTATUS:%{http_code}" ) || {
      error "curl 요청 실패. 서버/포트/방화벽을 확인하세요. (${REGISTER_URL})"
      exit 1
    }

  HTTP_STATUS="${RAW_RESPONSE##*HTTPSTATUS:}"
  RESP_BODY="${RAW_RESPONSE%HTTPSTATUS:*}"

  log "  HTTP status: ${HTTP_STATUS}"
  log "  response body: ${RESP_BODY}"

  if [[ "${HTTP_STATUS}" != "200" && "${HTTP_STATUS}" != "201" ]]; then
    error "/auth/register 실패 (HTTP ${HTTP_STATUS})"
    error "서버 응답: ${RESP_BODY}"
    exit 1
  fi

  # 응답에서 토큰/ID 파싱
  AGENT_ID=$(echo "${RESP_BODY}"    | jq -r '.agent_id      // empty')
  ACCESS_TOKEN=$(echo "${RESP_BODY}"| jq -r '.access_token  // empty')
  REFRESH_TOKEN=$(echo "${RESP_BODY}" | jq -r '.refresh_token // empty')
  EXPIRES_IN=$(echo "${RESP_BODY}"  | jq -r '.expires_in    // 3600')

  if [[ -z "${AGENT_ID}" || -z "${ACCESS_TOKEN}" || "${AGENT_ID}" == "null" || "${ACCESS_TOKEN}" == "null" ]]; then
    error "서버 응답에서 agent_id / access_token 을 파싱하지 못했습니다."
    error "응답: ${RESP_BODY}"
    exit 1
  fi

  log "등록 성공: agent_id=${AGENT_ID}"

  # .env 생성 (agent-controller + secure-forwarder 공용)
  cat <<EOF > "${ETC_DIR}/.env"
# lastagent 자동 생성 .env

# 공용 메타 정보
CLIENT_ID=${CLIENT_ID}

# agent-controller 설정
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${ACCESS_TOKEN}
AGENT_REFRESH_TOKEN=${REFRESH_TOKEN}
AGENT_TOKEN_EXPIRES_IN=${EXPIRES_IN}

# secure-forwarder 설정
UPSTREAM_URL=${INGEST_URL}
UPSTREAM_LOG_TOKEN=${ACCESS_TOKEN}   # ingest/logs Authorization 에 사용
HMAC_SECRET=${HMAC_SECRET}
LOCAL_TOKEN=${LOCAL_TOKEN}
LISTEN_HOST=${LISTEN_HOST}
LISTEN_PORT=${LISTEN_PORT}
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  log ".env 생성 완료 → ${ETC_DIR}/.env"
fi

########################################
# 5. agent.yaml 복사 및 권한 설정
########################################

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

########################################
# 6. systemd 유닛 설치
########################################

install_service_unit "${ETC_DIR}/otel-agent.service" \
  "${SYSTEMD_DIR}/otel-agent.service" \
  "otel-agent"

install_service_unit "${REPO_DIR}/forwarder/secure-forwarder.service" \
  "${SYSTEMD_DIR}/secure-forwarder.service" \
  "secure-forwarder"

install_service_unit "${REPO_DIR}/agent/agent-controller.service" \
  "${SYSTEMD_DIR}/agent-controller.service" \
  "agent-controller"

########################################
# 7. 서비스 활성화 & 재시작
########################################

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
