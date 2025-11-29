#!/usr/bin/env bash
set -euo pipefail

#
# lastagent 설치 스크립트 (auth/register + ingest/logs 버전)
#
# - otel-agent + secure-forwarder + agent-controller 한 번에 설치
# - /auth/register 로 에이전트 등록해서 JWT 토큰 발급
# - 발급받은 토큰과 설정을 /home/last/lastagent/etc/.env 에 저장
#

########################################
# 0. 기본 설정
########################################

# lastagent 코드를 놓은 계정
LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"

# OTEL 에이전트를 돌릴 시스템 계정
AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"

ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# ───── 솔루션 서버 정보 ─────
BOOTSTRAP_SECRET="dev"        # 필요 없으면 무시, 일단 그대로 둠
AGENT_VERSION="1"             # /auth/register 에 넘길 agent_version (int 또는 str "1")
CLIENT_ID="default"

# 외부에서 접속하는 NodePort
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="30080"       # ← 엔드포인트: http://192.168.67.131:30080/
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"

# 에이전트 등록 API
REGISTER_PATH="/auth/register"
REGISTER_URL="${CONTROLLER_URL}${REGISTER_PATH}"

########################################
# 1. Helper 함수
########################################

log()   { echo "[*] $*"; }
error() { echo "[ERROR] $*" >&2; }

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

########################################
# 2. 설치 준비
########################################

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

source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

########################################
# 3. .env 자동 생성 (/auth/register)
########################################

if [[ -f "${ETC_DIR}/.env" ]]; then
  log "기존 .env 파일 있음 → 우선 재사용합니다: ${ETC_DIR}/.env"
else
  log ".env 파일 없음 → 서버 /auth/register 로 agent 등록 시도..."

  HOSTNAME="$(hostname -I | awk '{print $1}')"
  if [[ -z "${HOSTNAME}" ]]; then
    HOSTNAME="$(hostname)"
  fi

  # 서버가 기대하는 JSON 형식
  #   { "client_id": "...", "host": "...", "agent_version": 1 }
  JSON_PAYLOAD=$(cat <<EOF
{
  "client_id": "${CLIENT_ID}",
  "host": "${HOSTNAME}",
  "agent_version": ${AGENT_VERSION}
}
EOF
)

  log "POST ${REGISTER_URL}"
  # HTTP 상태코드까지 같이 받기
  RAW_RESPONSE=$(curl -sS -X POST "${REGISTER_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}" \
    -w "HTTPSTATUS:%{http_code}" ) || {
      error "curl 자체가 실패했습니다. 네트워크/방화벽을 확인하세요."
      exit 1
    }

  HTTP_STATUS=$(echo "${RAW_RESPONSE}" | sed -n 's/.*HTTPSTATUS://p')
  RESPONSE_BODY=$(echo "${RAW_RESPONSE}" | sed 's/HTTPSTATUS:.*//')

  if [[ "${HTTP_STATUS}" != "200" && "${HTTP_STATUS}" != "201" ]]; then
    error "agent-register  실패 (status=${HTTP_STATUS})"
    echo "  서버 응답: ${RESPONSE_BODY}"
    exit 1
  fi

  # 응답 JSON: { "agent_id": aid, "access_token": acc, "refresh_token": ref, "expires_in": exp }
  AGENT_ID=$(echo "${RESPONSE_BODY}" | jq -r '.agent_id // empty')
  TOKEN=$(echo "${RESPONSE_BODY}" | jq -r '.access_token // empty')
  REFRESH_TOKEN=$(echo "${RESPONSE_BODY}" | jq -r '.refresh_token // empty')
  EXPIRES_IN=$(echo "${RESPONSE_BODY}" | jq -r '.expires_in // 3600')

  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    error "서버 응답에 access_token 없음. 응답: ${RESPONSE_BODY}"
    exit 1
  fi
  if [[ -z "${AGENT_ID}" || "${AGENT_ID}" == "null" ]]; then
    error "서버 응답에 agent_id 없음. 응답: ${RESPONSE_BODY}"
    exit 1
  fi

  # .env 작성
  cat <<EOF > "${ETC_DIR}/.env"
# lastagent 자동 생성된 파일

# agent-controller 설정
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${TOKEN}
AGENT_REFRESH_TOKEN=${REFRESH_TOKEN}
AGENT_TOKEN_EXPIRES_IN=${EXPIRES_IN}

# secure-forwarder 설정
UPSTREAM_URL=http://${CONTROLLER_HOST}:${CONTROLLER_PORT}/ingest/logs
UPSTREAM_LOG_TOKEN=${TOKEN}          # ingest/logs 에 사용하는 JWT
HMAC_SECRET=super_secret_hmac_key
LOCAL_TOKEN=dev_agent_token
LISTEN_HOST=127.0.0.1
LISTEN_PORT=19000
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  log ".env 생성 완료 → ${ETC_DIR}/.env"
fi

########################################
# 4. agent.yaml 복사 및 권한
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
# 5. systemd 유닛 설치
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
