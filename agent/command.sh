#!/usr/bin/env bash
set -euo pipefail

#
# lastagent 설치 스크립트 (서비스 파일 수정 없이 설치)
#  - otel-agent + secure-forwarder + agent-controller 설치
#  - .env 자동 생성 (/auth/register 호출)
#  - 필요한 버퍼 디렉토리(otel_storage) 자동 생성
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

# [입력 확인] 웹 콘솔에서 키를 확인하고 실행 시 환경변수로 주입해야 함
BOOTSTRAP_SECRET=""

# ───────────── Helper 함수 ─────────────

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

# ───────────── 설치 시작 ─────────────

log "agent 설치 시작"

if [[ "${EUID}" -ne 0 ]]; then
  error "root 권한이 필요합니다. sudo로 실행하세요."
  exit 1
fi

mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${REPO_DIR}/venv"
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib

# [수정] 서비스 파일 수정 없이 동작하도록 여기서 디렉토리 생성
# agent.yaml 에서 사용하는 경로를 미리 생성합니다.
log "버퍼 디렉토리 생성: /var/lib/secure-log-agent/otel_storage"
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

# Python venv
if [[ ! -d "${REPO_DIR}/venv" ]]; then
  log "Python venv 생성: ${REPO_DIR}/venv"
  python3 -m venv "${REPO_DIR}/venv"
fi

# venv 안에 필요한 패키지 설치
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

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

  log "▶ POST ${REGISTER_URL}"

  RESPONSE=$(
    curl -sS -w "\n%{http_code}" -X POST "${REGISTER_URL}" \
      -H "Content-Type: application/json" \
      -d "${JSON_PAYLOAD}"
  ) || {
    error "/auth/register 요청 자체가 실패했습니다."
    exit 1
  }

  # 마지막 줄은 HTTP status code, 위는 body
  HTTP_STATUS=$(echo "${RESPONSE}" | tail -n1)
  BODY=$(echo "${RESPONSE}" | sed '$d')

  if [[ "${HTTP_STATUS}" != "200" && "${HTTP_STATUS}" != "201" ]]; then
    error "HTTP status: ${HTTP_STATUS}"
    error "서버 응답: ${BODY}"
    error "/auth/register 요청 실패 (키가 만료되었거나 서버 주소가 틀렸을 수 있습니다)"
    exit 1
  fi

  log "[*] 등록 성공! HTTP status: ${HTTP_STATUS}"

  TOKEN=$(echo "${BODY}"         | jq -r '.access_token // empty')
  AGENT_ID=$(echo "${BODY}"      | jq -r '.agent_id // empty')
  REFRESH_TOKEN=$(echo "${BODY}" | jq -r '.refresh_token // empty')
  EXPIRES_IN=$(echo "${BODY}"    | jq -r '.expires_in // 3600')

  # 로컬 통신용 랜덤 토큰 생성
  LOCAL_TOKEN_VAL=$(python3 -c "import secrets; print(secrets.token_hex(16))")

  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    error "access_token 파싱 실패. 응답: ${BODY}"
    exit 1
  fi

  # .env 생성
  cat <<EOF > "${ENV_FILE}"
# lastagent 자동 생성 환경파일

# [Identity]
CLIENT_ID=${CLIENT_ID}
AGENT_ID=${AGENT_ID}

# [Authentication]
AGENT_TOKEN=${TOKEN}
AGENT_REFRESH_TOKEN=${REFRESH_TOKEN}
AGENT_TOKEN_EXPIRES_IN=${EXPIRES_IN}
HMAC_SECRET=super_secret_hmac_key

# [Connection]
CONTROLLER_URL=http://${CONTROLLER_HOST}:${CONTROLLER_PORT}
UPSTREAM_URL=http://${CONTROLLER_HOST}:${CONTROLLER_PORT}/ingest/logs
UPSTREAM_LOG_TOKEN=${TOKEN} 
POLL_INTERVAL=5

# [Local Communication]
LISTEN_HOST=127.0.0.1
LISTEN_PORT=19000
LOCAL_TOKEN=${LOCAL_TOKEN_VAL}
INGEST_ENDPOINT=http://127.0.0.1:19000
INGEST_TOKEN=${LOCAL_TOKEN_VAL}
EOF

  chmod 600 "${ENV_FILE}"
  chown root:root "${ENV_FILE}"
  log ".env 생성 완료 → ${ENV_FILE}"
fi

# agent.yaml 확인 및 설치
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  error "agent.yaml 이 없습니다: ${ETC_DIR}/agent.yaml"
  exit 1
fi

cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"

# [중요] 권한 설정: otel-agent가 otel_storage에 쓸 수 있도록 소유권 변경
log "권한 설정 적용..."
chown -R "${AGENT_USER}:nogroup" \
  "${AGENT_HOME}" \
  /var/lib/otelcol-contrib \
  /var/lib/secure-log-agent

chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# ───────────── systemd 유닛 설치 ─────────────

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

log "서비스 재시작 중..."
systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

echo
log "서비스 상태 요약:"
systemctl --no-pager status otel-agent.service secure-forwarder.service agent-controller.service | grep "Active:"

echo
log "설치 완료. 에이전트가 실행 중입니다."