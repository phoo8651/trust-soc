#!/usr/bin/env bash
set -euo pipefail

#
# lastagent 설치 스크립트
#  - 에이전트 스택(secure-forwarder, agent-controller, otel-agent)을 한 번에 설치/등록
#  - .env 자동 생성 (솔루션 서버에 agent register 요청)
#  - 이미 설치된 service 유닛은 "덮어쓰지 않도록" 수정됨
#

# ───────────────── 기본 환경 설정 ─────────────────

# lastagent 코드를 배포한 리눅스 계정 (예: ubuntu, ec2-user 등)
LAST_USER="last"

# lastagent 리포지토리 위치
REPO_DIR="/home/${LAST_USER}/lastagent"

# OTEL 에이전트를 실행할 시스템 계정
AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"

# 설정 파일, systemd 유닛 경로
ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# 솔루션 서버(컨트롤러) 정보
BOOTSTRAP_SECRET="dev"
AGENT_VERSION="0.1.0"
CLIENT_ID="default"

# ※ 여기 IP/PORT를 솔루션 서버에 맞게 조정
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="9000"              # NodePort(또는 포트포워딩) 기준 포트
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"
REGISTER_PATH="/api/agent-register" # 백엔드에서 사용하는 실제 경로
REGISTER_URL="${CONTROLLER_URL}${REGISTER_PATH}"

# ───────────────── Helper 함수 ─────────────────

log() {
  echo "[*] $*"
}

error() {
  echo "[ERROR] $*" >&2
}

# systemd 서비스 유닛을 "있을 때는 덮어쓰지 않고" 설치
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

# ───────────────── 설치 시작 ─────────────────

log "agent 설치 시작"

# 1. Root 권한 확인
if [[ "${EUID}" -ne 0 ]]; then
  error "root 권한이 필요합니다. sudo로 실행하세요."
  exit 1
fi

# 2. 필수 디렉터리 생성
mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${REPO_DIR}/venv"
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib
mkdir -p /var/lib/secure-log-agent/queue

# 3. 시스템 계정 생성 (없을 때만)
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  log "시스템 계정 ${AGENT_USER} 생성"
  useradd --system --no-create-home \
    --home "${AGENT_HOME}" \
    --shell /usr/sbin/nologin \
    "${AGENT_USER}"
fi

# 4. 패키지 설치
apt-get update
apt-get install -y python3 python3-venv curl jq

# 5. Python venv 생성 + 패키지 설치 (없을 때만 생성)
if [[ ! -d "${REPO_DIR}/venv" ]]; then
  log "Python venv 생성: ${REPO_DIR}/venv"
  python3 -m venv "${REPO_DIR}/venv"
fi

# venv 안에 필요한 패키지 설치/업데이트
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

# 6. .env 자동 생성 (없을 때만 생성)
if [[ -f "${ETC_DIR}/.env" ]]; then
  log "기존 .env 파일 있으므로 재사용합니다: ${ETC_DIR}/.env"
else
  log ".env 파일 없음 → 서버에 agent 등록 시도 중..."

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
      error "agent-register 요청 실패. 서버/포트/방화벽을 확인하세요. (${REGISTER_URL})"
      exit 1
    }

  # 응답에서 access_token 추출 (필요하면 agent_id, refresh_token도 추가로 저장 가능)
  TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token // empty')

  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    error "서버 응답에 access_token 없음. 응답: ${RESPONSE}"
    exit 1
  fi

  cat <<EOF > "${ETC_DIR}/.env"
# 생성된 에이전트 환경 변수 (.env)
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_TOKEN=${TOKEN}
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

# 8. agent.yaml 복사 및 권한 설정
cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"

chown -R "${AGENT_USER}:nogroup" \
  "${AGENT_HOME}" \
  /var/lib/otelcol-contrib \
  /var/lib/secure-log-agent

chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# 9. systemd 서비스 유닛 설치 (이미 있으면 덮어쓰지 않음)
install_service_unit "${ETC_DIR}/otel-agent.service" \
  "${SYSTEMD_DIR}/otel-agent.service" \
  "otel-agent"

install_service_unit "${REPO_DIR}/forwarder/secure-forwarder.service" \
  "${SYSTEMD_DIR}/secure-forwarder.service" \
  "secure-forwarder"

install_service_unit "${REPO_DIR}/agent/agent-controller.service" \
  "${SYSTEMD_DIR}/agent-controller.service" \
  "agent-controller"

# 10. systemd 반영 + enable
systemctl daemon-reload
systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

# 11. 서비스 재시작
systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

# 12. 상태 요약
echo
log "서비스 상태 요약:"
systemctl --no-pager --full status otel-agent.service         | sed -n '1,8p'
systemctl --no-pager --full status secure-forwarder.service   | sed -n '1,8p'
systemctl --no-pager --full status agent-controller.service   | sed -n '1,8p'

echo
log "설치 완료. 서비스 실행 중입니다."
