#!/usr/bin/env bash
set -euo pipefail

# lastagent 설치 스크립트
# - otel-agent + secure-forwarder + agent-controller 설치
# - 솔루션 서버에 에이전트 등록 (AGENT_TOKEN 받기)
# - .env 자동 생성 (INGEST_ENDPOINT / LOCAL_TOKEN / UPSTREAM_URL 등)

# ===== 환경에 맞게 바꿀 수 있는 값들 =====
LAST_USER="last"                        # 코드가 있는 리눅스 계정
REPO_DIR="/home/${LAST_USER}/lastagent" # lastagent 리포지토리 위치

AGENT_USER="otel-agent"                 # OTEL 에이전트 실행 계정
AGENT_HOME="/etc/secure-log-agent"      # OTEL 설정/상태 디렉터리
ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# 솔루션 서버 (backend) 정보
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="8000"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"

# 에이전트 등록 시 쓸 값들
BOOTSTRAP_SECRET="dev"
AGENT_VERSION="0.1.0"
CLIENT_ID="default"

echo "[*] agent 설치 시작"

# 0. root 권한 체크
if [[ "${EUID}" -ne 0 ]]; then
  echo "[FATAL] root 권한이 필요합니다 (sudo 사용)"
  exit 1
fi

# 1. 기본 디렉터리 생성
mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${REPO_DIR}/venv"
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib
mkdir -p /var/lib/secure-log-agent/queue

# 2. 시스템 계정 생성 (없으면)
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --home "${AGENT_HOME}" --shell /usr/sbin/nologin "${AGENT_USER}"
fi

# 3. 패키지 설치
apt-get update
apt-get install -y python3 python3-venv curl jq

# 4. Python venv + 패키지
python3 -m venv "${REPO_DIR}/venv"
# venv 안에서만 사용하는 pip
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

# 5. .env 자동 생성 (없을 때만)
if [[ ! -f "${ETC_DIR}/.env" ]]; then
  echo "[*] .env 파일 없음 → 솔루션 서버에 agent 등록 시도 중..."

  HOSTNAME=$(hostname)
  REGISTER_URL="${CONTROLLER_URL}/auth/register"

  # 서버 요구 스키마에 맞춰 JSON payload 구성
  JSON_PAYLOAD=$(cat <<EOF
{
  "client_id": "${CLIENT_ID}",
  "host": "${HOSTNAME}",
  "agent_version": "${AGENT_VERSION}",
  "secret_proof": "${BOOTSTRAP_SECRET}"
}
EOF
)

  RESPONSE=$(curl -s --fail -X POST "${REGISTER_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}") || {
    echo "[ERROR] agent-register 요청 실패. 서버(${REGISTER_URL}) 확인 필요."
    exit 1
  }

  # access_token 꺼내기
  TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token')
  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    echo "[ERROR] 서버 응답에 access_token 없음. 응답: ${RESPONSE}"
    exit 1
  fi

  # otel-agent <-> secure-forwarder 사이에서 쓸 로컬 토큰 하나 생성
  LOCAL_INGEST_TOKEN=$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)

  # .env 내용 생성
  cat <<EOF > "${ETC_DIR}/.env"
########################################
# lastagent 에이전트 설정 (.env)
########################################

# --- 솔루션 서버 제어용 (Agent Controller) ---
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_TOKEN=${TOKEN}

# --- otel-agent → secure-forwarder (로컬 통신) ---
# otel-agent 가 로그를 보낼 주소 (secure-forwarder 가 listen 하는 곳)
INGEST_ENDPOINT=http://127.0.0.1:19000
# otel-agent 가 Authorization: Bearer 에 넣을 토큰
INGEST_TOKEN=${LOCAL_INGEST_TOKEN}

# secure-forwarder 가 로컬 요청을 검증할 때 사용하는 토큰
LOCAL_TOKEN=${LOCAL_INGEST_TOKEN}

# --- secure-forwarder → 솔루션 서버 (ingest) ---
# 솔루션 서버의 로그 수집 엔드포인트 (백엔드 구조에 맞게 필요시 수정)
UPSTREAM_URL=http://${CONTROLLER_HOST}:8000/ingest/logs

# 솔루션 서버에서 발급하는 로그 토큰 / HMAC 키 (서버 쪽 구현에 맞춰 값 교체)
UPSTREAM_LOG_TOKEN=CHANGE_ME_SERVER_LOG_TOKEN
HMAC_SECRET=CHANGE_ME_HMAC_SECRET

# (옵션) secure-forwarder listen 주소/포트 (기본 127.0.0.1:19000)
LISTEN_HOST=127.0.0.1
LISTEN_PORT=19000
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  echo "[+] .env 생성 완료 (${ETC_DIR}/.env)"
else
  echo "[*] 기존 .env 가 있으므로 재사용합니다: ${ETC_DIR}/.env"
fi

# 6. agent.yaml 존재 확인
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  echo "[FATAL] agent.yaml이 없습니다: ${ETC_DIR}/agent.yaml"
  exit 1
fi

# 7. agent.yaml 배포 + 권한
cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"
chown -R "${AGENT_USER}:nogroup" "${AGENT_HOME}" /var/lib/otelcol-contrib /var/lib/secure-log-agent
chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# 8. systemd 유닛 배포
cp "${ETC_DIR}/otel-agent.service" "${SYSTEMD_DIR}/otel-agent.service"
cp "${REPO_DIR}/forwarder/secure-forwarder.service" "${SYSTEMD_DIR}/secure-forwarder.service"
cp "${REPO_DIR}/agent/agent-controller.service" "${SYSTEMD_DIR}/agent-controller.service"

# 9. systemd 리로드 + enable
systemctl daemon-reload
systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

# 10. 서비스 재시작
systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

# 11. 요약 출력
echo
echo "[*] 서비스 상태 요약:"
systemctl --no-pager --full status otel-agent.service | sed -n '1,5p'
systemctl --no-pager --full status secure-forwarder.service | sed -n '1,5p'
systemctl --no-pager --full status agent-controller.service | sed -n '1,5p'

echo
echo "[+] 설치 완료. 서비스 실행 중입니다."
