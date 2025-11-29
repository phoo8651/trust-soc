#!/usr/bin/env bash
set -euo pipefail

# ───── 기본 설정 ─────
LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"
ETC_DIR="${REPO_DIR}/etc"

# 서버 정보
BOOTSTRAP_SECRET="dev"
AGENT_VERSION="0.1.0"
CLIENT_ID="default"

# 컨트롤러 주소
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="8000"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"
REGISTER_PATH="/api/agent-register"
REGISTER_URL="${CONTROLLER_URL}${REGISTER_PATH}"

# Ingest log 관련 설정
UPSTREAM_URL="http://192.168.67.131:30080/v1/logs"
UPSTREAM_LOG_TOKEN="dev_log_token"
HMAC_SECRET="super_secret_hmac_key"

# ───── .env 자동 생성 ─────

if [[ -f "${ETC_DIR}/.env" ]]; then
  echo "[*] 기존 .env 파일 있으므로 재사용합니다: ${ETC_DIR}/.env"
else
  echo "[*] .env 파일 없음 → 서버에 agent 등록 시도 중..."

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

  echo "[*] POST ${REGISTER_URL}"
  RESPONSE=$(curl -sS --fail -X POST "${REGISTER_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}") || {
      echo "[ERROR] agent-register 요청 실패. 서버/포트/방화벽을 확인하세요."
      exit 1
  }

  TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token // empty')
  AGENT_ID=$(echo "${RESPONSE}" | jq -r '.agent_id // empty')
  REFRESH_TOKEN=$(echo "${RESPONSE}" | jq -r '.refresh_token // empty')
  EXPIRES_IN=$(echo "${RESPONSE}" | jq -r '.expires_in // 3600')

  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    echo "[ERROR] access_token 없음. 응답: ${RESPONSE}"
    exit 1
  fi

  # 🟢 .env 파일 생성 (Ingest용 변수 포함)
  cat <<EOF > "${ETC_DIR}/.env"
# 자동 생성된 에이전트 환경변수
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${TOKEN}
AGENT_REFRESH_TOKEN=${REFRESH_TOKEN}
AGENT_TOKEN_EXPIRES_IN=${EXPIRES_IN}

# Ingest Log 전송용 환경 변수
UPSTREAM_URL=${UPSTREAM_URL}
UPSTREAM_LOG_TOKEN=${UPSTREAM_LOG_TOKEN}
HMAC_SECRET=${HMAC_SECRET}
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  echo "[*] .env 생성 완료 → ${ETC_DIR}/.env"
fi
