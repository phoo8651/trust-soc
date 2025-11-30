#!/usr/bin/env bash
set -euo pipefail

# lastagent 토큰 갱신(/auth/renew) 스크립트

LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"
ETC_DIR="${REPO_DIR}/etc"
ENV_FILE="${ETC_DIR}/.env"

# 솔루션 서버
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="30080"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"
RENEW_URL="${CONTROLLER_URL}/auth/renew"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "${ENV_FILE} 이 없습니다. 먼저 설치/등록부터 하세요."
  exit 1
fi

# .env 로드
set -a
source "${ENV_FILE}"
set +a

if [[ -z "${AGENT_ID:-}" || -z "${AGENT_REFRESH_TOKEN:-}" ]]; then
  echo "AGENT_ID 또는 AGENT_REFRESH_TOKEN 이 .env 에 없습니다."
  exit 1
fi

echo "[*] /auth/renew 호출:"
echo "    agent_id       = ${AGENT_ID}"
echo "    refresh_token  = ${AGENT_REFRESH_TOKEN}"

JSON_PAYLOAD=$(cat <<EOF
{
  "agent_id": "${AGENT_ID}",
  "refresh_token": "${AGENT_REFRESH_TOKEN}"
}
EOF
)

RAW_RESP=$(curl -sS -w '\n%{http_code}' -X POST "${RENEW_URL}" \
  -H "Content-Type: application/json" \
  -d "${JSON_PAYLOAD}")

HTTP_STATUS=$(echo "${RAW_RESP}" | tail -n1)
BODY=$(echo "${RAW_RESP}" | sed '$d')

echo "HTTP status: ${HTTP_STATUS}"

if [[ "${HTTP_STATUS}" != "200" && "${HTTP_STATUS}" != "201" ]]; then
  echo "/auth/renew 실패 (HTTP ${HTTP_STATUS})"
  echo "${BODY}"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  apt-get update && apt-get install -y jq
fi

NEW_ACCESS=$(echo "${BODY}" | jq -r '.access_token // empty')
NEW_REFRESH=$(echo "${BODY}" | jq -r '.refresh_token // empty')
NEW_EXPIRES=$(echo "${BODY}" | jq -r '.expires_in // 3600')

if [[ -z "${NEW_ACCESS}" || "${NEW_ACCESS}" == "null" ]]; then
  echo "응답에서 access_token 을 읽지 못했습니다."
  echo "${BODY}"
  exit 1
fi

echo "갱신 성공:"
echo "    access_token  = ${NEW_ACCESS}"
echo "    refresh_token = ${NEW_REFRESH}"
echo "    expires_in    = ${NEW_EXPIRES}"

# .env 안의 토큰 부분만 교체
tmp="${ENV_FILE}.tmp.$$"
awk -v at="${NEW_ACCESS}" -v rt="${NEW_REFRESH}" -v ex="${NEW_EXPIRES}" '
  /^AGENT_TOKEN=/            { print "AGENT_TOKEN=" at; next }
  /^AGENT_REFRESH_TOKEN=/    { print "AGENT_REFRESH_TOKEN=" rt; next }
  /^AGENT_TOKEN_EXPIRES_IN=/ { print "AGENT_TOKEN_EXPIRES_IN=" ex; next }
  { print }
' "${ENV_FILE}" > "${tmp}"

mv "${tmp}" "${ENV_FILE}"
chmod 600 "${ENV_FILE}"
chown root:root "${ENV_FILE}"

echo " .env 토큰 값이 갱신되었습니다."
systemctl restart secure-forwarder.service agent-controller.service

echo " 완료!"
