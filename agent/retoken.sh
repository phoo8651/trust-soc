#!/usr/bin/env bash
set -euo pipefail

# lastagent 토큰 갱신 스크립트 (/auth/renew 사용)

BASE_DIR="/home/last/lastagent"
ENV_FILE="${BASE_DIR}/etc/.env"

log()   { echo "[token] $*"; }
error() { echo "[token][ERROR] $*" >&2; }

if [[ "${EUID}" -ne 0 ]]; then
  error "root 권한이 필요합니다. sudo로 실행하세요."
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  error ".env 파일을 찾을 수 없습니다: ${ENV_FILE}"
  error "먼저 command.sh 로 설치를 완료해야 합니다."
  exit 1
fi

# .env 로드
# (주석 줄은 source 에 영향 없음)
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

: "${CONTROLLER_URL:?CONTROLLER_URL 이 .env 에 없습니다}"
: "${AGENT_ID:?AGENT_ID 가 .env 에 없습니다}"
: "${AGENT_REFRESH_TOKEN:?AGENT_REFRESH_TOKEN 이 .env 에 없습니다}"

RENEW_URL="${CONTROLLER_URL}/auth/renew"

JSON_PAYLOAD=$(cat <<EOF
{
  "agent_id": "${AGENT_ID}",
  "refresh_token": "${AGENT_REFRESH_TOKEN}"
}
EOF
)

log "▶ POST ${RENEW_URL}"
log "[*] payload: ${JSON_PAYLOAD}"

RESPONSE=$(
  curl -sS -w "\n%{http_code}" -X POST "${RENEW_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}"
) || {
  error "/auth/renew 요청 실패"
  exit 1
}

HTTP_STATUS=$(echo "${RESPONSE}" | tail -n1)
BODY=$(echo "${RESPONSE}" | sed '$d')

if [[ "${HTTP_STATUS}" != "200" ]]; then
  error "HTTP status: ${HTTP_STATUS}"
  error "서버 응답: ${BODY}"
  exit 1
fi

log "[*] HTTP status: ${HTTP_STATUS}"
log "[*] response body: ${BODY}"

NEW_TOKEN=$(echo "${BODY}"        | jq -r '.access_token // empty')
NEW_REFRESH=$(echo "${BODY}"      | jq -r '.refresh_token // empty')
NEW_EXPIRES=$(echo "${BODY}"      | jq -r '.expires_in // 3600')

if [[ -z "${NEW_TOKEN}" || "${NEW_TOKEN}" == "null" ]]; then
  error "access_token 파싱 실패. 응답: ${BODY}"
  exit 1
fi

TMP_FILE=$(mktemp)

# .env 내용을 읽으면서 토큰 관련 라인만 교체
while IFS= read -r line; do
  case "${line}" in
    AGENT_TOKEN=*)
      echo "AGENT_TOKEN=${NEW_TOKEN}"
      ;;
    AGENT_REFRESH_TOKEN=*)
      echo "AGENT_REFRESH_TOKEN=${NEW_REFRESH}"
      ;;
    AGENT_TOKEN_EXPIRES_IN=*)
      echo "AGENT_TOKEN_EXPIRES_IN=${NEW_EXPIRES}"
      ;;
    *)
      echo "${line}"
      ;;
  esac
done < "${ENV_FILE}" > "${TMP_FILE}"

mv "${TMP_FILE}" "${ENV_FILE}"
chmod 600 "${ENV_FILE}"
chown root:root "${ENV_FILE}"

log ".env 토큰 정보 갱신 완료"

# agent-controller 는 .env 를 읽어서 실행되므로 토큰 갱신 후 재시작
log "agent-controller.service 재시작"
systemctl restart agent-controller.service

log "완료"
