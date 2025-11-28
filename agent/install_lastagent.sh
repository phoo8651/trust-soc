#!/usr/bin/env bash
set -euo pipefail

# lastagent 설치 스크립트
# 이 스크립트는 "에이전트 스택(secure-forwarder, agent-controller, otel-agent)"
# 을 한 번에 설치/등록하는 용도입니다.
#
# 기본 예시 환경
#   - 리눅스 계정: last
#   - 코드 경로 : /home/last/lastagent
#   - OTEL 설정: /etc/secure-log-agent/agent.yaml
#
# 환경이 다를 경우 아래 변수 4개만 수정하면 됩니다.
#   - LAST_USER  : 코드를 배포한 리눅스 계정명 (예: ubuntu, ec2-user 등)
#   - REPO_DIR   : lastagent 리포지토리 위치
#   - AGENT_USER : OTEL 에이전트를 실행할 시스템 계정명
#   - AGENT_HOME : OTEL 에이전트 설정/상태 디렉터리

LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"
AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"
ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# 에이전트 등록용 메타데이터
BOOTSTRAP_SECRET="dev"
AGENT_VERSION="0.1.0"
CLIENT_ID="default"

# ──────────────────────────────────────────────
# 컨트롤러(솔루션 서버) 위치
#  - 백엔드: http://192.168.67.131:8000
#  - AgentRegister: /auth/register
# ──────────────────────────────────────────────
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="8000"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"

echo "[*] agent 설치 시작"

# 1. root 권한 확인
if [[ "${EUID}" -ne 0 ]]; then
  echo "root 권한이 필요합니다 (sudo 사용)"
  exit 1
fi

# 2. 필수 디렉터리 생성
mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${REPO_DIR}/venv"
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib
mkdir -p /var/lib/secure-log-agent/queue

# 3. 시스템 계정 생성 (otelcol 전용 계정, 서비스는 지금 root로 돌리더라도 남겨둠)
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --home "${AGENT_HOME}" --shell /usr/sbin/nologin "${AGENT_USER}"
fi

# 4. 패키지 설치
apt-get update
apt-get install -y python3 python3-venv curl jq

# 5. Python venv 생성 + 패키지 설치
python3 -m venv "${REPO_DIR}/venv"
# shellcheck disable=SC1091
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

# 6. .env 자동 생성 (없을 때만)
if [[ ! -f "${ETC_DIR}/.env" ]]; then
  echo "[*] .env 파일 없음 → 서버에 agent 등록 시도 중..."

  HOSTNAME=$(hostname)
  REGISTER_URL="${CONTROLLER_URL}/auth/register"

  JSON_PAYLOAD=$(cat <<EOF
{
  "client_id": "${CLIENT_ID}",
  "host": "${HOSTNAME}",
  "agent_version": "${AGENT_VERSION}",
  "secret_proof": "${BOOTSTRAP_SECRET}"
}
EOF
)

  RESPONSE=$(curl -s --fail -X POST "$REGISTER_URL" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}") || {
    echo "[ERROR] agent-register 요청 실패."
    echo "        서버가 열려 있는지, 포트/경로(${REGISTER_URL})가 맞는지 확인하세요."
    exit 1
  }

  # 서버 응답(JSON)에서 필드 추출
  AGENT_ID=$(echo "$RESPONSE"        | jq -r '.agent_id // empty')
  ACCESS_TOKEN=$(echo "$RESPONSE"    | jq -r '.access_token // empty')
  REFRESH_TOKEN=$(echo "$RESPONSE"   | jq -r '.refresh_token // empty')
  EXPIRES_IN=$(echo "$RESPONSE"      | jq -r '.expires_in // empty')

  if [[ -z "$ACCESS_TOKEN" || "$ACCESS_TOKEN" == "null" ]]; then
    echo "[ERROR] 서버 응답에 access_token 필드가 없습니다."
    echo "        응답 내용: $RESPONSE"
    exit 1
  fi

  cat <<EOF > "${ETC_DIR}/.env"
# lastagent 자동 등록으로 생성된 파일
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${ACCESS_TOKEN}
AGENT_REFRESH_TOKEN=${REFRESH_TOKEN}
AGENT_TOKEN_EXPIRES_IN=${EXPIRES_IN}
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  echo "[+] .env 생성 완료: ${ETC_DIR}/.env"
else
  echo "[*] ${ETC_DIR}/.env 이미 존재 → 재사용합니다."
fi

# 7. OTEL 설정 파일 확인
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  echo "[FATAL] agent.yaml이 없습니다: ${ETC_DIR}/agent.yaml"
  exit 1
fi

# 8. OTEL 설정 복사 및 권한
cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"
chown -R "${AGENT_USER}:nogroup" "${AGENT_HOME}" /var/lib/otelcol-contrib /var/lib/secure-log-agent || true
chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# 9. systemd 유닛 배포
cp "${ETC_DIR}/otel-agent.service" "${SYSTEMD_DIR}/otel-agent.service"
cp "${REPO_DIR}/forwarder/secure-forwarder.service" "${SYSTEMD_DIR}/secure-forwarder.service"
cp "${REPO_DIR}/agent/agent-controller.service" "${SYSTEMD_DIR}/agent-controller.service"

# 10. systemd 리로드 및 enable
systemctl daemon-reload
systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

# 11. 서비스 재시작
systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

# 12. 상태 요약 출력
echo
echo "[*] 서비스 상태 요약:"
systemctl --no-pager --full status otel-agent.service | sed -n '1,5p'
systemctl --no-pager --full status secure-forwarder.service | sed -n '1,5p'
systemctl --no-pager --full status agent-controller.service | sed -n '1,5p'

echo
echo "[+] 설치 완료. 서비스 실행 중입니다."
