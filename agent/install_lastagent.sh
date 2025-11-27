#!/usr/bin/env bash
set -euo pipefail

# lastagent 설치 스크립트
# 이 스크립트는 "에이전트 스택(secure-forwarder, agent-controller, otel-agent)"
# 을 한 번에 설치/등록하는 용도입니다.
# 기본 예시 환경
#   - 리눅스 계정: last
#   - 코드 경로 : /home/last/lastagent
#   - OTEL 설정: /etc/secure-log-agent/agent.yaml
#
#  환경이 다를 경우 아래 변수 4개만 수정하면 됩니다.
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

BOOTSTRAP_SECRET="dev"
AGENT_VERSION="0.1.0"
CLIENT_ID="default"
CONTROLLER_HOST="192.168.67.131"
CONTROLLER_PORT="8000"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"

echo "[*] agent 설치 시작"

if [[ "${EUID}" -ne 0 ]]; then
  echo "root 권한이 필요합니다 (sudo 사용)"
  exit 1
fi

mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${REPO_DIR}/venv"
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib
mkdir -p /var/lib/secure-log-agent/queue

if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --home "${AGENT_HOME}" --shell /usr/sbin/nologin "${AGENT_USER}"
fi

apt-get update
apt-get install -y python3 python3-venv curl jq

python3 -m venv "${REPO_DIR}/venv"
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML python-dotenv
deactivate

if [[ ! -f "${ETC_DIR}/.env" ]]; then
  echo "[*] .env 파일 없음 → 서버에 agent 등록 시도 중..."

  HOSTNAME=$(hostname)
  REGISTER_URL="${CONTROLLER_URL}/api/agent-register"

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
    echo "agent-register 요청 실패. 서버 연결 확인 필요."
    exit 1
  }

  TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')
  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    echo "서버 응답에 access_token 없음. 응답: $RESPONSE"
    exit 1
  fi

  cat <<EOF > "${ETC_DIR}/.env"
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_TOKEN=${TOKEN}
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  echo "[+] .env 생성 완료"
fi

if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  echo " agent.yaml이 없습니다: ${ETC_DIR}/agent.yaml"
  exit 1
fi

cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"
chown -R "${AGENT_USER}:nogroup" "${AGENT_HOME}" /var/lib/otelcol-contrib /var/lib/secure-log-agent
chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

cp "${ETC_DIR}/otel-agent.service" "${SYSTEMD_DIR}/otel-agent.service"
cp "${REPO_DIR}/forwarder/secure-forwarder.service" "${SYSTEMD_DIR}/secure-forwarder.service"
cp "${REPO_DIR}/agent/agent-controller.service" "${SYSTEMD_DIR}/agent-controller.service"

systemctl daemon-reload
systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

echo
echo "[*] 서비스 상태 요약:"
systemctl --no-pager --full status otel-agent.service | sed -n '1,5p'
systemctl --no-pager --full status secure-forwarder.service | sed -n '1,5p'
systemctl --no-pager --full status agent-controller.service | sed -n '1,5p'

echo
echo " 설치 완료. 서비스 실행 중입니다."

