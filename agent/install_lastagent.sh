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

# 사용자 정의 변수
LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"
AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"
ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

echo "설치 시작:"

# 1. root 권한 확인
if [[ "${EUID}" -ne 0 ]]; then
  echo "root 권한으로 실행해야 합니다. (예: sudo bash install_agent_stack.sh)"
  exit 1
fi

# 2. 필수 디렉토리 생성 및 권한 설정
mkdir -p /var/lib/secure-log-agent/queue "${AGENT_HOME}/remote.d" /var/lib/otelcol-contrib "${REPO_DIR}" "${ETC_DIR}"
chown -R "${AGENT_USER}:nogroup" /var/lib/secure-log-agent || true

# 3. Python 및 venv 설치
echo "Python 환경 확인"
apt-get update
apt-get install -y python3 python3-venv curl

VENVDIR="${REPO_DIR}/venv"
if [[ ! -d "${VENVDIR}" ]]; then
  python3 -m venv "${VENVDIR}"
fi

source "${VENVDIR}/bin/activate"
pip install --upgrade pip
pip install requests PyYAML
deactivate

# 4. .env 자동 생성
echo ".env 확인 및 자동 생성 시도"
if [[ ! -f "${ETC_DIR}/.env" ]]; then
  HOSTNAME=$(hostname)
  REGISTER_URL="http://192.168.67.131:8000/api/agent-register?hostname=${HOSTNAME}"
  RESPONSE=$(curl -s --fail "${REGISTER_URL}") || true

  ENDPOINT=$(echo "$RESPONSE" | grep -oP '"endpoint"\s*:\s*"\K[^"]+')
  TOKEN=$(echo "$RESPONSE" | grep -oP '"token"\s*:\s*"\K[^"]+')

  if [[ -n "$ENDPOINT" && -n "$TOKEN" ]]; then
    cat <<EOF > "${ETC_DIR}/.env"
INGEST_ENDPOINT=${ENDPOINT}
INGEST_TOKEN=${TOKEN}
CONTROLLER_URL=http://192.168.67.131:8000
AGENT_TOKEN=${TOKEN}
AGENT_ID=${HOSTNAME}
EOF
    echo " .env 자동 생성 완료"
  else
    echo " 자동 생성 실패. ${REGISTER_URL} 확인 필요"
    exit 1
  fi
fi

chmod 600 "${ETC_DIR}/.env"
chown root:root "${ETC_DIR}/.env"

# 5. agent.yaml 확인
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  echo " ${ETC_DIR}/agent.yaml 파일이 없습니다."
  exit 1
fi

# 6. 시스템 사용자 생성
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --home "${AGENT_HOME}" --shell /usr/sbin/nologin "${AGENT_USER}"
fi

# 7. 설정 복사 및 권한
cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"
chown -R "${AGENT_USER}:nogroup" "${AGENT_HOME}" /var/lib/otelcol-contrib
chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# 8. systemd 서비스 등록
echo " systemd 서비스 등록"

cp "${ETC_DIR}/otel-agent.service" "${SYSTEMD_DIR}/otel-agent.service"
cp "${REPO_DIR}/forwarder/secure-forwarder.service" "${SYSTEMD_DIR}/secure-forwarder.service"
cp "${REPO_DIR}/agent/agent-controller.service" "${SYSTEMD_DIR}/agent-controller.service"

systemctl daemon-reload
systemctl enable otel-agent.service || true
systemctl enable secure-forwarder.service || true
systemctl enable agent-controller.service || true

# 9. 서비스 시작
systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

echo "설치 완료"
