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

# 사용자 설정
LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"
AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"

ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"
VENVDIR="${REPO_DIR}/venv"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Root 권한으로 실행해야 합니다."
  exit 1
fi

# 디렉토리 생성
mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${VENVDIR}"
mkdir -p /var/lib/secure-log-agent/queue /var/lib/otelcol-contrib
mkdir -p "${AGENT_HOME}/remote.d"
chown -R "${AGENT_USER}:nogroup" /var/lib/secure-log-agent || true

# 파이썬 및 venv 설치
if ! command -v python3 >/dev/null; then
  apt-get update && apt-get install -y python3
fi
if ! python3 -m venv --help >/dev/null; then
  apt-get update && apt-get install -y python3-venv
fi

# venv 설정 및 패키지 설치
if [[ ! -d "${VENVDIR}" ]]; then
  python3 -m venv "${VENVDIR}"
fi

source "${VENVDIR}/bin/activate"
pip install --upgrade pip
pip install requests PyYAML
deactivate

# .env 파일 생성
if [[ ! -f "${ETC_DIR}/.env" ]]; then
  HOSTNAME=$(hostname)
  RESPONSE=$(curl -s --fail "http://192.168.67.131:8000/api/agent-register?hostname=${HOSTNAME}") || exit 1
  ENDPOINT=$(echo "$RESPONSE" | grep -oP '"endpoint"\s*:\s*"\K[^"]+')
  TOKEN=$(echo "$RESPONSE" | grep -oP '"token"\s*:\s*"\K[^"]+')
  [[ -z "$ENDPOINT" || -z "$TOKEN" ]] && exit 1

  cat <<EOF > "${ETC_DIR}/.env"
INGEST_ENDPOINT=${ENDPOINT}
INGEST_TOKEN=${TOKEN}
CONTROLLER_URL=http://192.168.67.131:8000
AGENT_TOKEN=${TOKEN}
EOF
fi

chmod 600 "${ETC_DIR}/.env"
chown root:root "${ETC_DIR}/.env"

# 에이전트 설정
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  echo "agent.yaml 없음"
  exit 1
fi

# 시스템 계정 생성
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --home "${AGENT_HOME}" --shell /usr/sbin/nologin "${AGENT_USER}"
fi

cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"
chown -R "${AGENT_USER}:nogroup" "${AGENT_HOME}" /var/lib/otelcol-contrib
chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# systemd 등록
cp "${ETC_DIR}/otel-agent.service" "${SYSTEMD_DIR}/otel-agent.service"
cp "${REPO_DIR}/forwarder/secure-forwarder.service" "${SYSTEMD_DIR}/secure-forwarder.service"
cp "${REPO_DIR}/agent/agent-controller.service" "${SYSTEMD_DIR}/agent-controller.service"

systemctl daemon-reexec
systemctl daemon-reload

systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

# 상태 확인 (요약)
systemctl --no-pager --full status otel-agent.service | sed -n '1,6p'
systemctl --no-pager --full status secure-forwarder.service | sed -n '1,6p'
systemctl --no-pager --full status agent-controller.service | sed -n '1,6p'
