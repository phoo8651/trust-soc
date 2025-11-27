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

# 사용자 환경 설정
LAST_USER="last"                                 # 리눅스 사용자명
REPO_DIR="/home/${LAST_USER}/lastagent"          # 코드 디렉토리
AGENT_USER="otel-agent"                          # 에이전트 실행 계정
AGENT_HOME="/etc/secure-log-agent"               # 설정 디렉토리

ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# 1. 루트 권한 확인
if [[ "${EUID}" -ne 0 ]]; then
  echo " 루트 권한으로 실행해야 합니다. sudo로 실행하세요."
  exit 1
fi

echo "설치 시작"

# 2. 시스템 패키지 설치
apt-get update
apt-get install -y python3 python3-venv curl

# 3. 에이전트 계정 생성
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  echo "시스템 계정 생성: ${AGENT_USER}"
  useradd --system --no-create-home \
    --home "${AGENT_HOME}" \
    --shell /usr/sbin/nologin \
    "${AGENT_USER}"
fi

# 4. 디렉토리 생성
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/secure-log-agent/queue
mkdir -p /var/lib/otelcol-contrib
mkdir -p "${ETC_DIR}"

# 5. 권한 설정
chown -R ${AGENT_USER}:nogroup "${AGENT_HOME}" /var/lib/secure-log-agent /var/lib/otelcol-contrib
chmod 750 "${AGENT_HOME}"
chmod 700 /var/lib/secure-log-agent/queue

# 6. Python venv 및 라이브러리
echo "Python 가상환경 구성"
VENVDIR="${REPO_DIR}/venv"
python3 -m venv "${VENVDIR}"
source "${VENVDIR}/bin/activate"
pip install --upgrade pip
pip install requests PyYAML
deactivate

# 7. .env 생성 (서버 응답 기반)
if [[ ! -f "${ETC_DIR}/.env" ]]; then
  echo " .env 자동 생성 시도 중..."

  HOSTNAME=$(hostname)
  REGISTER_URL="http://192.168.67.131:8000/api/agent-register?hostname=${HOSTNAME}"
  RESPONSE=$(curl -s --fail "${REGISTER_URL}") || {
    echo "서버 연결 실패. .env 수동 생성 필요."
    exit 1
  }

  ENDPOINT=$(echo "$RESPONSE" | grep -oP '"endpoint"\s*:\s*"\K[^"]+')
  TOKEN=$(echo "$RESPONSE" | grep -oP '"token"\s*:\s*"\K[^"]+')

  if [[ -z "$ENDPOINT" || -z "$TOKEN" ]]; then
    echo "서버 응답에 endpoint 또는 token이 없습니다."
    exit 1
  fi

  cat <<EOF > "${ETC_DIR}/.env"
INGEST_ENDPOINT=${ENDPOINT}
INGEST_TOKEN=${TOKEN}
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"

  echo ".env 파일 생성 완료"
fi

# 8. agent.yaml 복사
if [[ -f "${ETC_DIR}/agent.yaml" ]]; then
  cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"
  chown ${AGENT_USER}:nogroup "${AGENT_HOME}/agent.yaml"
  chmod 640 "${AGENT_HOME}/agent.yaml"
else
  echo " ${ETC_DIR}/agent.yaml 파일이 없습니다."
  exit 1
fi

# 9. systemd 서비스 설치
echo "systemd 서비스 파일 복사"
cp "${ETC_DIR}/otel-agent.service"                 "${SYSTEMD_DIR}/otel-agent.service"
cp "${REPO_DIR}/forwarder/secure-forwarder.service" "${SYSTEMD_DIR}/secure-forwarder.service"
cp "${REPO_DIR}/agent/agent-controller.service"     "${SYSTEMD_DIR}/agent-controller.service"

# 10. systemd 서비스 등록 및 시작
systemctl daemon-reload
systemctl enable otel-agent.service secure-forwarder.service agent-controller.service
systemctl restart otel-agent.service secure-forwarder.service agent-controller.service

echo "설치 및 서비스 시작 완료!"
