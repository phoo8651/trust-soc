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

echo "[*] agent 설치 시작"

# 1. Root 권한 확인
if [[ "${EUID}" -ne 0 ]]; then
  echo "root 권한이 필요합니다 (sudo 사용)"
  exit 1
fi

# 2. 필수 디렉토리 생성
mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${REPO_DIR}/venv"
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib
mkdir -p /var/lib/secure-log-agent/queue

# 3. 시스템 계정 생성
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --home "${AGENT_HOME}" --shell /usr/sbin/nologin "${AGENT_USER}"
fi

# 4. 패키지 설치
apt-get update
apt-get install -y python3 python3-venv curl

# 5. Python venv 생성 + 패키지 설치
python3 -m venv "${REPO_DIR}/venv"
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip
pip install requests PyYAML
deactivate

# 6. .env 자동 생성
if [[ ! -f "${ETC_DIR}/.env" ]]; then
  echo "[*] .env 파일 없음 → 솔루션 서버에서 값 가져오는 중..."
  HOSTNAME=$(hostname)
  REGISTER_URL="http://192.168.67.131:8000/api/agent-register?hostname=${HOSTNAME}"
  RESPONSE=$(curl -s --fail "${REGISTER_URL}") || {
    echo " .env 자동 생성 실패. 서버 연결 안됨."
    exit 1
  }

  ENDPOINT=$(echo "$RESPONSE" | grep -oP '"endpoint"\s*:\s*"\K[^"]+')
  TOKEN=$(echo "$RESPONSE" | grep -oP '"token"\s*:\s*"\K[^"]+')

  if [[ -z "$ENDPOINT" || -z "$TOKEN" ]]; then
    echo "[ERROR] endpoint 또는 token 누락"
    exit 1
  fi

  cat <<EOF > "${ETC_DIR}/.env"
INGEST_ENDPOINT=${ENDPOINT}
INGEST_TOKEN=${TOKEN}
CONTROLLER_URL=http://192.168.67.131:8000
AGENT_TOKEN=${TOKEN}
EOF
  echo "[+] .env 생성 완료"
fi

chmod 600 "${ETC_DIR}/.env"
chown root:root "${ETC_DIR}/.env"

# 7. agent.yaml 확인
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  echo "[FATAL] agent.yaml이 없습니다: ${ETC_DIR}/agent.yaml"
  exit 1
fi

# 8. agent.yaml 복사 및 권한
cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"
chown -R "${AGENT_USER}:nogroup" "${AGENT_HOME}" /var/lib/otelcol-contrib /var/lib/secure-log-agent
chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# 9. 서비스 유닛 배포
cp "${ETC_DIR}/otel-agent.service" "${SYSTEMD_DIR}/otel-agent.service"
cp "${REPO_DIR}/forwarder/secure-forwarder.service" "${SYSTEMD_DIR}/secure-forwarder.service"
cp "${REPO_DIR}/agent/agent-controller.service" "${SYSTEMD_DIR}/agent-controller.service"

systemctl daemon-reload
systemctl enable otel-agent.service
systemctl enable secure-forwarder.service
systemctl enable agent-controller.service

# 10. 서비스 시작
systemctl restart otel-agent.service
systemctl restart secure-forwarder.service
systemctl restart agent-controller.service

# 11. 상태 출력
echo
echo "[*] 서비스 상태 요약:"
systemctl --no-pager --full status otel-agent.service | sed -n '1,5p'
systemctl --no-pager --full status secure-forwarder.service | sed -n '1,5p'
systemctl --no-pager --full status agent-controller.service | sed -n '1,5p'

echo
echo "[+] 설치 완료. 서비스 실행 중입니다."
