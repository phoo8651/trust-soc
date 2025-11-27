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
# [사용자 설정]
LAST_USER="last"
REPO_DIR="/home/${LAST_USER}/lastagent"
AGENT_USER="otel-agent"
AGENT_HOME="/etc/secure-log-agent"

ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# ===== root 권한 확인 =====
if [[ "${EUID}" -ne 0 ]]; then
  echo "[FATAL] root 권한으로 실행되어야 합니다."
  exit 1
fi

echo "[INFO] 설치 시작"

# ===== 디렉토리 생성 =====
mkdir -p "${REPO_DIR}"
mkdir -p "${REPO_DIR}/venv"
mkdir -p "${ETC_DIR}"
mkdir -p /var/lib/secure-log-agent/queue || true
mkdir -p /var/lib/otelcol-contrib || true
mkdir -p "${AGENT_HOME}/remote.d" || true

chown -R "${AGENT_USER}:nogroup" /var/lib/secure-log-agent || true

# ===== 필수 패키지 설치 =====
if ! command -v python3 >/dev/null; then
  apt-get update && apt-get install -y python3
fi
if ! python3 -m venv --help >/dev/null; then
  apt-get update && apt-get install -y python3-venv
fi

# ===== Python venv 생성 및 패키지 설치 =====
VENVDIR="${REPO_DIR}/venv"
if [[ ! -d "${VENVDIR}" ]]; then
  python3 -m venv "${VENVDIR}"
fi

source "${VENVDIR}/bin/activate"
pip install --upgrade pip
pip install requests PyYAML
deactivate

# ===== .env 자동 생성 =====
if [[ ! -f "${ETC_DIR}/.env" ]]; then
  echo "[INFO] .env 파일 없음 → 솔루션 서버로 요청"

  HOSTNAME=$(hostname)
  REGISTER_URL="http://192.168.67.131:8000/api/agent-register?hostname=${HOSTNAME}"
  RESPONSE=$(curl -s --fail "${REGISTER_URL}") || {
    echo "[ERROR] 등록 실패 - 서버 응답 없음"; exit 1;
  }

  ENDPOINT=$(echo "$RESPONSE" | grep -oP '"endpoint"\s*:\s*"\K[^"]+')
  TOKEN=$(echo "$RESPONSE" | grep -oP '"token"\s*:\s*"\K[^"]+')

  if [[ -z "$ENDPOINT" || -z "$TOKEN" ]]; then
    echo "[ERROR] 응답 오류 - endpoint/token 누락"; exit 1;
  fi

  cat <<EOF > "${ETC_DIR}/.env"
INGEST_ENDPOINT=${ENDPOINT}
INGEST_TOKEN=${TOKEN}
CONTROLLER_URL=http://192.168.67.131:8000
AGENT_TOKEN=${TOKEN}
EOF

  echo "[INFO] .env 자동 생성 완료"
fi

chmod 600 "${ETC_DIR}/.env"
chown root:root "${ETC_DIR}/.env"

# ===== 에이전트 설정 =====
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  echo "[FATAL] agent.yaml 누락 → ${ETC_DIR}/agent.yaml 확인 필요"
  exit 1
fi

# 시스템 계정 생성
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --home "${AGENT_HOME}" --shell /usr/sbin/nologin "${AGENT_USER}"
fi

# 설정 복사 및 권한
cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"
chown -R "${AGENT_USER}:nogroup" "${AGENT_HOME}" /var/lib/otelcol-contrib
chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# ===== systemd 서비스 등록 =====
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

# ===== 상태 확인 =====
echo "서비스 상태:"
systemctl --no-pager --full status otel-agent.service | sed -n '1,5p'
systemctl --no-pager --full status secure-forwarder.service | sed -n '1,5p'
systemctl --no-pager --full status agent-controller.service | sed -n '1,5p'

echo " 설치 완료. ."
