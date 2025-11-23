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

#  [사용자 환경에 맞게 수정 가능한 변수] 
LAST_USER="last"                           # 코드가 위치한 계정명
REPO_DIR="/home/${LAST_USER}/lastagent"    # 리포지토리 루트

AGENT_USER="otel-agent"                    # OTEL 에이전트용 시스템 계정
AGENT_HOME="/etc/secure-log-agent"         # OTEL 에이전트 설정 디렉터리

# 디렉토리 생성 및 권한 설정
mkdir -p /var/lib/secure-log-agent/queue
chown -R otel-agent:nogroup /var/lib/secure-log-agent

# 이 아래부터는 일반적으로 수정 필요 없음
ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# ===== root 확인 ===================================================
if [[ "${EUID}" -ne 0 ]]; then
  echo "[FATAL] 이 스크립트는 root 권한으로 실행해야 합니다."
  echo "  예) sudo bash install_lastagent.sh"
  exit 1
fi

echo "[INFO] lastagent 자동 설치 시작"

#  기본 패키지 설치
echo " 시스템 패키지 설치 확인 (python3, python3-venv)"

if ! command -v python3 >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3-venv
fi

# (필요 시: otelcol-contrib 설치는 별도 가이드 참고)

#  리포지토리 경로 확인
echo " 리포지토리 경로 확인: ${REPO_DIR}"

if [[ ! -d "${REPO_DIR}" ]]; then
  echo "[FATAL] ${REPO_DIR} 디렉터리가 없습니다."
  echo "  -> 먼저 서버에 lastagent 코드를 git clone 또는 scp로 배포한 뒤 다시 실행하세요."
  exit 1
fi

# venv 생성 + 패키지 설치
echo "Python venv 생성 및 패키지 설치"

VENVDIR="${REPO_DIR}/venv"

if [[ ! -d "${VENVDIR}" ]]; then
  python3 -m venv "${VENVDIR}"
fi

# venv 활성화
# shellcheck source=/dev/null
source "${VENVDIR}/bin/activate"

pip install --upgrade pip
pip install requests PyYAML

deactivate

#.env 및 OTEL 설정 확인/권한 
echo " 설정 파일(.env, agent.yaml) 확인"

if [[ ! -f "${ETC_DIR}/.env" ]]; then
  echo "[FATAL] ${ETC_DIR}/.env 파일이 없습니다."
  echo "  -> .env.example을 복사해 토큰/URL을 채운 뒤 다시 실행하세요."
  exit 1
fi

if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
  echo "[FATAL] ${ETC_DIR}/agent.yaml 파일이 없습니다."
  exit 1
fi

# .env는 root만 읽도록 (시크릿 보호)
chmod 600 "${ETC_DIR}/.env"
chown root:root "${ETC_DIR}/.env"

#OTEL 에이전트 전용 계정/디렉터리
echo " otel-agent 시스템 계정 및 디렉터리 준비"

if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home \
    --home "${AGENT_HOME}" \
    --shell /usr/sbin/nologin \
    "${AGENT_USER}"
fi

mkdir -p "${AGENT_HOME}/remote.d" /var/lib/otelcol-contrib

# OTEL 메인 설정 복사
cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"

chown -R "${AGENT_USER}:nogroup" "${AGENT_HOME}" /var/lib/otelcol-contrib
chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

#systemd 서비스 파일 배치 
echo " systemd 서비스 파일 복사"

cp "${ETC_DIR}/otel-agent.service"                 "${SYSTEMD_DIR}/otel-agent.service"
cp "${REPO_DIR}/forwarder/secure-forwarder.service" "${SYSTEMD_DIR}/secure-forwarder.service"
cp "${REPO_DIR}/agent/agent-controller.service"     "${SYSTEMD_DIR}/agent-controller.service"

systemctl daemon-reload

systemctl enable secure-forwarder.service || true
systemctl enable agent-controller.service || true
systemctl enable otel-agent.service || true

# 서비스 시작 
echo " 서비스 시작"

systemctl restart secure-forwarder.service
systemctl restart agent-controller.service
systemctl restart otel-agent.service

echo
systemctl --no-pager --full status secure-forwarder.service | sed -n '1,5p' || true
systemctl --no-pager --full status agent-controller.service    | sed -n '1,5p' || true
systemctl --no-pager --full status otel-agent.service          | sed -n '1,5p' || true

echo
echo "[DONE] lastagent 스택 자동 설치 완료."
echo "  - 설정 파일: ${ETC_DIR}/.env, ${AGENT_HOME}/agent.yaml"
echo "  - 서비스 상태 확인:"
echo "      sudo systemctl status secure-forwarder.service"
echo "      sudo systemctl status agent-controller.service"
echo "      sudo systemctl status otel-agent.service"
