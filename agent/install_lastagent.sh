#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# LastAgent 통합 설치 스크립트 (Updated for Multi-tenancy & Secure Ingest)
#
# 1. 솔루션 서버에 에이전트 등록 (Agent ID, Token 발급)
# 2. .env 파일 생성 (CLIENT_ID, HMAC Key, Updated API Paths)
# 3. Python 가상환경 구성 및 패키지 설치
# 4. Systemd 서비스 등록 및 실행
# ==============================================================================

# [설정] 설치 환경에 맞게 수정하세요
LAST_USER="last"                        # 코드가 위치할 리눅스 계정
REPO_DIR="/home/${LAST_USER}/lastagent" # 설치 디렉토리

AGENT_USER="otel-agent"                 # OTEL 실행 계정
AGENT_HOME="/etc/secure-log-agent"      
ETC_DIR="${REPO_DIR}/etc"
SYSTEMD_DIR="/etc/systemd/system"

# [중요] 솔루션 서버 접속 정보
CONTROLLER_HOST="192.168.67.131"        # 서버 IP (변경 필수)
CONTROLLER_PORT="8000"
CONTROLLER_URL="http://${CONTROLLER_HOST}:${CONTROLLER_PORT}"

# [중요] 인증 및 테넌트 정보
BOOTSTRAP_SECRET="dev"                  # 서버의 AGENT_BOOTSTRAP_SECRET과 일치해야 함
CLIENT_ID="default-client"              # [New] 테넌트 ID (서버의 X-Client-Id 헤더용)
AGENT_VERSION="0.2.0"

# [중요] HMAC 비밀키 (서버의 JOB_SIGNING_SECRET / WEBHOOK_SECRET 등과 협의된 키)
# 보안을 위해 실제 운영 시에는 안전하게 주입해야 합니다.
HMAC_SECRET_VALUE="change_this_to_match_server_secret"

echo "[*] LastAgent 설치를 시작합니다..."

# 0. Root 권한 체크
if [[ "${EUID}" -ne 0 ]]; then
  echo "[FATAL] 이 스크립트는 root 권한으로 실행해야 합니다 (sudo 사용)."
  exit 1
fi

# 1. 디렉토리 생성
echo "[*] 디렉토리 생성 중..."
mkdir -p "${REPO_DIR}" "${ETC_DIR}" "${REPO_DIR}/venv"
mkdir -p "${AGENT_HOME}/remote.d"
mkdir -p /var/lib/otelcol-contrib
mkdir -p /var/lib/secure-log-agent/queue

# 2. 시스템 계정 생성
if ! id -u "${AGENT_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --home "${AGENT_HOME}" --shell /usr/sbin/nologin "${AGENT_USER}"
  echo "[+] 사용자 ${AGENT_USER} 생성 완료"
fi

# 3. 필수 패키지 설치
echo "[*] 시스템 패키지 업데이트 및 설치..."
apt-get update -qq
apt-get install -y python3 python3-venv curl jq

# 4. Python 가상환경 구성
echo "[*] Python 가상환경(venv) 구성..."
python3 -m venv "${REPO_DIR}/venv"
source "${REPO_DIR}/venv/bin/activate"
pip install --upgrade pip -q
# [Update] python-dotenv 추가 (환경변수 로드용)
pip install requests PyYAML python-dotenv -q
deactivate

# 5. 에이전트 등록 및 .env 생성
if [[ ! -f "${ETC_DIR}/.env" ]]; then
  echo "[*] .env 파일이 없습니다. 서버에 에이전트 등록을 시도합니다..."
  echo "    Target: ${CONTROLLER_URL}/auth/register"

  HOSTNAME=$(hostname)
  REGISTER_URL="${CONTROLLER_URL}/auth/register"

  # 등록 요청 Payload
  JSON_PAYLOAD=$(cat <<EOF
{
  "client_id": "${CLIENT_ID}",
  "host": "${HOSTNAME}",
  "agent_version": "${AGENT_VERSION}",
  "secret_proof": "${BOOTSTRAP_SECRET}"
}
EOF
)

  # 등록 API 호출
  RESPONSE=$(curl -s --fail -X POST "${REGISTER_URL}" \
    -H "Content-Type: application/json" \
    -d "${JSON_PAYLOAD}") || {
    echo "[FATAL] 에이전트 등록 실패. 서버 주소(${CONTROLLER_URL})와 BOOTSTRAP_SECRET을 확인하세요."
    exit 1
  }

  # 토큰 파싱
  TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token')
  SERVER_ASSIGNED_AGENT_ID=$(echo "${RESPONSE}" | jq -r '.agent_id')

  if [[ -z "${TOKEN}" || "${TOKEN}" == "null" ]]; then
    echo "[FATAL] 서버 응답에서 토큰을 찾을 수 없습니다. 응답: ${RESPONSE}"
    exit 1
  fi
  
  echo "[+] 에이전트 등록 성공! (ID: ${SERVER_ASSIGNED_AGENT_ID})"

  # 로컬 통신용(OTEL->Forwarder) 랜덤 토큰 생성
  LOCAL_INGEST_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(16))")

  # .env 파일 작성 (업데이트된 변수명 반영)
  cat <<EOF > "${ETC_DIR}/.env"
########################################
# LastAgent Configuration (.env)
# Created at: $(date)
########################################

# [Identity]
AGENT_ID=${SERVER_ASSIGNED_AGENT_ID}
CLIENT_ID=${CLIENT_ID}

# [Server Connection]
CONTROLLER_URL=${CONTROLLER_URL}
AGENT_TOKEN=${TOKEN}
POLL_INTERVAL=5
HMAC_SECRET=${HMAC_SECRET_VALUE}

# [Secure Forwarder -> Server Ingest]
# 서버의 Ingest API 경로와 일치해야 함 (/ingest/logs)
UPSTREAM_URL=${CONTROLLER_URL}/ingest/logs
UPSTREAM_LOG_TOKEN=${TOKEN}

# [Local OTEL -> Secure Forwarder]
INGEST_ENDPOINT=http://127.0.0.1:19000
INGEST_TOKEN=${LOCAL_INGEST_TOKEN}
LOCAL_TOKEN=${LOCAL_INGEST_TOKEN}

# [Forwarder Config]
LISTEN_HOST=127.0.0.1
LISTEN_PORT=19000
FORWARD_INTERVAL=1.0
MAX_FRAGMENT_SIZE=204800
EOF

  chmod 600 "${ETC_DIR}/.env"
  chown root:root "${ETC_DIR}/.env"
  echo "[+] .env 파일 생성 완료 (${ETC_DIR}/.env)"

else
  echo "[*] 기존 .env 파일을 감지했습니다. 등록 과정을 건너뜁니다."
fi

# 6. agent.yaml (OTEL 설정) 확인 및 배포
if [[ ! -f "${ETC_DIR}/agent.yaml" ]]; then
    # agent.yaml이 없으면 기본 템플릿 생성 (필요시)
    echo "[WARN] ${ETC_DIR}/agent.yaml 파일이 없습니다. 기본 파일을 생성합니다."
    # (여기에 기본 agent.yaml 생성 로직을 넣거나, 사용자가 파일 준비했다고 가정)
    # 여기서는 에러 처리
    echo "[FATAL] 배포할 agent.yaml을 찾을 수 없습니다."
    exit 1
fi

echo "[*] 설정 파일 배포..."
cp "${ETC_DIR}/agent.yaml" "${AGENT_HOME}/agent.yaml"
chown -R "${AGENT_USER}:nogroup" "${AGENT_HOME}" /var/lib/otelcol-contrib /var/lib/secure-log-agent
chmod 750 "${AGENT_HOME}"
chmod 640 "${AGENT_HOME}/agent.yaml"

# 7. Systemd 서비스 파일 배포
echo "[*] Systemd 서비스 등록..."
# (주의: 원본 소스 경로가 정확한지 확인 필요, 여기서는 스크립트 실행 위치 기준 가정)
# 실제 사용 시 리포지토리 내의 올바른 경로로 수정하세요.
# 예: cp "${REPO_DIR}/forwarder/secure-forwarder.service" ...

# 편의상 스크립트 내에서 서비스 파일 내용이 있다고 가정하지 않고, 
# 사용자가 제공한 zip 내의 파일 경로를 따른다고 가정합니다.
if [[ -f "${REPO_DIR}/etc/otel-agent.service" ]]; then
    cp "${REPO_DIR}/etc/otel-agent.service" "${SYSTEMD_DIR}/otel-agent.service"
fi
if [[ -f "${REPO_DIR}/forwarder/secure-forwarder.service" ]]; then
    cp "${REPO_DIR}/forwarder/secure-forwarder.service" "${SYSTEMD_DIR}/secure-forwarder.service"
fi
if [[ -f "${REPO_DIR}/agent/agent-controller.service" ]]; then
    cp "${REPO_DIR}/agent/agent-controller.service" "${SYSTEMD_DIR}/agent-controller.service"
fi

# 8. 서비스 시작
echo "[*] 서비스 재시작..."
systemctl daemon-reload
systemctl enable otel-agent secure-forwarder agent-controller
systemctl restart otel-agent secure-forwarder agent-controller

# 9. 상태 확인
echo "----------------------------------------------------------------"
echo " Installation Completed."
echo " Checking service status..."
echo "----------------------------------------------------------------"
systemctl --no-pager status secure-forwarder.service | head -n 3
echo "..."
systemctl --no-pager status agent-controller.service | head -n 3
echo "----------------------------------------------------------------"
echo " 로그 확인:"
echo "   journalctl -fu secure-forwarder"
echo "   journalctl -fu agent-controller"
echo "----------------------------------------------------------------"