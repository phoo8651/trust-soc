1. Goals

- 애플리케이션/NGINX 로그를 안전하게 중앙으로 전송
- 에이전트 코드/서비스를 직접 수정하지 않고, 중앙에서 정책/명령 제어
- 토큰/시크릿 분리, 재전송 방지(HMAC), 최소 권한(systemd 하드닝) 적용
- 새 VM 환경에서도 스크립트 한 번으로 에이전트 스택 설치/등록 가능하게 만들기


2. Architecture Overview
2.1 OTEL Agent (`otel-agent`)

- OpenTelemetry Collector 기반 로그 에이전트
- `filelog` receiver로 `/var/log/nginx/access.log` 수집
- `transform/pii_mask` 로 기본 PII(IP 등) 마스킹
- `batch`, `file_storage`, `queued_retry` 로 무손실/재시도 보장
- OTLP/HTTP exporter:
  - endpoint: `http://127.0.0.1:19000/v1/logs` (Secure Forwarder)
  - token: `LOCAL_TOKEN` (에이전트 전용 토큰)
- 실행:
  - 시스템 계정: `otel-agent`
  - 설정: `/etc/secure-log-agent/agent.yaml`
  - remote 설정: `/etc/secure-log-agent/remote.d/remote.yaml`
2.2 Secure Forwarder

- 위치: `secure-forwarder/secure-forwarder.py`
- 역할:
  - 로컬에서 `/v1/logs` 수신
  - `Authorization: Bearer LOCAL_TOKEN` 검증
  - 중앙 Ingest 서버로 포워딩:
    - `Authorization: Bearer LOG_TOKEN`
    - `X-Request-Timestamp`, `X-Nonce`, `X-Idempotency-Key`,
      `X-Payload-Hash`, `X-Signature` (HMAC-SHA256) 추가
  - 로컬 에이전트와 중앙 서버 사이의 HMAC 게이트웨이 역할
2.3 Agent Controller

- 위치: `agent.controller/agent_controller.py`
- systemd 서비스로 상시 동작
- 주기적으로 Control Server에서 명령 pull
- 지원 명령:
  - `ping` : 연결 확인
  - `reload_agent` : `systemctl restart otel-agent`
  - `update_config` :
    - `/etc/secure-log-agent/remote.d/remote.yaml` 생성/갱신
    - `systemctl reload otel-agent`
- 모든 호출에 `CTRL_TOKEN` + HMAC-SHA256 사용

2.4 Ingest & Control Server (PoC 개요)

- Ingest API (`/v1/logs`)
  - `LOG_TOKEN` + HMAC 검증 후 로그 수신 (현재는 콘솔 출력)
- Control API (에이전트 원격 명령 채널)
  - `POST /api/agents/{id}/commands/enqueue`
  - `GET /api/agents/{id}/commands`
  - `POST /api/agents/{id}/commands/{cmd_id}/ack`
- 저장소는 메모리 기반 (PoC) → 실서비스에서는 DB/Queue로 교체 예정

3. Repository & Runtime Layout

> 기본 예시는 `last` 계정, `/home/last/lastagent` 기준입니다.

 3.1 Repository Layout

```bash
/home/last/lastagent
├── agent/                       # 에이전트 컨트롤러 쪽 코드
│   ├── agent_controller.py
│   └── agent-controller.service
│
├── forwarder/                   # 시큐어 포워더 코드
│   ├── secure-forwarder.py
│   └── secure-forwarder.service
│
├── etc/                         # OTEL/서비스 설정 모음
│   ├── agent.yaml               # OTEL 에이전트 메인 설정
│   ├── otel-agent.service       # OTEL 에이전트 systemd 유닛 템플릿
│   └── .env                     # (로컬 전용, Git에 올리지 않음)
│
├── venv/                        # Python 가상환경 (Git에 X)
│   └── ...                      # site-packages 등
│
├── install_lastagent.sh         # 자동 설치 스크립트
├── .gitignore
└── README.md                    # 에이전트/포워더 + 설치 방법 문서

3.2 Runtime Layout
OTEL 설정: /etc/secure-log-agent/agent.yaml

OTEL remote 설정: /etc/secure-log-agent/remote.d/remote.yaml

OTEL 상태/큐: /var/lib/otelcol-contrib

.env (시크릿): /home/last/lastagent/.env 또는 etc/.env
(실제 .env는 Git에 올리지 않고, .env.example만 공유)

4. New VM Setup (새 VM에 에이전트 스택 설치하기)
이 섹션은 새로운 VM에 Secure Log Agent 스택을 올릴 때 필요한 전체 단계를 정리합니다.

기본 예시는 last 계정, /home/last/lastagent 경로 기준입니다.
다른 계정/경로를 사용할 경우 install_lastagent.sh 상단 변수와 service 파일의 경로를 환경에 맞게 수정해서 사용합니다.

4.1 사전 조건 (Prerequisites)
OS: Ubuntu 계열 (systemd + apt 사용)

root 또는 sudo 권한

VM에서 Ingest/Control 서버로 HTTP(S) 통신 가능해야 함

OpenTelemetry Collector 바이너리(otelcol-contrib)는 별도로 설치
(패키지/압축본 등 환경에 맞게 설치, ExecStart=/usr/local/bin/otelcol-contrib 기준)

4.2 코드 배포
bash
코드 복사
 1. last 계정 생성 (이미 있으면 생략)
sudo useradd -m last

 2. last 계정으로 전환
sudo su - last

3. 리포지토리 배포
cd ~
git clone <THIS_REPO_URL> lastagent
cd ~/lastagent
4.3 .env 작성 (최소 예시)
env
코드 복사
# Secure Forwarder
LOCAL_TOKEN=dev_agent_token
UPSTREAM_URL=http://127.0.0.1:8000/v1/logs
UPSTREAM_LOG_TOKEN=dev_log_token
HMAC_SECRET=super_secret_hmac_key

# OTEL Agent
INGEST_ENDPOINT=http://127.0.0.1:19000
INGEST_TOKEN=dev_agent_token

# Agent Controller
CONTROLLER_URL=http://127.0.0.1:8000
AGENT_TOKEN=dev_ctrl_token
AGENT_ID=agent-01
POLL_INTERVAL=5
실제 운영값은 Ingest/Control 서버에서 발급 받은 토큰과 URL로 교체해야 합니다.

4.4 설치 스크립트 실행
bash
코드 복사
cd ~/lastagent
chmod +x install_lastagent.sh
sudo bash ./install_lastagent.sh
스크립트 주요 동작:

root 권한 체크

python3, python3-venv 설치 확인 및 설치

venv/ 가상환경 생성 + requests, PyYAML 설치

.env, agent.yaml 존재 확인 (없으면 FATAL 종료)

.env 권한 강화 (chmod 600, root:root)

otel-agent 시스템 계정 및 /etc/secure-log-agent, /var/lib/otelcol-contrib 생성

otel-agent.service, secure-forwarder.service, agent-controller.service 를 /etc/systemd/system/ 에 배치

systemctl daemon-reload 후 세 서비스 enable + restart

설치 결과로 각 서비스 status 1~2줄 출력

4.5 설치 후 상태 확인
bash
코드 복사
sudo systemctl status secure-forwarder.service
sudo systemctl status agent-controller.service
sudo systemctl status otel-agent.service

sudo journalctl -fu secure-forwarder.service
sudo journalctl -fu agent-controller.service
sudo journalctl -fu otel-agent.service
5. (옵션) Ingest Server (FastAPI) – 로컬 테스트용
이 부분은 에이전트가 붙을 PoC Ingest 서버를 로컬에서 띄우고 싶을 때 사용합니다.
실제 운영 환경에서는 별도 Ingest 서버 리포지토리 또는 서비스로 분리될 수 있습니다.

5.1 주요 기능
filelog Receiver: 지정된 로그 파일에서 tail 방식으로 수집

memory_limiter, batch: 메모리 보호 및 배치 전송

redaction/secret, transform/encrypt_pii: 민감정보 마스킹 (PoC 규칙)

probabilistic_sampler: 샘플링(예: 50%)

otlphttp Exporter:

INGEST_ENDPOINT, INGEST_TOKEN 환경변수 사용

sending_queue + file_storage 로 디스크 큐 기반 무손실 전송 시도

telemetry.metrics on :8889: 에이전트 내부 메트릭 노출

5.2 준비
bash
코드 복사
sudo apt-get update && sudo apt-get install -y python3.12-venv python3-pip libpq-dev build-essential
# (필요 시) PostgreSQL 설치 후 계정/DB:
# CREATE USER ingest WITH PASSWORD 'ingest_pw';
# CREATE DATABASE socdb OWNER ingest;
5.3 실행
bash
코드 복사
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # 필요시 값 수정
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
5.4 스모크 테스트
bash
코드 복사
# 헬스 체크
curl -s http://127.0.0.1:8000/health

# 클라이언트 등록
curl -s -X POST 'http://127.0.0.1:8000/auth/register' \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "acme",
    "host": "host-01",
    "agent_version": "0.1.0",
    "secret_proof": "dev"
  }'

# 정책 조회 (위 응답의 access_token 사용)
curl -s -H "Authorization: Bearer <여기_토큰>" \
  http://127.0.0.1:8000/policy
5.5 OTEL Agent와 연동 예시
bash
코드 복사
# 설정 파일 배치
sudo mkdir -p /etc/secure-log-agent
sudo cp agent.yaml /etc/secure-log-agent/agent.yaml
sudo cp otel-agent.service /etc/systemd/system/otel-agent.service

# 비밀값/엔드포인트는 systemd override로 주입 (예: /etc/systemd/system/otel-agent.service.d/override.conf)
[Service]
Environment="INGEST_ENDPOINT=http://127.0.0.1:8000"
Environment="INGEST_TOKEN=<여기에_발급받은_access_token>"

# 서비스 적용
sudo systemctl daemon-reload
sudo systemctl enable --now otel-agent
sudo systemctl status otel-agent
