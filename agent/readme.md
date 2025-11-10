# Ingest Server (FastAPI)
주요 기능
filelog Receiver: 지정된 로그 파일에서 tail 방식으로 수집
memory_limiter, batch: 메모리 보호 및 배치 전송
redaction/secret, transform/encrypt_pii: 민감정보 마스킹 (PoC 규칙)
probabilistic_sampler: 샘플링(예: 50%)
otlphttp Exporter:
INGEST_ENDPOINT, INGEST_TOKEN 환경변수 사용
sending_queue + file_storage 로 디스크 큐 기반 무손실 전송 시도
telemetry.metrics on :8889: 에이전트 내부 메트릭 노출



## 1) 준비
sudo apt-get update && sudo apt-get install -y python3.12-venv python3-pip libpq-dev build-essential
# (필요 시) PostgreSQL 설치 후 계정/DB:
# CREATE USER ingest WITH PASSWORD 'ingest_pw';
# CREATE DATABASE socdb OWNER ingest;

## 2) 실행
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # 필요시 값 수정
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

## 3) 스모크 테스트
curl -s http://127.0.0.1:8000/health
curl -s -X POST 'http://127.0.0.1:8000/auth/register' \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"acme","host":"host-01","agent_version":"0.1.0","secret_proof":"dev"}'
# 응답의 access_token을 아래 Authorization에 넣어서 정책 조회:
curl -s -H "Authorization: Bearer <여기_토큰>" http://127.0.0.1:8000/policy

헬스 체크
curl -s http://127.0.0.1:8000/health

클라이언트 등록
curl -s -X POST 'http://127.0.0.1:8000/auth/register' \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "acme",
    "host": "host-01",
    "agent_version": "0.1.0",
    "secret_proof": "dev"
  }'

  정책 조회
  curl -s -H "Authorization: Bearer <여기_토큰>" \
  http://127.0.0.1:8000/policy


설치 / 실행 (예시)
1.OTel Collector Contrib 설치 (환경에 맞게 변경)
sudo apt-get install -y otelcol-contrib
2.설정 파일 배치
sudo mkdir -p /etc/secure-log-agent
sudo cp agent.yaml /etc/secure-log-agent/agent.yaml
sudo cp otel-agent.service /etc/systemd/system/otel-agent.service
3.비밀값/엔드포인트는 systemd override로 주입
(예시: /etc/systemd/system/otel-agent.service.d/override.conf)
[Service]
Environment="INGEST_ENDPOINT=http://127.0.0.1:8000"     # PoC Ingest 서버
Environment="INGEST_TOKEN=여기에_발급받은_access_token"
4.서비스 적용
sudo systemctl daemon-reload
sudo systemctl enable --now otel-agent
sudo systemctl status otel-agent
