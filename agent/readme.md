# Ingest Server (FastAPI)

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
