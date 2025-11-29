#!/bin/bash
set -e

echo "🚀 Starting SOC Integrated Server..."

# 1. .env 파일이 존재하면 로드 (우선순위: OS환경변수 > .env > 기본값)
if [ -f .env ]; then
    echo "📜 Loading environment from .env file"
    export $(cat .env | grep -v '#' | awk '/=/ {print $1}')
fi

# 2. 필수 환경 변수 기본값 설정 (Docker env나 k8s env가 없으면 이 값 사용)
: "${DATABASE_URL:=postgresql://user:password@localhost:5432/socdb}"
: "${LLM_MODE:=local}"
: "${LOCAL_MODEL:=/app/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf}"

export DATABASE_URL LLM_MODE LOCAL_MODEL PYTHONPATH=$PYTHONPATH:$(pwd)

# 3. 디렉토리 권한 및 존재 여부 체크 (선택 사항)
mkdir -p /app/models /app/data

# 4. 서버 실행
# exec를 사용하여 쉘 프로세스를 uvicorn 프로세스로 대체 (시그널 전달을 위해 중요)
echo "🔥 Executing Uvicorn..."
exec uvicorn main:app --host 0.0.0.0 --port 8000