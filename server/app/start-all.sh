#!/usr/bin/env sh
set -e

echo "[entrypoint] waiting for PostgreSQL on ${DB_HOST:-127.0.0.1}:${DB_PORT:-5432}..."

# psycopg2 이용해서 간단하게 연결 될 때까지 대기
python - << 'PY'
import os, time
import psycopg2

host = os.getenv("DB_HOST", "127.0.0.1")
port = int(os.getenv("DB_PORT", "5432"))
dbname = os.getenv("DB_NAME", "logs_db")
user = os.getenv("DB_USER", "postgres")
password = os.getenv("DB_PASS", "password")

while True:
    try:
        conn = psycopg2.connect(
            host=host, port=port, dbname=dbname, user=user, password=password
        )
        conn.close()
        print("[entrypoint] PostgreSQL is ready.")
        break
    except Exception as e:
        print(f"[entrypoint] PostgreSQL not ready yet: {e}")
        time.sleep(2)
PY

# 여기부터는 기존 내용 (backend + llm + detect 시작)
echo "[backend] starting on :8000"
cd /app/backend/postgres
uvicorn main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

echo "[llm] starting on :9000"
cd /app
uvicorn llm.advisor_api:app --host 0.0.0.0 --port 9000 &
LLM_PID=$!

echo "[detect] starting workers"
cd /app/detect
python yara_batch_scanner.py &
YARA_PID=$!
python rollup.py &
ROLLUP_PID=$!
python ml_dedct.py &
ML_PID=$!
python hybrid_detect.py &
HYBRID_PID=$!

echo "[entrypoint] all processes started, waiting..."
wait $BACKEND_PID $LLM_PID $YARA_PID $ROLLUP_PID $ML_PID $HYBRID_PID
EXIT_CODE=$?

echo "[entrypoint] one of the processes exited with code ${EXIT_CODE}, shutting down..."
kill $BACKEND_PID $LLM_PID $YARA_PID $ROLLUP_PID $ML_PID $HYBRID_PID 2>/dev/null || true
exit $EXIT_CODE
