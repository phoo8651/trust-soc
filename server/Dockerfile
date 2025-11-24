FROM python:3.11-slim

WORKDIR /app

# 빌드에 필요한 OS 패키지 (psycopg2, 일부 과학 계산 라이브러리용)
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# 통합 소스 복사 (solution_server/ 안에 backend, detect, llm, requirements.txt 있다고 가정)
COPY app/ .

# LLM 패키지 초기화 파일 정리 (_init_.py → __init__.py)
RUN [ -f llm/_init_.py ] && mv llm/_init_.py llm/__init__.py || true \
 && [ -f llm/masking/_init_.py ] && mv llm/masking/_init_.py llm/masking/__init__.py || true \
 && [ -f llm/tests/_init_.py ] && mv llm/tests/_init_.py llm/tests/__init__.py || true

# 파이썬 의존성 설치
# - app/requirements.txt (컨테이너 경로: /app/requirements.txt) 사용
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# 통합 실행 스크립트 복사
RUN chmod +x start-all.sh

CMD ["./start-all.sh"]
