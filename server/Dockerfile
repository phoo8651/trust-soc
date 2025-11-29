FROM python:3.11-slim

WORKDIR /app

# 빌드에 필요한 OS 패키지 (psycopg2, 일부 과학 계산 라이브러리용)
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    libpq-dev \
    libyara-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 통합 소스 복사 (solution_server/ 안에 backend, detect, llm, requirements.txt 있다고 가정)
COPY app/ .

# 2. 의존성 설치
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. 소스 코드 및 스크립트 복사
COPY . .

# 4. start-all.sh 실행 권한 부여
RUN chmod +x start-all.sh

# 5. 환경 설정 (기본값)
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# 6. 실행 명령 변경 (스크립트 사용)
CMD ["./start-all.sh"]
