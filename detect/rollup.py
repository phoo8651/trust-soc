#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
feature_rollup_* 테이블에 1m/5m/1h 윈도우별 시계열·통계 피처 집계.
ON CONFLICT → 멱등성 보장
Late arrival 포함(각 윈도우 retention)
Prometheus 지표(롤업 지연 시간) 측정 기능 추가.
"""
import os, sys, logging, psycopg2
from psycopg2.extras import DictCursor
from prometheus_client import start_http_server, Histogram # ⚠️ Prometheus 클라이언트 라이브러리 추가

# ───────────────────────────────────────────────────────────
# 환경변수
# ───────────────────────────────────────────────────────────
# 데이터베이스 연결 정보를 환경 변수에서 가져오거나 기본값 설정
DB_HOST  = os.getenv("DB_HOST", "localhost")
DB_PORT  = os.getenv("DB_PORT", "5432")
DB_NAME  = os.getenv("DB_NAME", "logs_db")
DB_USER  = os.getenv("DB_USER", "postgres")
DB_PASS  = os.getenv("DB_PASS", "password")
PROMETHEUS_PORT = int(os.getenv("PROMETHEUS_PORT", 8000)) # Prometheus 노출 포트

# ───────────────────────────────────────────────────────────
# 로깅
# ───────────────────────────────────────────────────────────
# 로깅 설정: 시간, 레벨, 메시지 형식으로 INFO 레벨 이상 출력
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("rollup")

# ───────────────────────────────────────────────────────────
# 윈도우 정의: (suffix, time_bucket 간격, retention)
# retention 은 해당 윈도우 크기의 2배 이상 권장 (Late arrival 데이터 처리 위함)
# ───────────────────────────────────────────────────────────
WINDOWS = [
    # (테이블 접미사, time_bucket 간격, 데이터 보존 기간)
    ("1m", "1 minute", "2 minutes"),
    ("5m", "5 minutes", "10 minutes"),
    ("1h", "1 hour", "2 hours"),
]

# ───────────────────────────────────────────────────────────
# Prometheus 메트릭 정의
# ───────────────────────────────────────────────────────────
# 롤업 작업 실행 시간을 측정하는 히스토그램 메트릭
ROLLUP_LATENCY = Histogram(
    "rollup_job_latency_seconds",
    "Latency of the feature rollup job (including commit)",
    ["suffix"], # 윈도우 유형(1m, 5m, 1h)별로 분류하기 위한 레이블
    buckets=(0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, float('inf'))
)

# ───────────────────────────────────────────────────────────
# 집계 SQL 템플릿
# ───────────────────────────────────────────────────────────
# PostgreSQL/TimescaleDB의 time_bucket 함수를 사용한 시계열 집계 SQL 템플릿
ROLLUP_SQL = """
-- 집계 결과를 feature_rollup_{suffix} 테이블에 삽입 (또는 업데이트)
INSERT INTO feature_rollup_{suffix} (
    client_id, host_name, source_ip,
    window_start, window_end,
    event_count,
    error4xx_ratio, error5xx_ratio,
    unique_url_count, unique_user_count
)
SELECT
    client_id,
    host_name,
    source_ip,
    bucket AS window_start, -- time_bucket 결과는 윈도우 시작 시간
    bucket + INTERVAL '{interval}' AS window_end, -- 윈도우 시작 시간에 간격을 더하여 윈도우 종료 시간 계산
    COUNT(*) AS event_count, -- 총 이벤트 수
    -- 4xx 에러 비율 계산: 400~499 상태 코드를 1로, 아니면 0으로 세고 총 이벤트 수로 나눔
    SUM(CASE WHEN http_status BETWEEN 400 AND 499 THEN 1 ELSE 0 END)::double precision / COUNT(*) AS error4xx_ratio,
    -- 5xx 에러 비율 계산: 500~599 상태 코드를 1로, 아니면 0으로 세고 총 이벤트 수로 나눔
    SUM(CASE WHEN http_status BETWEEN 500 AND 599 THEN 1 ELSE 0 END)::double precision / COUNT(*) AS error5xx_ratio,
    COUNT(DISTINCT url_path)  AS unique_url_count, -- 고유 URL 경로 수
    COUNT(DISTINCT user_name) AS unique_user_count -- 고유 사용자 수
FROM (
  -- 서브 쿼리: normalized_logs 테이블에서 필요한 컬럼을 선택하고, time_bucket으로 윈도우 시작 시간(bucket)을 계산
  SELECT
    client_id, host_name, source_ip,
    http_status, url_path, user_name,
    time_bucket('{interval}', "@timestamp") AS bucket -- 지정된 간격으로 타임스탬프를 버킷팅
  FROM normalized_logs
  -- retention 기간 내의 데이터만 처리하여 Late arrival 데이터를 포함하고 불필요한 과거 데이터 스캔을 줄임
  WHERE "@timestamp" >= NOW() - INTERVAL '{retention}'
) AS sub
-- client_id, host_name, source_ip, bucket(window_start) 기준으로 그룹화하여 집계
GROUP BY client_id, host_name, source_ip, bucket
-- 멱등성 보장: 기본키(client_id, host_name, source_ip, window_start) 충돌 시 업데이트 수행
ON CONFLICT (client_id, host_name, source_ip, window_start)
DO UPDATE SET
    event_count           = EXCLUDED.event_count, -- EXCLUDED는 충돌을 일으킨 INSERT 시도의 데이터를 의미
    error4xx_ratio      = EXCLUDED.error4xx_ratio,
    error5xx_ratio      = EXCLUDED.error5xx_ratio,
    unique_url_count    = EXCLUDED.unique_url_count,
    unique_user_count = EXCLUDED.unique_user_count;
"""

# ───────────────────────────────────────────────────────────
# 메인 함수
# ───────────────────────────────────────────────────────────

def do_rollup(conn, suffix, interval, retention):
    """
    지정된 윈도우 설정으로 데이터 집계를 실행하고 실행 시간을 Prometheus에 기록하는 함수
    """
    # ⚠️ SQL 템플릿 포매팅: do_rollup 함수 내에서 'sql' 변수를 정의하도록 원래 코드 구조 복원
    sql = ROLLUP_SQL.format(suffix=suffix, interval=interval, retention=retention)
    
    # 롤업 작업의 실행 시간을 측정하기 위해 ROLLUP_LATENCY 히스토그램을 사용합니다.
    # .labels(suffix=suffix)를 사용하여 롤업 유형(suffix)별로 지연 시간을 분류합니다.
    # .time() 컨텍스트 매니저를 사용하면 블록 실행이 끝날 때까지의 시간을 자동으로 측정하고 기록합니다.
    with ROLLUP_LATENCY.labels(suffix=suffix).time():
        with conn.cursor() as cur:
            logger.info(f"[{suffix}] 집계 시작 (interval={interval}, retention={retention})")
            # SQL 실행
            cur.execute(sql)
            # 처리된 행 수 로깅 (INSERT 또는 UPDATE된 행 수)
            logger.info(f"[{suffix}] 집계 완료, {cur.rowcount} rows upserted")
        # 트랜잭션 커밋 (with .time() 블록 안에 포함되어 측정됨)
        conn.commit()

def main():
    """
    DB 연결 및 모든 윈도우에 대한 집계 작업을 순차적으로 실행하고
    Prometheus 메트릭 서버를 시작하는 메인 함수
    """
    # 🌟 Prometheus 메트릭 서버 시작
    try:
        start_http_server(PROMETHEUS_PORT)
        logger.info(f"Prometheus 메트릭 서버 시작. 포트: {PROMETHEUS_PORT}")
    except Exception as e:
        logger.error("Prometheus 서버 시작 실패: %s", e)
        sys.exit(1)

    conn = None
    try:
        # PostgreSQL/TimescaleDB 데이터베이스 연결 시도
        conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
                                 user=DB_USER, password=DB_PASS,
                                 cursor_factory=DictCursor, connect_timeout=5)
    except Exception as e:
        logger.error("DB 연결 실패: %s", e)
        sys.exit(1) # 연결 실패 시 스크립트 종료

    try:
        # 정의된 모든 윈도우에 대해 순차적으로 do_rollup 함수 실행
        for suffix, interval, retention in WINDOWS:
            do_rollup(conn, suffix, interval, retention)
    except Exception:
        # 집계 작업 중 예상치 못한 에러 발생 시 로그 기록
        logger.exception("집계 중 에러 발생")
    finally:
        if conn:
            conn.close() # DB 연결 종료
            logger.info("DB 연결 종료")

if __name__ == "__main__":
    main()