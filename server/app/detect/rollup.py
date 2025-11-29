#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# /backend/postgres/app/detect/rollup.py

import os
import logging
import psycopg2
from psycopg2.extras import DictCursor
from detect_utils import start_metrics_server, ROLLUP_LATENCY

# DB 연결 설정
DB_CFG = dict(
    host=os.getenv("DB_HOST", "localhost"),
    port=os.getenv("DB_PORT", "5432"),
    dbname=os.getenv("DB_NAME", "socdb"),
    user=os.getenv("DB_USER", "postgres"),
    password=os.getenv("DB_PASS", "password"),
)
PROMETHEUS_PORT = int(os.getenv("PROMETHEUS_PORT", 8001))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("rollup")

# 윈도우 설정: (테이블 접미사, 집계 간격, 데이터 보존 기간)
WINDOWS = [
    ("1m", "1 minute", "2 minutes"),
    ("5m", "5 minutes", "10 minutes"),
    ("1h", "1 hour", "2 hours"),
]

# 롤업 SQL 템플릿
# raw_logs 테이블에서 정규식으로 HTTP 상태 코드를 추출하여 집계합니다.
ROLLUP_SQL = """
INSERT INTO feature_rollup_{suffix} (
    client_id, host_name, source_ip,
    window_start, window_end,
    event_count,
    error4xx_ratio, error5xx_ratio,
    unique_url_count, unique_user_count
)
SELECT
    client_id,
    host,
    '0.0.0.0' as source_ip, -- raw_logs에 IP 컬럼이 없으면 기본값
    bucket AS window_start,
    bucket + INTERVAL '{interval}' AS window_end,
    COUNT(*) AS event_count,
    
    -- HTTP 4xx 비율 (정규식 매칭)
    SUM(CASE WHEN raw_line ~ ' 4[0-9][0-9] ' THEN 1 ELSE 0 END)::float / NULLIF(COUNT(*), 0) AS error4xx_ratio,
    -- HTTP 5xx 비율 (정규식 매칭)
    SUM(CASE WHEN raw_line ~ ' 5[0-9][0-9] ' THEN 1 ELSE 0 END)::float / NULLIF(COUNT(*), 0) AS error5xx_ratio,
    
    -- URL/User 카운트 (여기서는 데모용으로 단순화)
    1 AS unique_url_count,
    1 AS unique_user_count
FROM (
  SELECT
    client_id, host, raw_line,
    -- Time Bucket 함수 사용 (Postgres date_bin)
    date_bin(INTERVAL '{interval}', ts, TIMESTAMP '1970-01-01 00:00:00Z') AS bucket
  FROM raw_logs
  WHERE ts >= NOW() - INTERVAL '{retention}'
) AS sub
GROUP BY client_id, host, bucket
ON CONFLICT (client_id, host_name, source_ip, window_start)
DO UPDATE SET
    event_count       = EXCLUDED.event_count,
    error4xx_ratio    = EXCLUDED.error4xx_ratio,
    error5xx_ratio    = EXCLUDED.error5xx_ratio
"""

def ensure_schema(conn):
    """필요한 테이블과 확장이 존재하는지 확인하고 생성합니다."""
    with conn.cursor() as cur:
        # pgcrypto 확장 생성 (권한 오류 시 롤백하여 무시)
        try:
            cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.warning(f"pgcrypto extension creation skipped: {e}")

        # 롤업 테이블 및 이벤트 테이블 생성
        cur.execute("""
        CREATE TABLE IF NOT EXISTS feature_rollup_5m (
            client_id text NOT NULL, host_name text NOT NULL, source_ip text NOT NULL,
            window_start timestamptz NOT NULL, window_end timestamptz NOT NULL,
            event_count bigint NOT NULL,
            error4xx_ratio double precision, error5xx_ratio double precision,
            unique_url_count bigint, unique_user_count bigint,
            ml_score double precision, ml_anomaly boolean,
            ml_processed boolean DEFAULT FALSE,
            hybrid_processed boolean DEFAULT FALSE,
            final_score double precision,
            ewma_anomaly boolean DEFAULT FALSE,
            PRIMARY KEY (client_id, host_name, source_ip, window_start)
        );
        -- 1m, 1h 테이블은 5m 테이블 구조 복사
        CREATE TABLE IF NOT EXISTS feature_rollup_1m (LIKE feature_rollup_5m INCLUDING ALL);
        CREATE TABLE IF NOT EXISTS feature_rollup_1h (LIKE feature_rollup_5m INCLUDING ALL);
        """)
        conn.commit()
    logger.info("Schema ensured.")

def do_rollup(conn, suffix, interval, retention):
    """특정 윈도우에 대해 롤업 쿼리를 실행합니다."""
    sql = ROLLUP_SQL.format(suffix=suffix, interval=interval, retention=retention)
    try:
        # Prometheus로 수행 시간 측정
        with ROLLUP_LATENCY.time():
            with conn.cursor() as cur:
                cur.execute(sql)
                logger.info(f"[{suffix}] Rollup complete: {cur.rowcount} rows upserted.")
            conn.commit()
    except Exception as e:
        conn.rollback() # 오류 시 반드시 롤백
        logger.error(f"[{suffix}] Rollup failed: {e}")

def main():
    start_metrics_server(PROMETHEUS_PORT)
    try:
        conn = psycopg2.connect(**DB_CFG)
        ensure_schema(conn)
        # 정의된 모든 윈도우에 대해 작업 수행
        for s, i, r in WINDOWS:
            do_rollup(conn, s, i, r)
        conn.close()
    except Exception as e:
        logger.error(f"Rollup main loop error: {e}")

if __name__ == "__main__":
    main()