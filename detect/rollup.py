# -*- coding: utf-8 -*-
# 파일 경로: trust-soc/detect/rollup.py

import os
import sys
import logging
import psycopg2
from psycopg2.extras import DictCursor

# ───────────────────────────────────────────────────────────
# 환경변수 설정 (or .env 로드)
# ───────────────────────────────────────────────────────────
DB_HOST     = os.getenv("DB_HOST", "localhost")
DB_PORT     = os.getenv("DB_PORT", "5432")
DB_NAME     = os.getenv("DB_NAME", "logs_db")
DB_USER     = os.getenv("DB_USER", "postgres")
DB_PASS     = os.getenv("DB_PASS", "password")

# ───────────────────────────────────────────────────────────
# 로깅 설정
# ───────────────────────────────────────────────────────────
logging.basicConfig(
    level    = logging.INFO,
    format   = "%(asctime)s %(levelname)s %(message)s",
    handlers = [logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("rollup")

# ───────────────────────────────────────────────────────────
# 집계 윈도우 설정: suffix (테이블명), interval (time_bucket, 윈도우 크기), retention (쿼리 대상 시간 범위)
# ───────────────────────────────────────────────────────────
WINDOWS = [
    # 1분 윈도우: 1분 간격으로 집계, 2분 전까지의 데이터를 커버하여 Late arrival 포함
    ("1m", "1 minute", "2 minutes"),
    # 5분 윈도우: 5분 간격으로 집계, 10분 전까지의 데이터를 커버하여 Late arrival 포함
    ("5m", "5 minutes", "10 minutes"),
    # 1시간 윈도우: 1시간 간격으로 집계, 2시간 전까지의 데이터를 커버하여 Late arrival 포함
    ("1h", "1 hour", "2 hours"),
]

# ───────────────────────────────────────────────────────────
# Rollup 파이프라인 SQL 템플릿
# - time_bucket으로 윈도우를 정의하고,
# - ON CONFLICT로 멱등성을 보장합니다.
# ───────────────────────────────────────────────────────────
ROLLUP_SQL_TEMPLATE = """
INSERT INTO feature_rollup_{suffix} (
    client_id,
    host_name,
    source_ip,
    window_start,
    window_end,
    event_count,
    error4xx_ratio,
    error5xx_ratio,
    unique_url_count,
    unique_user_count
)
SELECT
    client_id,
    host_name,
    source_ip,
    bucket AS window_start,
    bucket + INTERVAL '{interval}' AS window_end,
    COUNT(*) AS event_count,
    -- 4xx/5xx 비율 계산: 전체 카운트로 나누어 비율 계산
    SUM(CASE WHEN http_status BETWEEN 400 AND 499 THEN 1 ELSE 0 END)::double precision / COUNT(*) AS error4xx_ratio,
    SUM(CASE WHEN http_status BETWEEN 500 AND 599 THEN 1 ELSE 0 END)::double precision / COUNT(*) AS error5xx_ratio,
    COUNT(DISTINCT url_path)  AS unique_url_count,
    COUNT(DISTINCT user_name) AS unique_user_count
FROM (
    SELECT
      client_id,
      host_name,
      source_ip,
      http_status,
      url_path,
      user_name,
      -- time_bucket 함수를 사용하여 윈도우 시작 시각(bucket) 계산
      time_bucket('{interval}', "@timestamp") AS bucket
    FROM normalized_logs
    -- 데이터 처리 범위 제한: NOW() - retention 간격 이후의 데이터를 처리 (Late arrival 포함)
    WHERE "@timestamp" >= NOW() - INTERVAL '{retention}'
) AS sub
GROUP BY
    client_id,
    host_name,
    source_ip,
    bucket
-- 충돌 시 업데이트: 이미 집계된 윈도우가 있다면 덮어쓰기 (멱등성 보장)
ON CONFLICT (client_id, host_name, source_ip, window_start)
DO UPDATE
    SET
        event_count     = EXCLUDED.event_count,
        error4xx_ratio  = EXCLUDED.error4xx_ratio,
        error5xx_ratio  = EXCLUDED.error5xx_ratio,
        unique_url_count = EXCLUDED.unique_url_count,
        unique_user_count = EXCLUDED.unique_user_count
;
"""

def do_rollup(conn, suffix: str, interval: str, retention: str):
    """
    단일 윈도우(suffix, interval)에 대한 집계 수행
    """
    # SQL 템플릿에 윈도우 및 보존 기간(retention) 값 삽입
    sql = ROLLUP_SQL_TEMPLATE.format(suffix=suffix, interval=interval, retention=retention)
    with conn.cursor() as cur:
        logger.info(f"[{suffix}] 집계 시작 (interval={interval}, retention={retention})")
        cur.execute(sql)
        count = cur.rowcount
        conn.commit()
        logger.info(f"[{suffix}] 집계 완료, INSERT/UPDATE된 row 수: {count}")


def main():
    try:
        conn = psycopg2.connect(
            host     = DB_HOST,
            port     = DB_PORT,
            dbname   = DB_NAME,
            user     = DB_USER,
            password = DB_PASS,
            cursor_factory = DictCursor,
            connect_timeout = 5
        )
    except Exception as e:
        logger.error("DB 연결 실패: %s", e)
        sys.exit(1)

    try:
        for suffix, interval, retention in WINDOWS:
            do_rollup(conn, suffix, interval, retention)
    except Exception as e:
        logger.exception("집계 중 에러 발생: %s", e)
    finally:
        conn.close()
        logger.info("DB 연결 종료")

if __name__ == "__main__":
    main()