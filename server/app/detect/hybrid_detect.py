#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# /backend/postgres/app/detect/hybrid_detect.py

import os
import logging
import psycopg2
from psycopg2.extras import DictCursor, Json
from detect_utils import start_metrics_server, HYBRID_LATENCY

DB_CFG = dict(
    host=os.getenv("DB_HOST", "localhost"),
    port=os.getenv("DB_PORT", "5432"),
    dbname=os.getenv("DB_NAME", "socdb"),
    user=os.getenv("DB_USER", "postgres"),
    password=os.getenv("DB_PASS", "password"),
)
PROMETHEUS_PORT = int(os.getenv("PROMETHEUS_PORT", 8001))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("hybrid_detect")

# 가중치 설정
W_RULE = 1.0
W_ML = 0.7

def get_conn():
    return psycopg2.connect(cursor_factory=DictCursor, **DB_CFG)

def run_hybrid(conn):
    """
    ML 처리가 완료된(ml_processed=True) 데이터 중, 
    아직 하이브리드 처리가 안 된(hybrid_processed=False) 데이터를 처리합니다.
    """
    with conn.cursor() as cur:
        # 1. 처리 대상 조회
        cur.execute("""
            SELECT client_id, host_name, source_ip, window_start, ml_score
            FROM feature_rollup_5m
            WHERE ml_processed = TRUE AND hybrid_processed IS FALSE
            LIMIT 1000
        """)
        rows = cur.fetchall()

        if not rows:
            return

        logger.info(f"Processing {len(rows)} rows for hybrid detection.")
        
        events_to_insert = []
        updates = []

        for row in rows:
            # 2. 해당 시간대 YARA 룰 매치 여부 조회 (간소화됨)
            # 실제로는 events 테이블의 yara_match 타입을 조회해야 함
            rule_bool = 0 
            
            # 3. 점수 계산
            ml_score = row['ml_score'] or 0.0
            final_score = (W_RULE * rule_bool) + (W_ML * ml_score)
            
            # 4. 심각도 결정
            severity = "Low"
            if final_score >= 1.0: severity = "Critical"
            elif final_score >= 0.7: severity = "High"
            elif final_score >= 0.4: severity = "Medium"

            # 5. 이벤트 생성 (중간 이상일 때만)
            if final_score >= 0.4:
                events_to_insert.append((
                    row['client_id'], row['host_name'], row['source_ip'],
                    "hybrid", "hybrid_detect", severity,
                    f"Hybrid Score: {final_score:.2f} (ML:{ml_score:.2f})",
                    row['window_start'],
                    Json({"ml_score": ml_score, "final_score": final_score})
                ))
            
            # 업데이트 목록에 추가
            updates.append((final_score, row['client_id'], row['host_name'], row['source_ip'], row['window_start']))

        # 6. DB 일괄 적용
        if events_to_insert:
            cur.executemany("""
                INSERT INTO events (
                    client_id, host_name, source_ip, event_category, event_type,
                    severity, summary, "@timestamp", metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, events_to_insert)
        
        cur.executemany("""
            UPDATE feature_rollup_5m
            SET hybrid_processed = TRUE, final_score = %s
            WHERE client_id = %s AND host_name = %s AND source_ip = %s AND window_start = %s
        """, updates)

        conn.commit()
        logger.info(f"Hybrid detect complete. Generated {len(events_to_insert)} events.")

def main():
    start_metrics_server(PROMETHEUS_PORT)
    conn = None
    try:
        conn = get_conn()
        with HYBRID_LATENCY.time():
            run_hybrid(conn)
    except Exception as e:
        logger.error(f"Hybrid detect error: {e}")
        if conn: conn.rollback()
    finally:
        if conn: conn.close()

if __name__ == "__main__":
    main()