#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# /backend/postgres/app/detect/yara_batch_scanner.py

import os
import logging
import yara
import psycopg2
from psycopg2.extras import DictCursor
from detect_utils import start_metrics_server, YARA_LATENCY

DB_CFG = dict(
    host=os.getenv("DB_HOST", "localhost"),
    port=os.getenv("DB_PORT", "5432"),
    dbname=os.getenv("DB_NAME", "socdb"),
    user=os.getenv("DB_USER", "postgres"),
    password=os.getenv("DB_PASS", "password"),
)
# 룰 파일 경로 (상대 경로 문제 해결)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
YARA_RULES_PATH = os.path.join(BASE_DIR, "yara_rules", "suspicious.yar")
PROMETHEUS_PORT = int(os.getenv("PROMETHEUS_PORT", 8001))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("yara_scanner")

def ensure_yara_rule():
    """YARA 룰 파일이 없으면 기본 더미 룰을 생성합니다."""
    if not os.path.exists(YARA_RULES_PATH):
        logger.warning(f"YARA rules not found at {YARA_RULES_PATH}. Creating default rule.")
        os.makedirs(os.path.dirname(YARA_RULES_PATH), exist_ok=True)
        with open(YARA_RULES_PATH, "w") as f:
            f.write("""
rule TEST_SUSPICIOUS {
    meta:
        description = "Test rule to ensure scanner works"
        severity = 1
    strings:
        $a = "evil_script_signature"
    condition:
        $a
}
""")

def compile_rules():
    ensure_yara_rule()
    try:
        return yara.compile(filepath=YARA_RULES_PATH)
    except Exception as e:
        logger.error(f"YARA compilation failed: {e}")
        return None

def main():
    start_metrics_server(PROMETHEUS_PORT)
    
    # 1. 룰 컴파일
    rules = compile_rules()
    if not rules:
        return

    conn = None
    try:
        conn = psycopg2.connect(**DB_CFG)
        
        # 2. 스캔 대상(파일 업로드 로그) 조회 (예시 쿼리)
        # 실제로는 Normalized Logs 또는 Raw Logs에서 파일 경로 추출 필요
        # 여기서는 데모를 위해 로직 스텁만 유지
        logger.info("YARA scanner running... (No target logs in raw_logs currently implemented)")
        
        # 3. 스캔 로직 (스텁)
        # targets = fetch_targets(conn)
        # for t in targets:
        #    with YARA_LATENCY.time():
        #        scan_file(t, rules)
        
    except Exception as e:
        logger.error(f"Scanner error: {e}")
    finally:
        if conn: conn.close()

if __name__ == "__main__":
    main()