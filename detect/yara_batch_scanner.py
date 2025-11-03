# -*- coding: utf-8 -*-
# 파일 경로: trust-soc/detect/yara_batch_scanner.py

import os
import sys
import logging
import yara
import psycopg2
from psycopg2.extras import DictCursor, Json
from concurrent.futures import ThreadPoolExecutor
import time

# ───────────────────────────────────────────────────────────
# 환경변수 및 상수 설정
# ───────────────────────────────────────────────────────────
DB_HOST     = os.getenv("DB_HOST", "localhost")
DB_PORT     = os.getenv("DB_PORT", "5432")
DB_NAME     = os.getenv("DB_NAME", "logs_db")
DB_USER     = os.getenv("DB_USER", "postgres")
DB_PASS     = os.getenv("DB_PASS", "password")

YARA_RULES_PATH = os.path.join(os.path.dirname(__file__), "yara_rules", "suspicious.yar")
MAX_WORKERS = 4  # FR-09: 병렬 처리 가능
SCAN_CHUNK_SIZE = 100 # 한 번에 DB에서 가져와 스캔할 파일 이벤트 수
LOG_RETENTION = "5 minutes" # 최근 5분 이내의 파일 이벤트만 스캔

# ───────────────────────────────────────────────────────────
# 로깅 설정
# ───────────────────────────────────────────────────────────
logging.basicConfig(
    level    = logging.INFO,
    format   = "%(asctime)s %(levelname)s %(message)s",
    handlers = [logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("yara_scanner")

# ───────────────────────────────────────────────────────────
# 유틸리티 함수
# ───────────────────────────────────────────────────────────

def get_db_connection():
    """DB 연결 객체를 반환합니다."""
    return psycopg2.connect(
        host     = DB_HOST,
        port     = DB_PORT,
        dbname   = DB_NAME,
        user     = DB_USER,
        password = DB_PASS,
        cursor_factory = DictCursor,
        connect_timeout = 5
    )

def compile_yara_rules():
    """YARA 룰 파일을 컴파일합니다."""
    logger.info(f"YARA 룰 컴파일 시작: {YARA_RULES_PATH}")
    try:
        rules = yara.compile(filepath=YARA_RULES_PATH)
        logger.info("YARA 룰 컴파일 성공.")
        return rules
    except yara.Error as e:
        logger.error(f"YARA 룰 컴파일 에러: {e}")
        return None

# ───────────────────────────────────────────────────────────
# 핵심 로직
# ───────────────────────────────────────────────────────────

def fetch_scan_targets(conn, limit: int):
    """
    Normalized Logs 테이블에서 최근 파일 업로드/생성 이벤트를 가져옵니다.
    event_category='file' 이며, 아직 YARA 처리가 안된 로그만 대상입니다.
    (실제 file_path에 접근할 수 있다고 가정)
    """
    SQL = f"""
    SELECT 
        log_id, client_id, host_name, file_path, file_name, file_mime_type, "@timestamp"
    FROM 
        normalized_logs
    WHERE 
        event_category = 'file' AND file_path IS NOT NULL
        AND processed_by_yara = FALSE -- 아직 처리되지 않은 이벤트
        AND "@timestamp" >= NOW() - INTERVAL '{LOG_RETENTION}' -- 최근 로그만 처리
    LIMIT %s;
    """
    with conn.cursor() as cur:
        cur.execute(SQL, (limit,))
        targets = cur.fetchall()
        logger.info(f"스캔 대상 이벤트 {len(targets)}건 조회 완료.")
        return targets

def scan_file_with_yara(log_entry, compiled_rules):
    """
    단일 파일에 대해 YARA 스캔을 수행하고 매칭 결과를 반환합니다.
    """
    file_path = log_entry['file_path']
    try:
        # 실제 파일 내용을 읽어 스캔
        with open(file_path, 'rb') as f:
            data = f.read()

        # 스캔 수행
        matches = compiled_rules.match(data=data)
        
        detection_events = []
        
        # FR-09: 매칭 근거 포함 (룰 ID, 오프셋, hexdump 샘플)
        for match in matches:
            event_metadata = {
                "rule_name": match.rule,
                "tags": match.tags,
                "meta": match.meta,
                "strings": [],
            }
            # 매칭된 문자열 정보 추출
            for string_match in match.strings:
                offset = string_match[0]
                string_id = string_match[1]
                # hexdump 샘플을 위해 매칭된 문자열 주변 16바이트를 추출
                snippet_start = max(0, offset - 8)
                snippet_end = min(len(data), offset + 16)
                
                event_metadata["strings"].append({
                    "offset": offset,
                    "string_id": string_id,
                    "snippet_hex": data[snippet_start:snippet_end].hex(),
                    "snippet_ascii": data[snippet_start:snippet_end].decode('utf-8', errors='ignore').replace('\n', '\\n'),
                })
            
            # 탐지 이벤트를 Events 테이블에 저장할 형식으로 정리
            detection_events.append({
                "log_id": log_entry['log_id'],
                "client_id": log_entry['client_id'],
                "host_name": log_entry['host_name'],
                "timestamp": log_entry['@timestamp'],
                "event_category": "file",
                "event_type": "yara_match",
                "rule_name": match.rule,
                "severity": match.meta.get('severity', 5), # 룰 메타데이터에서 Severity 가져오기
                "description": match.meta.get('description', 'YARA rule matched'),
                "metadata": event_metadata
            })
            
        return log_entry['log_id'], detection_events, True
    
    except FileNotFoundError:
        logger.warning(f"파일을 찾을 수 없습니다: {file_path}. 로그 {log_entry['log_id']} 처리 건너뛰기.")
        return log_entry['log_id'], [], True # 스캔은 건너뛰지만, 처리 완료로 표시
    except Exception as e:
        logger.error(f"로그 {log_entry['log_id']} 스캔 중 예상치 못한 에러 발생: {e}")
        return log_entry['log_id'], [], False # 실패

def insert_detection_events(conn, events):
    """탐지 이벤트를 Events 테이블에 배치 삽입합니다."""
    if not events:
        return
        
    SQL = """
    INSERT INTO events ("@timestamp", log_id, client_id, host_name, event_category, event_type, rule_name, severity, description, metadata)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (event_id) DO NOTHING; -- NFR-03: 멱등성 처리
    """
    
    data_to_insert = [
        (
            e['timestamp'], e['log_id'], e['client_id'], e['host_name'], 
            e['event_category'], e['event_type'], e['rule_name'], e['severity'], e['description'],
            Json(e['metadata']) # JSONB 저장을 위해 Json() 사용
        )
        for e in events
    ]
    
    with conn.cursor() as cur:
        cur.executemany(SQL, data_to_insert)
        conn.commit()
        logger.info(f"Events 테이블에 {len(events)}건의 탐지 이벤트 저장 완료.")

def update_log_status(conn, processed_ids, failed_ids):
    """
    처리 완료된 로그의 상태를 업데이트합니다.
    NFR-02: at-least-once 소비, 서버 멱등 처리 (여기서는 `processed_by_yara` 플래그로 단순화)
    """
    if processed_ids:
        # 성공적으로 처리된 로그는 플래그 업데이트
        SQL_SUCCESS = "UPDATE normalized_logs SET processed_by_yara = TRUE WHERE log_id IN %s;"
        with conn.cursor() as cur:
            cur.execute(SQL_SUCCESS, (tuple(processed_ids),))
            conn.commit()
            logger.info(f"로그 {len(processed_ids)}건의 YARA 처리 완료 플래그 설정.")
    
    if failed_ids:
        # 실패한 로그는 다음 실행 시 재시도하도록 플래그를 업데이트하지 않음
        logger.warning(f"로그 {len(failed_ids)}건의 처리가 실패했습니다. 다음 배치에서 재시도됩니다.")

def main():
    start_time = time.time()
    
    compiled_rules = compile_yara_rules()
    if not compiled_rules:
        sys.exit(1)
        
    try:
        conn = get_db_connection()
    except Exception as e:
        logger.error("DB 연결 실패: %s", e)
        sys.exit(1)

    all_detection_events = []
    all_processed_ids = []
    all_failed_ids = []

    try:
        # 1. 스캔 대상 이벤트 조회
        scan_targets = fetch_scan_targets(conn, SCAN_CHUNK_SIZE)

        if not scan_targets:
            logger.info("새로운 스캔 대상 파일 이벤트가 없습니다. 종료합니다.")
            return

        # 2. FR-09: 멀티쓰레드를 사용한 병렬 스캔 처리
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # 퓨처 객체 생성
            future_to_log = {
                executor.submit(scan_file_with_yara, target, compiled_rules): target
                for target in scan_targets
            }
            
            # 결과 처리
            for future in future_to_log:
                log_id, detection_events, success = future.result()
                
                if success:
                    all_processed_ids.append(log_id)
                    all_detection_events.extend(detection_events)
                else:
                    all_failed_ids.append(log_id)
        
        # 3. 탐지 이벤트 저장
        insert_detection_events(conn, all_detection_events)
        
        # 4. 로그 상태 업데이트 (멱등성 / at-least-once 처리)
        update_log_status(conn, all_processed_ids, all_failed_ids)

    except Exception as e:
        logger.exception("YARA 배치 스캔 중 에러 발생: %s", e)
    finally:
        conn.close()
        end_time = time.time()
        logger.info(f"총 처리 시간: {end_time - start_time:.2f}초")

if __name__ == "__main__":
    main()