#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FR-09: 파일 업로드 이벤트 → (디컴프레스) → YARA 스캔 → events 테이블에 증거 저장.
멀티스레드, 배치 처리, 멱등성 보장(processed_by_yara 플래그)
"""
import os, sys, logging, tempfile, shutil, time
import yara
import psycopg2
from psycopg2.extras import DictCursor, Json
from concurrent.futures import ThreadPoolExecutor

# ───────────────────────────────────────────────────────────
# 환경변수 및 상수
# ───────────────────────────────────────────────────────────
# 데이터베이스 연결 정보 설정
DB_HOST         = os.getenv("DB_HOST","localhost")
DB_PORT         = os.getenv("DB_PORT","5432")
DB_NAME         = os.getenv("DB_NAME","logs_db")
DB_USER         = os.getenv("DB_USER","postgres")
DB_PASS         = os.getenv("DB_PASS","password")

# YARA 룰 파일 경로 설정
YARA_RULES_PATH = os.path.join(os.path.dirname(__file__),"yara_rules","suspicious.yar")
# 멀티스레딩에 사용할 최대 워커 수 (병렬 처리 수)
MAX_WORKERS     = int(os.getenv("MAX_WORKERS","4"))
# DB에서 한 번에 가져와 처리할 로그의 개수
BATCH_SIZE      = int(os.getenv("BATCH_SIZE","100"))
# 처리할 로그의 최대 보존 기간 (오래된 로그는 건너뛰기 위함)
LOG_RETENTION   = os.getenv("LOG_RETENTION","5 minutes")

# ───────────────────────────────────────────────────────────
# 로깅
# ───────────────────────────────────────────────────────────
# 로깅 설정 초기화
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("yara_scanner")

# ───────────────────────────────────────────────────────────
# DB 연결
# ───────────────────────────────────────────────────────────
def get_conn():
    """새로운 PostgreSQL DB 연결 객체를 반환합니다."""
    return psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
                            user=DB_USER, password=DB_PASS,
                            cursor_factory=DictCursor, connect_timeout=5)

# ───────────────────────────────────────────────────────────
# YARA 룰 컴파일
# ───────────────────────────────────────────────────────────
def compile_rules(path):
    """지정된 경로의 YARA 룰 파일을 컴파일하고 yara.Rules 객체를 반환합니다."""
    logger.info("YARA 룰 컴파일: %s", path)
    try:
        return yara.compile(filepath=path)
    except Exception as e:
        logger.error("YARA 룰 컴파일 실패: %s", e)
        return None

# ───────────────────────────────────────────────────────────
# 압축 해제 지원
# ───────────────────────────────────────────────────────────
def decompress(path, workdir):
    """
    주어진 파일 경로가 zip/tar 등으로 압축되어 있으면 해제하고,
    스캔할 파일 목록을 반환합니다. 압축 해제 실패 시 원본 파일 경로만 반환합니다.
    """
    files = []
    lower = path.lower()
    try:
        if lower.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(path) as zf:
                # 작업 디렉토리에 모두 압축 해제
                zf.extractall(workdir)
                files = [os.path.join(workdir,n) for n in zf.namelist()]
        elif lower.endswith((".tar",".tar.gz",".tgz",".tar.bz2")):
            import tarfile
            # 압축 유형 자동 감지하여 열기
            with tarfile.open(path,"r:*") as tf:
                tf.extractall(workdir)
                files = [os.path.join(workdir,n) for n in tf.getnames()]
        else:
            # 압축 파일이 아니면 원본 파일만 스캔 대상으로 지정
            files = [path]
    except Exception as e:
        logger.warning("압축 해제 실패(%s): %s", path, e)
        files = [path] # 압축 해제 실패 시에도 원본 파일은 스캔 시도
    # 실제 파일인 경우만 목록에 포함하여 반환
    return [f for f in files if os.path.isfile(f)]

# ───────────────────────────────────────────────────────────
# DB로부터 배치 대상 조회
# ───────────────────────────────────────────────────────────
def fetch_targets(conn, limit):
    """
    DB에서 아직 YARA 스캔이 처리되지 않은 파일 업로드 로그 항목을 배치 단위로 조회합니다.
    """
    SQL = f"""
    SELECT log_id, client_id, host_name, file_path, file_name, "@timestamp"
    FROM normalized_logs
    WHERE event_category='file'             -- 파일 이벤트
      AND file_path IS NOT NULL             -- 파일 경로가 존재하는 경우
      AND processed_by_yara IS NOT TRUE     -- 아직 YARA 스캔이 처리되지 않은 경우 (멱등성 플래그)
      AND "@timestamp" >= NOW() - INTERVAL '{LOG_RETENTION}' -- 최근 로그만 처리
    ORDER BY "@timestamp"
    LIMIT %s
    """
    with conn.cursor() as cur:
        cur.execute(SQL, (limit,))
        rows = cur.fetchall()
    logger.info("스캔 대상 조회: %d 건", len(rows))
    return rows

# ───────────────────────────────────────────────────────────
# 단일 파일 스캔 (멀티스레드 실행 대상)
# ───────────────────────────────────────────────────────────
def scan_one(entry, rules):
    """
    하나의 로그 항목(파일)에 대해 압축 해제 후 YARA 스캔을 실행합니다.
    결과: (log_id, [이벤트 목록], 성공 여부)
    """
    log_id = entry["log_id"]
    tmp = None # 임시 디렉토리 변수 초기화
    try:
        # 스캔을 위한 임시 디렉토리 생성
        tmp = tempfile.mkdtemp(prefix="yara_")
        hits = []
        
        # 파일 압축 해제 및 해제된 파일 목록 순회
        for f in decompress(entry["file_path"], tmp):
            data = open(f,"rb").read() # 파일 내용 읽기
            
            # YARA 룰 매치 실행
            for m in rules.match(data=data):
                # 매치된 각 문자열에 대한 상세 정보 추출
                for sid, off, blob in m.strings:
                    # 매치된 위치 주변의 16바이트(offset-8 ~ offset+16) 데이터를 추출하여 스니펫 생성
                    snippet_data = data[max(0,off-8):off+16]
                    snippet_hex     = snippet_data.hex()
                    # 제어 문자를 처리하여 ASCII 스니펫 생성
                    snippet_ascii = snippet_data.decode('utf-8','ignore').replace("\n","\\n")
                    
                    hits.append({
                        "rule":      m.rule,
                        "namespace": m.namespace,
                        "string_id": sid,
                        "offset":    off,
                        "snippet_hex":    snippet_hex,
                        "snippet_ascii": snippet_ascii,
                        "tags":      m.tags,
                        "meta":      m.meta
                    })
        
        # YARA 매치 결과를 DB events 테이블에 저장할 형식으로 변환
        events = []
        for h in hits:
            events.append({
                "log_id":          log_id,
                "client_id":       entry["client_id"],
                "host_name":       entry["host_name"],
                "@timestamp":      entry["@timestamp"],
                "event_category": "file",
                "event_type":      "yara_match",
                "rule_name":       h["rule"],
                # 메타데이터에서 심각도(severity)를 가져오거나 기본값 5 사용
                "severity":        h["meta"].get("severity",5),
                # 메타데이터에서 설명(description)을 가져오거나 기본값 사용
                "description":     h["meta"].get("description","YARA matched"),
                # 매치 상세 정보를 JSON 형태의 metadata 필드에 저장
                "metadata":        {
                    "namespace": h["namespace"],
                    "string_id": h["string_id"],
                    "offset":    h["offset"],
                    "snippet_hex":    h["snippet_hex"],
                    "snippet_ascii": h["snippet_ascii"],
                    "tags":      h["tags"]
                }
            })
        
        # 성공적으로 스캔 완료
        return log_id, events, True

    except FileNotFoundError:
        logger.warning("파일 없음(log_id=%s): %s", log_id, entry["file_path"])
        # 파일이 없어도 재처리를 막기 위해 성공으로 처리
        return log_id, [], True 
    except Exception as e:
        logger.error("스캔 실패(log_id=%s): %s", log_id, e)
        # 스캔 실패 (오류 발생)
        return log_id, [], False
    finally:
        # 임시 디렉토리 정리 (오류 발생 여부와 관계없이)
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

# ───────────────────────────────────────────────────────────
# 이벤트 저장 & 상태 업데이트
# ───────────────────────────────────────────────────────────
def persist_events(conn, evts):
    """
    YARA 매치 이벤트를 'events' 테이블에 저장합니다.
    """
    if not evts:
        return
    SQL = """
    INSERT INTO events (
      event_id, "@timestamp", log_id, client_id, host_name,
      event_category, event_type, rule_name, severity, description, metadata
    ) VALUES (
      gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    ) ON CONFLICT DO NOTHING -- 중복 이벤트 방지
    """
    # psycopg2.extras.Json을 사용하여 metadata 필드를 JSONb 타입으로 변환하여 저장
    vals = [
      (e["@timestamp"], e["log_id"], e["client_id"], e["host_name"],
       e["event_category"], e["event_type"], e["rule_name"],
       e["severity"], e["description"], Json(e["metadata"]))
      for e in evts
    ]
    with conn.cursor() as cur:
        # 배치 삽입을 위한 executemany 사용
        cur.executemany(SQL, vals)
    conn.commit()
    logger.info("이벤트 저장: %d 건", len(evts))

def mark_processed(conn, success_ids, fail_ids):
    """
    성공적으로 처리된 로그 항목에 processed_by_yara=TRUE 플래그를 설정하여
    다음 스캔 대상에서 제외되도록 합니다 (멱등성 보장).
    """
    if success_ids:
        # IN 절에 사용할 튜플로 변환하여 SQL 실행
        SQL = "UPDATE normalized_logs SET processed_by_yara=TRUE WHERE log_id IN %s"
        with conn.cursor() as cur:
            cur.execute(SQL, (tuple(success_ids),))
        conn.commit()
        logger.info("processed_by_yara 플래그 설정: %d 건", len(success_ids))
    if fail_ids:
        # 실패한 항목은 플래그를 설정하지 않아 다음 배치에서 재시도됨
        logger.warning("스캔 실패한 로그: %d 건", len(fail_ids))

# ───────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────
def main():
    """메인 실행 흐름: 룰 컴파일, DB 연결, 배치 조회, 멀티스레드 스캔, 결과 저장 및 업데이트."""
    start = time.time()
    
    # 1. YARA 룰 컴파일
    rules = compile_rules(YARA_RULES_PATH)
    if not rules:
        sys.exit(1)

    conn = get_conn()
    try:
        # 2. 스캔 대상 배치 조회
        targets = fetch_targets(conn, BATCH_SIZE)
        if not targets:
            logger.info("새로운 스캔 대상 없음.")
            return

        success_ids, fail_ids, all_events = [], [], []
        # 3. ThreadPoolExecutor를 이용한 멀티스레드 병렬 스캔
        with ThreadPoolExecutor(MAX_WORKERS) as pool:
            # 각 대상에 대해 scan_one 함수를 제출하고 결과를 퓨처(Future) 객체로 받음
            futures = { pool.submit(scan_one, t, rules): t for t in targets }
            for f in futures:
                # 결과 대기 및 추출
                log_id, evts, ok = f.result()
                if ok:
                    success_ids.append(log_id)
                    all_events += evts # 매치된 이벤트 목록을 통합
                else:
                    fail_ids.append(log_id)
        
        # 4. 모든 이벤트 저장 및 상태 업데이트
        persist_events(conn, all_events)
        mark_processed(conn, success_ids, fail_ids)

    except Exception:
        logger.exception("메인 처리 중 예상치 못한 에러 발생")
        
    finally:
        if conn:
            conn.close()
            logger.info("DB 연결 종료")
            logger.info("총 소요: %.2fs", time.time()-start)

if __name__ == "__main__":
    main()
