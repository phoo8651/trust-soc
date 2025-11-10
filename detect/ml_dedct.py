#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FR-08: PyOD IForest + ADTK EWMA
- feature_rollup_5m → 다변량 이상치(ml_score, ml_anomaly, ml_processed)
- feature_rollup_1h → EWMA 급변(ewma_anomaly)
- events 테이블에 증거 포함 삽입
- 모델/임계치 파일(joblib) 버전 관리
"""
import os, sys, logging, joblib
import numpy as np
import pandas as pd
import psycopg2
from psycopg2.extras import DictCursor, Json
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from pyod.models.iforest import IForest
from adtk.detector import EWMAStatDetector

# ───────────────────────────────────────────────────────────
# 설정
# ───────────────────────────────────────────────────────────
# DB 연결 설정 (환경 변수 또는 기본값 사용)
DB_CFG = dict(
    host     = os.getenv("DB_HOST","localhost"),
    port     = os.getenv("DB_PORT","5432"),
    dbname   = os.getenv("DB_NAME","logs_db"),
    user     = os.getenv("DB_USER","postgres"),
    password = os.getenv("DB_PASS","password")
)
# Isolation Forest (IForest) 모델 및 임계값 저장 파일 경로
MODEL_FILE = os.getenv("ML_MODEL_FILE","iforest_pipeline.pkl")
THRESH_FILE= os.getenv("ML_THRESH_FILE","iforest_thresh.pkl")
# IForest 학습에 사용할 데이터의 과거 기간 (일)
HISTORY_DAYS = int(os.getenv("TRAIN_HISTORY_DAYS","7"))
# IForest 학습 시 예상되는 이상치 비율 (contamination)
CONTAMINATION = float(os.getenv("IF_CONTAMINATION","0.01"))
# EWMA (Exponentially Weighted Moving Average) 탐지기의 임계값 계수 C
EWMA_C = float(os.getenv("EWMA_C","3.0"))

# 로깅 설정
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml_detect")

def get_conn():
    """DB 연결 객체를 반환합니다."""
    return psycopg2.connect(cursor_factory=DictCursor, **DB_CFG)

# ───────────────────────────────────────────────────────────
# IForest 모델 로드 및 학습
# ───────────────────────────────────────────────────────────
def load_or_train(conn):
    """
    저장된 모델 파일이 있으면 로드하고, 없으면 DB에서 데이터를 가져와 IForest 모델을 학습합니다.
    """
    # 1. 기존 모델 파일 로드 시도
    if os.path.exists(MODEL_FILE) and os.path.exists(THRESH_FILE):
        logger.info("기존 모델 로드: %s", MODEL_FILE)
        pipe = joblib.load(MODEL_FILE)
        thresh = joblib.load(THRESH_FILE)
        return pipe, float(thresh)
        
    # 2. 학습 데이터 조회 (feature_rollup_5m 테이블에서 최근 HISTORY_DAYS 기간 데이터 사용)
    df = pd.read_sql(f"""
        SELECT event_count, error4xx_ratio, error5xx_ratio,
                unique_url_count, unique_user_count
        FROM feature_rollup_5m
        WHERE window_start >= NOW() - INTERVAL '{HISTORY_DAYS} days'
          AND event_count IS NOT NULL
    """, conn)
    
    if df.empty:
        logger.error("학습용 데이터 부족")
        sys.exit(1)
        
    # 3. 데이터 준비 및 표준화 (StandardScaler)
    X = df.values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    
    # 4. Isolation Forest 모델 학습
    clf = IForest(contamination=CONTAMINATION, random_state=42)
    clf.fit(Xs)
    
    # 5. 모델 파이프라인 구성 (전처리 + 모델)
    pipe = Pipeline([("scaler",scaler),("iforest",clf)])
    
    # 6. 이상치 임계값 계산 (contamination 비율에 해당하는 결정 점수)
    scores = clf.decision_scores_
    thresh = float(np.percentile(scores,100*(1-CONTAMINATION)))
    
    # 7. 모델 및 임계값 저장 (재사용을 위함)
    joblib.dump(pipe, MODEL_FILE)
    joblib.dump(thresh, THRESH_FILE)
    logger.info("모델 학습 완료, threshold=%.4f", thresh)
    return pipe, thresh

# ───────────────────────────────────────────────────────────
# IForest 다변량 이상치 탐지 실행
# ───────────────────────────────────────────────────────────
def run_iforest(conn, pipe, thresh):
    """
    feature_rollup_5m 테이블의 미처리된 데이터에 대해 IForest 이상 탐지를 실행합니다.
    """
    # IForest 탐지 대상 조회 (ml_processed가 FALSE인 최근 1시간 데이터)
    df = pd.read_sql("""
        SELECT client_id, host_name, source_ip, window_start,
                event_count, error4xx_ratio, error5xx_ratio,
                unique_url_count, unique_user_count
        FROM feature_rollup_5m
        WHERE ml_processed IS NOT TRUE
          AND event_count IS NOT NULL
          AND window_start >= NOW() - INTERVAL '1 hour'
        ORDER BY window_start
    """, conn)
    
    if df.empty:
        logger.info("IForest 대상 없음")
        return
        
    # 1. 특성(Features) 추출 및 파이프라인 적용 (스케일링 포함)
    feats = df[["event_count","error4xx_ratio","error5xx_ratio",
                 "unique_url_count","unique_user_count"]].values
    # 파이프라인의 각 단계(scaler, iforest)를 명시적으로 호출하여 결정 점수(decision_function) 계산
    scores = pipe.named_steps["iforest"].decision_function(pipe.named_steps["scaler"].transform(feats))
    
    cnt = 0
    with conn.cursor() as cur:
        for i,row in df.iterrows():
            s = float(scores[i])
            anom = s >= thresh # 점수가 임계값 이상이면 이상치
            
            # 2. feature_rollup_5m 테이블 업데이트 (점수, 이상 여부, 처리 플래그)
            cur.execute("""
                UPDATE feature_rollup_5m
                    SET ml_score=%s, ml_anomaly=%s, ml_processed=TRUE
                 WHERE client_id=%s AND host_name=%s AND source_ip=%s AND window_start=%s
            """, (s,anom,row["client_id"],row["host_name"],row["source_ip"],row["window_start"]))
            
            # 3. 이상치인 경우 events 테이블에 증거와 함께 기록
            if anom:
                cnt += 1
                # 이벤트 증거(Evidence) 데이터 구성
                evidence = {
                    "window_start": str(row["window_start"]),
                    "event_count": row["event_count"],
                    "error4xx_ratio": row["error4xx_ratio"],
                    "error5xx_ratio": row["error5xx_ratio"],
                    "unique_url_count": row["unique_url_count"],
                    "unique_user_count": row["unique_user_count"],
                    "ml_score": s,
                    "ml_threshold": thresh,
                }
                cur.execute("""
                    INSERT INTO events (
                      event_id, client_id, host_name,
                      event_category, event_type,
                      ml_score, ml_threshold,
                      severity, description, evidence_refs, "@timestamp"
                    ) VALUES (
                      gen_random_uuid(), %s, %s,
                      'anomaly','iforest_multivariate',
                      %s, %s,
                      'High','Multivariate anomaly detected by IForest.',
                      %s, NOW()
                    ) ON CONFLICT DO NOTHING
                """, (row["client_id"],row["host_name"],s,thresh,Json(evidence)))
        conn.commit()
    logger.info("IForest 완료: 총 %d건 처리, %d건 이상 탐지", len(df), cnt)

# ───────────────────────────────────────────────────────────
# EWMA 시계열 이상 탐지 실행
# ───────────────────────────────────────────────────────────
def run_ewma(conn):
    """
    feature_rollup_1h 테이블의 전체 이벤트 수 합계를 기준으로 EWMA 이상 탐지를 실행합니다.
    (Global/Host 무관한 총합 트래픽 급변 탐지)
    """
    # 1. feature_rollup_1h에서 window_start별 총 이벤트 수 집계 (시계열 데이터)
    df = pd.read_sql("""
        SELECT window_start, SUM(event_count) AS event_count
        FROM feature_rollup_1h
        GROUP BY window_start ORDER BY window_start
    """, conn, index_col="window_start") # window_start를 인덱스로 설정
    
    if df.shape[0] < 10:
        logger.info("EWMA 대상 부족(%d)", df.shape[0]); return
        
    # 2. ADTK EWMAStatDetector 적용
    s = df["event_count"].astype(float)
    det = EWMAStatDetector(c=EWMA_C) # c 값은 이상치 민감도 조절
    anoms = det.fit_detect(s) # 시계열 데이터에 대해 이상 탐지 실행
    
    last = s.index[-1] # 가장 최근 윈도우 시간
    
    # 3. 가장 최근 데이터의 이상 여부 확인 및 처리
    if anoms.iloc[-1]:
        val = float(s.iloc[-1])
        with conn.cursor() as cur:
            # 중복 이벤트 삽입 방지 확인
            cur.execute("""
                 SELECT COUNT(*) AS cnt
                   FROM feature_rollup_1h
                  WHERE window_start=%s AND ewma_anomaly IS TRUE
            """, (last,))
            
            # 이미 처리된 이상 징후가 아니면 (멱등성 보장)
            if cur.fetchone()["cnt"] == 0:
                # feature_rollup_1h 테이블 업데이트
                cur.execute("UPDATE feature_rollup_1h SET ewma_anomaly=TRUE WHERE window_start=%s", (last,))
                
                # events 테이블에 EWMA 이상 징후 기록 (전역 이벤트이므로 client_id/host_name은 __GLOBAL__ 사용)
                cur.execute("""
                    INSERT INTO events (
                      event_id, client_id, host_name,
                      event_category, event_type,
                      severity, description, evidence_refs, "@timestamp"
                    ) VALUES (
                      gen_random_uuid(),'__GLOBAL__','__GLOBAL__',
                      'anomaly','ewma_timeseries',
                      'Medium','Global event count spike/drop detected (EWMA).',
                      %s, %s
                    ) ON CONFLICT DO NOTHING
                """, (Json({str(last):val}), last))
                conn.commit()
                logger.warning("EWMA anomaly at %s = %f", last, val)
    else:
        logger.info("EWMA 정상: %s", last)

# ───────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────
def main():
    """메인 실행 함수: DB 연결, 모델 로드/학습, IForest, EWMA 순차 실행."""
    conn = None
    try:
        conn = get_conn()
        pipe, thresh = load_or_train(conn) # IForest 모델 준비
        run_iforest(conn, pipe, thresh)    # IForest 다변량 이상 탐지 실행
        run_ewma(conn)                     # EWMA 시계열 이상 탐지 실행
    except Exception:
        logger.exception("ML 탐지 중 오류")
    finally:
        if conn:
            conn.close()
            logger.info("DB 연결 종료")
            logger.info("ML 탐지 종료")

if __name__ == "__main__":
    main()