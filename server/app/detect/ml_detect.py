#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# /backend/postgres/app/detect/ml_detect.py

import os
import logging
import joblib
import numpy as np
import pandas as pd
import psycopg2
from psycopg2.extras import DictCursor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from pyod.models.iforest import IForest
from detect_utils import start_metrics_server, ML_LATENCY

# DB 설정
DB_CFG = dict(
    host=os.getenv("DB_HOST", "localhost"),
    port=os.getenv("DB_PORT", "5432"),
    dbname=os.getenv("DB_NAME", "socdb"),
    user=os.getenv("DB_USER", "postgres"),
    password=os.getenv("DB_PASS", "password"),
)
# 모델 파일 경로 (K8s PVC 마운트 경로 고려)
MODEL_FILE = os.getenv("ML_MODEL_FILE", "/app/data/iforest_pipeline.pkl")
THRESH_FILE = os.getenv("ML_THRESH_FILE", "/app/data/iforest_thresh.pkl")
PROMETHEUS_PORT = int(os.getenv("PROMETHEUS_PORT", 8001))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml_detect")

def get_conn():
    return psycopg2.connect(cursor_factory=DictCursor, **DB_CFG)

def load_or_train(conn):
    """
    기존 모델을 로드하거나, 데이터가 있으면 새로 학습합니다.
    데이터가 너무 적으면 더미 모델을 생성하여 에러를 방지합니다.
    """
    if os.path.exists(MODEL_FILE) and os.path.exists(THRESH_FILE):
        logger.info("Loading existing model...")
        return joblib.load(MODEL_FILE), float(joblib.load(THRESH_FILE))
    
    logger.info("Training new model...")
    # 최근 7일치 데이터 조회
    query = """
        SELECT event_count, error4xx_ratio, error5xx_ratio 
        FROM feature_rollup_5m 
        WHERE window_start >= NOW() - INTERVAL '7 days'
        LIMIT 5000
    """
    df = pd.read_sql(query, conn)
    
    # 데이터가 부족할 경우 (초기 구축 시) 가짜 데이터로 모델 초기화
    if len(df) < 50:
        logger.warning("Not enough data for training. Creating dummy model.")
        X = np.array([[100, 0.0, 0.0], [500, 0.1, 0.0]]) # Dummy features
    else:
        X = df[['event_count', 'error4xx_ratio', 'error5xx_ratio']].fillna(0).values

    # 파이프라인 구성: 스케일링 -> IForest
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("iforest", IForest(contamination=0.01, random_state=42))
    ])
    pipeline.fit(X)
    
    # 임계값 계산 (학습 데이터의 결정 점수 분포 기준)
    scores = pipeline.named_steps["iforest"].decision_scores_
    thresh = float(np.percentile(scores, 99)) # 상위 1%를 이상치로 간주

    # 저장
    os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)
    joblib.dump(pipeline, MODEL_FILE)
    joblib.dump(thresh, THRESH_FILE)
    
    return pipeline, thresh

def run_iforest(conn, pipe, thresh):
    """Isolation Forest 실행 및 결과 업데이트"""
    if not pipe: return

    # 처리되지 않은 최신 5분 데이터 조회
    df = pd.read_sql("""
        SELECT client_id, host_name, source_ip, window_start,
               event_count, error4xx_ratio, error5xx_ratio
        FROM feature_rollup_5m
        WHERE ml_processed IS FALSE
          AND window_start >= NOW() - INTERVAL '1 hour'
    """, conn)

    if df.empty:
        logger.info("No data for IForest detection.")
        return

    # 예측 수행
    X = df[['event_count', 'error4xx_ratio', 'error5xx_ratio']].fillna(0).values
    X_scaled = pipe.named_steps["scaler"].transform(X)
    scores = pipe.named_steps["iforest"].decision_function(X_scaled)

    # DB 업데이트
    with conn.cursor() as cur:
        for idx, row in df.iterrows():
            score = float(scores[idx])
            is_anomaly = score >= thresh
            
            cur.execute("""
                UPDATE feature_rollup_5m
                SET ml_score = %s, ml_anomaly = %s, ml_processed = TRUE
                WHERE client_id = %s AND host_name = %s 
                  AND source_ip = %s AND window_start = %s
            """, (score, is_anomaly, row['client_id'], row['host_name'], 
                  row['source_ip'], row['window_start']))
        conn.commit()
    logger.info(f"IForest processed {len(df)} records.")

def run_ewma(conn):
    """
    EWMA (Exponentially Weighted Moving Average) 기반 시계열 급변 탐지.
    ADTK 라이브러리 대신 Pandas 내장 기능 사용.
    """
    df = pd.read_sql("""
        SELECT window_start, SUM(event_count) as total_events
        FROM feature_rollup_5m
        GROUP BY window_start
        ORDER BY window_start ASC
        LIMIT 1000
    """, conn)

    if len(df) < 10: return

    # Pandas ewm 계산
    df['ewm_mean'] = df['total_events'].ewm(span=12).mean()
    df['ewm_std'] = df['total_events'].ewm(span=12).std()
    
    # 3-Sigma Rule
    last_row = df.iloc[-1]
    upper = last_row['ewm_mean'] + (3 * last_row['ewm_std'])
    
    if last_row['total_events'] > upper:
        logger.warning(f"EWMA Anomaly Detected: {last_row['total_events']} > {upper}")
        # 실제 운영시 여기서 events 테이블에 insert 로직 추가 가능

def main():
    start_metrics_server(PROMETHEUS_PORT)
    conn = None
    try:
        conn = get_conn()
        pipe, thresh = load_or_train(conn)
        
        # 메트릭 측정과 함께 실행
        with ML_LATENCY.time():
            run_iforest(conn, pipe, thresh)
            run_ewma(conn)
            
    except Exception as e:
        logger.error(f"ML Detect failed: {e}")
    finally:
        if conn: conn.close()

if __name__ == "__main__":
    main()