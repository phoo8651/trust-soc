#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hybrid_detect.py

2.4. 하이브리드 탐지 & 이벤트 생성
- Final_Score = W_rule*Rule_Bool + W_ml*ML_Score - W_fp*FP_Penalty
- Critical/High/Medium Severity 결정
- events.summary, events.attack_mapping 채움
- feature_rollup_5m.hybrid_processed = TRUE 로 멱등성 보장
- Prometheus 지연 시간 측정 기능 추가.
"""

import os
import sys
import logging
import psycopg2
from psycopg2.extras import DictCursor, Json

# ⚠️ detect_utils 모듈의 함수를 임포트한다고 가정
# 실제 사용을 위해 prometheus_client 라이브러리 설치 및 해당 유틸리티 모듈 구현이 필요합니다.
from prometheus_client import start_http_server, Histogram
from rollup import ensure_schema

# ───────────────────────────────────────────────────────────
# Prometheus 메트릭 정의 (detect_utils에서 가져온다고 가정했지만, 코드를 위해 직접 정의)
# ───────────────────────────────────────────────────────────
HYBRID_LATENCY = Histogram(
    "hybrid_detect_latency_seconds",
    "Latency of the hybrid detection and event insertion job",
)


def start_metrics_server(port):
    """Prometheus 메트릭 서버를 시작합니다."""
    try:
        start_http_server(port)
        logger.info(f"Prometheus 메트릭 서버 시작. 포트: {port}")
    except Exception as e:
        logger.error("Prometheus 서버 시작 실패: %s", e)
        # 서버 시작 실패는 치명적이지 않을 수 있으므로 sys.exit(1) 대신 경고만 남깁니다.


# ───────────────────────────────────────────────────────────
# 가중치 상수 (Hybrid Score 계산용)
# ───────────────────────────────────────────────────────────
W_RULE = 1.0  # 룰 매치 발생 시 부여하는 점수 가중치 (강제 이벤트화)
W_ML = 0.7  # ML 이상치 점수에 부여하는 가중치
W_FP = 0.3  # 오탐(False Positive) 피드백에 대한 페널티 가중치

# ───────────────────────────────────────────────────────────
# ATT&CK 매핑 예제
# ───────────────────────────────────────────────────────────
ATTACK_MAP = {
    # YARA 룰 네임스페이스 혹은 룰명 → MITRE ID 매핑 예시
    # e.g. "web_shell": "T1505",
    # ML 이벤트 타입별 기본 매핑
    "iforest_multivariate": "T1059",  # Command and Scripting Interpreter 예시
    "ewma_timeseries": "T1090",  # Proxy (네트워크 급증/급감) 예시
}

# ───────────────────────────────────────────────────────────
# DB 연결 정보 (환경변수)
# ───────────────────────────────────────────────────────────
DB_CFG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432"),
    "dbname": os.getenv("DB_NAME", "logs_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "password"),
}
PROMETHEUS_PORT = int(os.getenv("METRICS_PORT", 8000))

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("hybrid_detect")


def get_conn():
    """DB 연결 객체를 반환합니다."""
    return psycopg2.connect(cursor_factory=DictCursor, **DB_CFG)


def fetch_fp_penalty(conn, client_id, host_name, source_ip, window_start):
    """
    (선택) False Positive 피드백 테이블에서 오탐 페널티 점수를 조회합니다.
    (실제 구현에서는 DB 접근이 필요하며, 현재는 0.0을 반환하는 스텁 함수입니다.)
    """
    return 0.0


def run_hybrid(conn):
    """
    feature_rollup_5m 의 ML 처리 완료(ml_processed=TRUE) 되었지만,
    아직 하이브리드 처리가 안 된(hybrid_processed=FALSE) 레코드를 순회하며
    최종 하이브리드 이벤트를 생성합니다.
    """
    with conn.cursor() as cur:
        # 1) 처리 대상 조회 (ML 점수가 이미 계산된 레코드만 대상)
        cur.execute(
            """
        SELECT client_id, host_name, source_ip, window_start, window_end, ml_score
          FROM feature_rollup_5m
        WHERE ml_processed = TRUE
          AND hybrid_processed IS NOT TRUE
        """
        )
        rows = cur.fetchall()

    if not rows:
        logger.info("하이브리드 처리 대상 없음")
        return

    logger.info("하이브리드 처리 시작: %d 건", len(rows))
    hybrid_events = []
    update_keys = []

    for r in rows:
        client_id, host_name, source_ip, window_start, window_end, ml_score = (
            r["client_id"],
            r["host_name"],
            r["source_ip"],
            r["window_start"],
            r["window_end"],
            r["ml_score"],
        )

        # 2) 해당 윈도우 기간 내에 룰(YARA) 탐지 이벤트가 있었는지 확인 (Rule_Bool)
        # Note: 룰 매치 여부 확인은 루프 내에서 DB 접근이 발생합니다.
        with conn.cursor() as cur:
            cur.execute(
                """
            SELECT COUNT(1) AS cnt
              FROM events
             WHERE event_type = 'yara_match'
               AND client_id = %s AND host_name = %s AND metadata->>'namespace' IS NOT NULL
               AND "@timestamp" BETWEEN %s AND %s
            """,
                (client_id, host_name, window_start, window_end),
            )
            rule_bool = 1 if cur.fetchone()["cnt"] > 0 else 0

        # 3) False-Positive 페널티 조회 (현재는 0.0)
        fp_penalty = fetch_fp_penalty(
            conn, client_id, host_name, source_ip, window_start
        )

        # 4) Final Score 계산 (핵심 공식)
        # Final_Score = W_rule * Rule_Bool + W_ml * ML_Score - W_fp * FP_Penalty
        final_score = W_RULE * rule_bool + W_ML * ml_score - W_FP * fp_penalty

        # 5) Severity 결정
        if rule_bool == 1 and final_score > 1.0:
            severity = "Critical"  # 룰 매치 & 점수 높으면 Critical
        elif final_score >= 0.8:
            severity = "High"
        elif final_score >= 0.5:
            severity = "Medium"
        else:
            # 낮은 점수는 이벤트화를 생략하지만, hybrid_processed 플래그는 설정해야 함
            logger.debug(
                "Final_Score 낮음(%.3f) → 생략: %s/%s/%s@%s",
                final_score,
                client_id,
                host_name,
                source_ip,
                window_start,
            )
            update_keys.append(
                (client_id, host_name, source_ip, window_start, final_score)
            )  # 9) final_score를 함께 저장
            continue

        # 6) ATT&CK 매핑 추출
        attack_mapping = None
        if rule_bool == 1:
            with conn.cursor() as cur:
                # 룰 매칭 시 events 테이블에서 해당 룰의 메타데이터(meta.attack_mapping)를 추출
                cur.execute(
                    """
                SELECT metadata->'meta'->>'attack_mapping' AS att
                  FROM events
                 WHERE event_type = 'yara_match'
                   AND client_id=%s AND host_name=%s
                   AND "@timestamp" BETWEEN %s AND %s
                   LIMIT 1
                """,
                    (client_id, host_name, window_start, window_end),
                )
                row2 = cur.fetchone()
                attack_mapping = row2["att"] if row2 and row2["att"] else None

        if not attack_mapping:
            # 룰 매핑이 없으면 ML 기본 매핑 사용
            attack_mapping = ATTACK_MAP.get("iforest_multivariate")

        # 7) Summary 작성
        summary = (
            f"HybridDetect rule={rule_bool} ml_score={ml_score:.3f} "
            f"final_score={final_score:.3f} "
            f"{client_id}/{host_name}/{source_ip} @ {window_start}"
        )

        # 8) 이벤트 리스트에 추가
        hybrid_events.append(
            {
                "client_id": client_id,
                "host_name": host_name,
                "source_ip": source_ip,
                "window_start": window_start,
                "severity": severity,
                "summary": summary,
                "final_score": final_score,
                "attack_mapping": attack_mapping,
                "timestamp": window_end,  # 이벤트 발생 시각 (윈도우 종료 시점 사용)
                "rule_bool": rule_bool,  # DB 삽입을 위해 메타데이터 정보 저장
                "fp_penalty": fp_penalty,
                "ml_score_raw": ml_score,  # 원본 ml_score
            }
        )
        update_keys.append(
            (client_id, host_name, source_ip, window_start, final_score)
        )  # 9) final_score를 함께 저장

    # 10) 이벤트 일괄 삽입 및 상태 업데이트
    # 🌟 요청된 HYBRID_LATENCY 측정 블록 시작
    with HYBRID_LATENCY.time():
        with conn.cursor() as cur:
            # events 테이블에 삽입
            SQL_INS = """
            INSERT INTO events (
              event_id, client_id, host_name, source_ip,
              event_category, event_type, severity, summary,
              metadata, "@timestamp", attack_mapping
            ) VALUES (
              gen_random_uuid(), %s, %s, %s,
              'hybrid', 'hybrid_detect', %s, %s,
              %s, %s, %s
            ) ON CONFLICT DO NOTHING
            """
            vals = []
            # 삽입할 이벤트 데이터 준비
            for e in hybrid_events:
                # metadata에 가중치·피드백 정보 포함 (디버깅/감사 목적)
                meta = {
                    "rule_bool": e["rule_bool"],
                    "ml_score": e["ml_score_raw"],
                    "final_score": e["final_score"],
                    "fp_penalty": e["fp_penalty"],
                }
                vals.append(
                    (
                        e["client_id"],
                        e["host_name"],
                        e["source_ip"],
                        e["severity"],
                        e["summary"],
                        Json(meta),
                        e["timestamp"],
                        e["attack_mapping"],
                    )
                )
            cur.executemany(SQL_INS, vals)
            logger.info("이벤트 삽입: %d건", len(hybrid_events))

            # feature_rollup_5m.hybrid_processed, final_score 업데이트 (성공/생략 모두 처리)
            SQL_UPD_SCORE = """
            UPDATE feature_rollup_5m
                SET hybrid_processed = TRUE,
                    final_score      = %s
              WHERE client_id = %s
                AND host_name = %s
                AND source_ip = %s
                AND window_start = %s
            """
            SQL_UPD_ONLY_PROCESSED = """
            UPDATE feature_rollup_5m
                SET hybrid_processed = TRUE
              WHERE client_id = %s
                AND host_name = %s
                AND source_ip = %s
                AND window_start = %s
            """

            # update_keys 리스트를 순회하며 업데이트 실행
            for (
                client_id,
                host_name,
                source_ip,
                window_start,
                final_score,
            ) in update_keys:
                if final_score is not None:
                    # 이벤트화 된 경우: final_score 업데이트
                    cur.execute(
                        SQL_UPD_SCORE,
                        (final_score, client_id, host_name, source_ip, window_start),
                    )
                else:
                    # 이벤트 생략된 경우: processed만 TRUE (final_score는 NULL)
                    cur.execute(
                        SQL_UPD_ONLY_PROCESSED,
                        (client_id, host_name, source_ip, window_start),
                    )

        conn.commit()
    # 🌟 HYBRID_LATENCY 측정 블록 종료 (conn.commit() 포함하여 측정됨)
    logger.info(
        "하이브리드 탐지 완료: %d건 이벤트 생성, %d건 처리 완료 플래그 설정",
        len(hybrid_events),
        len(update_keys),
    )


def main():
    """DB 연결 및 하이브리드 탐지 실행 메인 함수."""
    # 1) Metrics endpoint 시작
    start_metrics_server(PROMETHEUS_PORT)

    conn = None
    try:
        conn = get_conn()
    except Exception as ex:
        logger.error("DB 연결 실패: %s", ex)
        sys.exit(1)

    try:
        # 🔹 롤업/하이브리드가 사용하는 테이블 스키마 보장
        try:
            ensure_schema(conn)
        except Exception:
            logger.exception("롤업/이벤트 테이블 스키마 초기화 실패")

        run_hybrid(conn)
    except Exception:
        logger.exception("하이브리드 탐지 중 치명적 오류")
    finally:
        if conn:
            conn.close()
            logger.info("DB 연결 종료")
            logger.info("종료")


if __name__ == "__main__":
    main()
