# -*- coding: utf-8 -*-
# /backend/postgres/app/detect/detect_utils.py

import os
import json
import logging
import yaml
from prometheus_client import Counter, Histogram, start_http_server

# Ed25519 라이브러리 (선택적 로드: 키 파일이 없어도 서버가 죽지 않도록)
try:
    import ed25519
except ImportError:
    ed25519 = None

# 로거 설정
logger = logging.getLogger("detect_utils")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ───────────────────────────────────────────────────────────
# 1) Prometheus 메트릭 정의 (전역 공유)
# ───────────────────────────────────────────────────────────
# 데이터 수집 단계에서 누락된 로그 수
INGEST_DROPPED = Counter("ingest_dropped_total", "Dropped logs at ingest")

# 롤업(집계) 작업 소요 시간
ROLLUP_LATENCY = Histogram("rollup_latency_seconds", "Latency of rollup job", buckets=[0.1, 1, 5, 10, 60])

# YARA 스캔 소요 시간
YARA_LATENCY   = Histogram("yara_scan_latency_seconds", "Latency per YARA scan", buckets=[0.01, 0.1, 1, 5])

# ML 탐지 소요 시간
ML_LATENCY     = Histogram("ml_detect_latency_seconds", "Latency of ML detection", buckets=[0.1, 1, 5, 10])

# 하이브리드 탐지 소요 시간
HYBRID_LATENCY = Histogram("hybrid_detect_latency_seconds", "Latency of hybrid detection", buckets=[0.1, 1, 5, 10])

def start_metrics_server(port: int = 8001):
    """
    Prometheus 메트릭 서버를 시작합니다.
    API 서버(8000)와 충돌을 방지하기 위해 기본값을 8001로 설정합니다.
    이미 실행 중인 경우(멀티 프로세스 환경 등) 예외를 무시합니다.
    """
    try:
        start_http_server(port)
        logger.info(f"Prometheus metrics serving on :{port}")
    except OSError as e:
        if e.errno == 98: # Address already in use
            logger.warning(f"Port {port} is already in use. Assuming metrics server is running.")
        else:
            raise e

# ───────────────────────────────────────────────────────────
# 2) 정책 관리 (Policy Manager)
# ───────────────────────────────────────────────────────────
class PolicyManager:
    """
    YAML 기반의 탐지 정책을 로드하고 Ed25519 서명을 검증하는 클래스
    """
    def __init__(self, policy_dir):
        self.dir = policy_dir
        self.signing_key = None
        self.verify_key = None
        # Ed25519 모듈이 있고 키 파일 경로가 설정된 경우 키 로드
        if ed25519:
            self._load_keys()

    def _load_keys(self):
        """환경변수 또는 기본 경로에서 서명 키 로드"""
        keyfile = os.getenv("POLICY_SIGN_KEY", "/app/keys/ed25519_priv.pem")
        if os.path.exists(keyfile):
            try:
                with open(keyfile, "rb") as f:
                    self.signing_key = ed25519.SigningKey(f.read())
                self.verify_key = self.signing_key.get_verifying_key()
                logger.info("Policy signing keys loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load keys: {e}")

    def load(self, client_id=None, host=None):
        """
        Global -> Client -> Host 순서로 정책을 병합(Override)하여 반환
        """
        paths = [os.path.join(self.dir, "global.yaml")]
        if client_id:
            paths.append(os.path.join(self.dir, f"client_{client_id}.yaml"))
        if host:
            paths.append(os.path.join(self.dir, f"host_{host}.yaml"))

        merged = {}
        for p in paths:
            if os.path.exists(p):
                try:
                    with open(p, "r") as f:
                        data = yaml.safe_load(f) or {}
                    merged = self._deep_merge(merged, data)
                except Exception as e:
                    logger.warning(f"Failed to load policy file {p}: {e}")
        return merged

    def _deep_merge(self, base, override):
        """딕셔너리 재귀 병합"""
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                base[k] = self._deep_merge(base[k], v)
            else:
                base[k] = v
        return base