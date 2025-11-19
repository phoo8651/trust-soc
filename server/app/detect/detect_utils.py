# -*- coding: utf-8 -*-
# 파일 경로: trust-soc/detect/detect_utils.py
# 목적: 보안 탐지 시스템(trust-soc/detect)에서 사용되는 공통 유틸리티 모듈

import os, json, time, glob, logging, hashlib
import yaml # YAML 파일(정책) 처리
import ed25519 # Ed25519 디지털 서명 구현
import numpy as np # 과학 계산, 특히 동적 임계값 계산에 사용
# Prometheus 클라이언트 라이브러리 (메트릭 수집)
from prometheus_client import Counter, Histogram, Gauge, start_http_server 

# 모듈 로거 설정
logger = logging.getLogger("detect_utils")

# ───────────────────────────────────────────────────────────
# 1) 정책 관리 (PyYAML + Ed25519)
# PolicyManager 클래스는 YAML 형식의 정책 파일을 로드, 병합, 그리고 Ed25519로 서명/검증하는 기능을 제공합니다.
# ───────────────────────────────────────────────────────────
class PolicyManager:
    def __init__(self, policy_dir):
        """
        PolicyManager 초기화. 정책 디렉토리를 설정하고 서명 키를 로드합니다.
        
        policy_dir/
          global.yaml            # 전역 정책 (가장 낮은 우선순위)
          client_<ID>.yaml       # 특정 클라이언트(ID) 정책
          host_<HOST>.yaml       # 특정 호스트(IP/이름) 정책 (가장 높은 우선순위)
        우선순위: global < client < host
        """
        self.dir = policy_dir
        self._load_keys() # Ed25519 키 로드

    def _load_keys(self):
        # 환경 변수에서 개인키 파일 경로를 가져오거나 기본값 사용
        keyfile = os.getenv("POLICY_SIGN_KEY","./keys/ed25519_priv.pem")
        # Ed25519 개인키(.pem) 로드 및 서명 키(SigningKey) 생성
        with open(keyfile, "rb") as f:
            self.signing_key = ed25519.SigningKey(f.read())
        # 서명 키로부터 검증 키(VerifyingKey) 파생
        self.verify_key = self.signing_key.get_verifying_key()

    def load(self, client_id=None, host=None):
        # 로드할 정책 파일 경로 목록 초기화
        paths = []
        # 1) 전역 정책 경로 추가 (기본 정책)
        paths.append(os.path.join(self.dir,"global.yaml"))
        
        # 2) client_id가 제공되면 클라이언트별 정책 경로 추가 (전역 정책 재정의)
        if client_id:
            paths.append(os.path.join(self.dir, f"client_{client_id}.yaml"))
        
        # 3) host가 제공되면 호스트별 정책 경로 추가 (가장 높은 우선순위로 재정의)
        if host:
            paths.append(os.path.join(self.dir, f"host_{host}.yaml"))

        merged = {}
        for p in paths:
            if os.path.exists(p):
                with open(p,"r") as f:
                    # YAML 파일 안전하게 로드
                    data = yaml.safe_load(f)
                # 이전 정책과 새 정책을 깊은 병합(deep merge)
                merged = self._deep_merge(merged, data)
        return merged

    def _deep_merge(self, base, override):
        """
        두 딕셔너리를 깊게 병합 (재귀적으로 중첩된 딕셔너리를 병합).
        override의 값이 base의 값을 덮어씁니다.
        """
        for k,v in override.items():
            # 두 값 모두 딕셔너리인 경우, 재귀적으로 병합
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                base[k] = self._deep_merge(base[k], v)
            else:
                # 딕셔너리가 아닌 경우, override 값으로 덮어쓰기
                base[k] = v
        return base

    def canonicalize(self, obj):
        """
        딕셔너리 객체를 Canonical JSON (키 정렬, 구분자 최소화) 문자열로 변환합니다.
        이는 서명의 일관성을 보장하기 위함입니다.
        """
        # JSON 키 정렬 → canonical JSON
        return json.dumps(obj, sort_keys=True, separators=(',',':'))

    def sign(self, obj):
        """
        정책 객체(dict)에 Ed25519 서명을 생성합니다.
        반환: 서명 값의 16진수 문자열(hex)
        """
        # Canonical JSON으로 변환 후 바이트로 인코딩
        cj = self.canonicalize(obj).encode()
        # Ed25519 서명 생성
        sig = self.signing_key.sign(cj)
        # 서명을 16진수 문자열로 반환
        return sig.hex()

    def verify(self, obj, sig_hex):
        """
        정책 객체(dict)와 주어진 서명 값(hex)을 Ed25519로 검증합니다.
        """
        # Canonical JSON으로 변환 후 바이트로 인코딩
        cj = self.canonicalize(obj).encode()
        try:
            # 16진수 서명을 바이트로 변환
            sig_bytes = bytes.fromhex(sig_hex)
            # 검증 키를 사용하여 서명 검증
            self.verify_key.verify(sig_bytes, cj)
            return True # 검증 성공
        except ed25519.BadSignatureError:
            return False # 검증 실패

# ───────────────────────────────────────────────────────────
# 2) Drift 튜너 (3σ Rule, 7일 윈도우)
# 이상치 점수의 동적 임계값을 계산하여, 환경 변화에 따라 임계값을 자동으로 조정(Drift Tuning)합니다.
# ───────────────────────────────────────────────────────────
def dynamic_threshold(scores, method="3sigma"):
    """
    과거 이상치 점수(scores)를 기반으로 동적 임계값을 계산합니다.
    scores: 과거 이상치 점수들의 numpy 배열
    method: 임계값 계산 방법 ("3sigma" 또는 "percentile")
    """
    if method == "3sigma":
        # 중앙값 (Median) 계산
        med = np.median(scores)
        # 표준 편차 (Standard Deviation) 계산
        sigma = np.std(scores)
        # 3-시그마 규칙 적용: 중앙값 + 3 * 표준편차
        return med + 3*sigma
    else:
        # "3sigma"가 아닌 경우, 99% 백분위수(Percentile)를 폴백(fallback)으로 사용
        return np.percentile(scores, 99)

# ───────────────────────────────────────────────────────────
# 3) Prometheus 메트릭 (performance/SLO)
# 탐지 시스템의 성능과 서비스 수준 목표(SLO)를 모니터링하기 위한 메트릭 정의
# ───────────────────────────────────────────────────────────

# **Counter**: 누적 횟수를 기록 (계속 증가)
# Ingest 과정에서 드롭된 로그의 총 개수
INGEST_DROPPED = Counter("ingest_dropped_total","Dropped logs at ingest")

# **Histogram**: 관측값을 버킷으로 나누어 분포와 분위수(p95 등)를 측정
# 롤업(데이터 집계) 윈도우의 처리 지연 시간 (단위: seconds)
ROLLUP_LATENCY = Histogram("rollup_latency_seconds",
                           "Latency of each rollup window",
                           # 0.1, 0.5, 1, 5, 10, 30, 60, 120초 버킷
                           buckets=[0.1,0.5,1,5,10,30,60,120]) 

# YARA 파일 스캔 지연 시간
YARA_LATENCY   = Histogram("yara_scan_latency_seconds",
                           "Latency per file YARA scan",
                           # 0.01초부터 5초까지 버킷
                           buckets=[0.01,0.05,0.1,0.5,1,5]) 

# ML(머신러닝) 탐지 지연 시간
ML_LATENCY     = Histogram("ml_detect_latency_seconds",
                           "Latency of ML detection",
                           # 0.1초부터 30초까지 버킷
                           buckets=[0.1,0.5,1,5,10,30])

# 하이브리드 탐지 (ML + Rule 등) 지연 시간
HYBRID_LATENCY = Histogram("hybrid_detect_latency_seconds",
                           "Latency of hybrid detection",
                           # 0.1초부터 30초까지 버킷
                           buckets=[0.1,0.5,1,5,10,30])

# **Gauge**: 특정 시점의 값을 기록 (증가/감소 가능)
# 운영팀이 수동으로 설정/업데이트하는 오탐률(False Positive Rate) 게이지
FPR_GAUGE      = Gauge("detection_fpr","False Positive Rate") 
# 운영팀이 수동으로 설정/업데이트하는 F1 스코어 게이지 (탐지 성능 지표)
F1_GAUGE       = Gauge("detection_f1","F1 Score") 

# Metrics HTTP 엔드포인트(예: 8000)
def start_metrics_server(port:int=8000):
    """
    Prometheus 메트릭을 제공하는 HTTP 서버를 시작합니다.
    """
    start_http_server(port)
    logger.info("Prometheus metrics serving on :%d", port)