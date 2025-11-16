# llm/utils/guardrail.py
"""
Guardrail 정책 모듈
- 최종 confidence 기반 상태 결정
- 증거 부족/스키마 불일치에 대한 처리
"""

import logging

logger = logging.getLogger(__name__)

# Confidence 임계값
CONF_THRESHOLD_AUTO = 0.80  # 자동 승인
CONF_THRESHOLD_HIL = 0.50   # 승인 필요
# 0.5 미만: 차단 또는 HIL 유지

def apply_guardrail(confidence: float) -> str:
    """
    confidence 기반 상태 결정
    - >=0.80: approved
    - 0.50~0.79: pending_approval (HIL)
    - <0.50: pending_approval (추가 검토)
    """
    if confidence >= CONF_THRESHOLD_AUTO:
        status = "approved"
    elif confidence >= CONF_THRESHOLD_HIL:
        status = "pending_approval"
    else:
        status = "pending_approval"

    logger.info(f"[Guardrail] confidence={confidence} → status={status}")
    return status
