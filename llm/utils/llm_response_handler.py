# llm/utils/llm_response_handler.py
import logging

logger = logging.getLogger(__name__)

def evaluate_confidence(parsed: dict) -> float:
    """
    LLM 응답 내 confidence 필드 기반으로 신뢰도 평가.
    없거나 이상한 값이면 0.0으로 기본 처리.
    """
    try:
        conf = float(parsed.get("confidence", 0.0))
        if not (0.0 <= conf <= 1.0):
            return 0.0
        return conf
    except Exception:
        return 0.0


def determine_hil_requirement(confidence: float) -> bool:
    """
    신뢰도가 0.6 미만이면 HIL(Human-In-the-Loop) 필요.
    """
    return confidence < 0.6


def log_incident_decision(incident_id: str, confidence: float, hil_required: bool):
    """
    의사결정 로그 출력
    """
    level = "⚠️ HIL REQUIRED" if hil_required else "✅ Auto-approved"
    logger.info(f"[{incident_id}] Confidence={confidence:.2f} → {level}")
