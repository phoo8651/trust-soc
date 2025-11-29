import logging
logger = logging.getLogger(__name__)

def determine_hil_requirement(confidence: float) -> bool:
    """
    HIL 필요 여부 결정 정책
    - confidence < 0.80 ⇒ require HIL
    """
    return confidence < 0.80


def log_incident_decision(incident_id: str, confidence: float, hil_required: bool) -> None:
    """Incident 의사결정 기록 (추후 DB 연동 가능)"""
    logger.info(
        "[IncidentDecision] incident_id=%s confidence=%.3f hil_required=%s",
        incident_id,
        confidence,
        hil_required,
    )
