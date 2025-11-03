def evaluate_confidence(confidence: float) -> bool:
    """신뢰도 점수 기반 HIL 여부 결정"""
    return confidence < 0.7
