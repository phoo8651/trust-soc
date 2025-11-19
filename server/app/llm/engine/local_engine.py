#llm/engine/local_engine.py
from llm.engine.base_engine import BaseEngine
from llm.models import IncidentAnalysisRequest, IncidentOutput, EvidenceOutput


class DummyLocalLLM(BaseEngine):
    """로컬 테스트용 더미 LLM"""
    async def analyze_incident(self, incident: IncidentAnalysisRequest) -> IncidentOutput:
        return IncidentOutput(
            incident_id=incident.incident_id,
            summary=f"분석된 이벤트: {incident.event_text[:50]}...",
            severity="Low",
            attack_mapping="T1595: Active Scanning",
            recommended_actions="로그 모니터링 강화",
            evidences=[
                EvidenceOutput(type=e.type, ref_id=e.ref_id, relevance_score=0.8)
                for e in incident.evidences
            ],
        )
