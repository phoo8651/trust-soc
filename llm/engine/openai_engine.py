from llm.engine.base_engine import BaseEngine
from llm.models import IncidentAnalysisRequest, IncidentOutput


class OpenAILLM(BaseEngine):
    """외부 OpenAI API용 엔진 (Step 3 이후 실제 연결 예정)"""
    async def analyze_incident(self, incident: IncidentAnalysisRequest) -> IncidentOutput:
        raise NotImplementedError("OpenAI API 연동은 Step 3에서 구현됩니다.")
