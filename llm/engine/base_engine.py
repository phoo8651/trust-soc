#llm/engine/base_engine.py
from abc import ABC, abstractmethod
from llm.models import IncidentAnalysisRequest, IncidentOutput


class BaseEngine(ABC):
    """공통 LLM 엔진 인터페이스"""
    @abstractmethod
    async def analyze_incident(self, incident: IncidentAnalysisRequest) -> IncidentOutput:
        pass
