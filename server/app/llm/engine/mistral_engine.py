import os
import json
import logging
try:
    from llama_cpp import Llama
except ImportError:
    Llama = None

from app.llm.engine.base_engine import BaseEngine
from app.llm.models import IncidentAnalysisRequest, IncidentOutput

logger = logging.getLogger("mistral_engine")

class MistralLLM(BaseEngine):
    def __init__(self, model_path: str):
        if not Llama:
            raise ImportError("llama-cpp-python required")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
            
        self.llm = Llama(
            model_path=model_path,
            n_ctx=4096,
            n_gpu_layers=-1,
            verbose=False
        )
        logger.info(f"Loaded Mistral: {os.path.basename(model_path)}")

    async def analyze_incident(self, request: IncidentAnalysisRequest) -> IncidentOutput:
        prompt = f"[INST] Analyze this: {request.event_text} [/INST]"
        output = self.llm(prompt, max_tokens=512, echo=False)
        text = output["choices"][0]["text"]
        
        # 결과 반환 (Dummy로 채움, 실제론 파싱 필요)
        return IncidentOutput(
            incident_id=request.incident_id,
            summary=text[:100],
            severity="Medium",
            attack_mapping=[],
            recommended_actions=[],
            confidence=0.7,
            hil_required=True,
            status="pending",
            evidence_refs=request.evidences
        )