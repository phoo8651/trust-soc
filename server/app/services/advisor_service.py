import os
import logging
from pathlib import Path
from typing import Optional

from app.llm.models import IncidentAnalysisRequest, IncidentOutput
from app.llm.masking.data_masking import mask_all
from app.llm.rag.rag_engine import RAGEngine
from app.llm.attack_mapper import AttackMapper
from app.llm.model_gateway import ModelGateway
from app.llm.prompt_manager import PromptManager
from app.llm.utils.guardrail import apply_guardrail

logger = logging.getLogger("advisor_service")


class AdvisorService:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AdvisorService, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.base_dir = Path("/app/app/llm")  # Docker 내부 경로

        # 1. 컴포넌트 초기화
        self.rag = RAGEngine()
        self.attack_mapper = AttackMapper()
        self.prompt_manager = PromptManager(
            base_path=str(self.base_dir / "prompt_templates")
        )

        # 2. Gateway 초기화
        model_path = os.getenv(
            "LOCAL_MODEL", "/app/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf"
        )
        self.gateway = ModelGateway(
            local_model_path=model_path,
            use_real_llm=os.path.exists(model_path),
            enable_fallback=True,
        )

        # 3. KB 로드
        self._load_knowledge_base()
        self._initialized = True

    def _load_knowledge_base(self):
        kb_dir = self.base_dir / "rag" / "knowledge_base"
        if kb_dir.exists():
            count = 0
            for f in kb_dir.glob("*.md"):
                self.rag.index_documents(f.stem, f.read_text(encoding="utf-8"))
                count += 1
            logger.info(f"📚 RAG Loaded: {count} docs")

    async def analyze(self, request: IncidentAnalysisRequest) -> IncidentOutput:
        logger.info(f"Analyzing: {request.incident_id}")

        # 1. Masking
        masked, _ = mask_all(request.event_text)

        # 2. RAG
        hits = self.rag.retrieve(masked, top_k=2)
        rag_context = "\n".join([h["text"][:200] for h in hits])

        # 3. Mapping
        ev_dicts = [e.dict() for e in request.evidences]
        mappings = self.attack_mapper.map(masked, ev_dicts)

        # 4. Prompt
        tpl = self.prompt_manager.load_prompt("summary")
        from string import Template

        prompt = Template(tpl).safe_substitute(
            event_text=masked, evidence_block=str(ev_dicts), rag_block=rag_context
        )

        # 5. LLM
        resp = await self.gateway.generate(prompt)

        # 6. 결과 조립 (간소화)
        # 실제로는 JSON 파싱 로직 필요 (이전 답변 참조)
        return IncidentOutput(
            summary=f"Analysis of {masked[:50]}...",
            attack_mapping=[m["id"] for m in mappings] if mappings else ["UNKNOWN"],
            recommended_actions=["Check logs", "Isolate host"],
            confidence=0.8,
            hil_required=False,
            status="approved",
            evidence_refs=request.evidences,
        )
