import os
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any

from app.llm.models import IncidentAnalysisRequest, IncidentOutput
from app.llm.masking.data_masking import mask_all
from app.llm.rag.rag_engine import RAGEngine
from app.llm.attack_mapper import AttackMapper
from app.llm.model_gateway import ModelGateway
from app.llm.prompt_manager import PromptManager
from app.llm.utils.guardrail import apply_guardrail

logger = logging.getLogger("AdvisorService")


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

        # 실제 모델 파일 존재 여부 확인
        use_real = os.path.exists(model_path)
        if not use_real:
            logger.warning(f"⚠️ Model not found at {model_path}. Using Dummy LLM.")

        self.gateway = ModelGateway(
            local_model_path=model_path, use_real_llm=use_real, enable_fallback=True
        )

        # 3. KB 로드
        self._load_knowledge_base()
        self._initialized = True

    def _load_knowledge_base(self):
        kb_dir = self.base_dir / "rag" / "knowledge_base"
        if kb_dir.exists():
            count = 0
            for f in kb_dir.glob("*.md"):
                try:
                    self.rag.index_documents(f.stem, f.read_text(encoding="utf-8"))
                    count += 1
                except Exception as e:
                    logger.error(f"RAG Load Error {f.name}: {e}")
            logger.info(f"📚 RAG Loaded: {count} docs")

    async def analyze(self, request: IncidentAnalysisRequest) -> IncidentOutput:
        logger.info(f"Analyzing Incident: {request.incident_id}")

        # 1. Masking
        masked, _ = mask_all(request.event_text)

        # 2. RAG Retrieval
        hits = self.rag.retrieve(masked, top_k=2)
        rag_context = "\n".join([f"- {h['text'][:300]}..." for h in hits])

        # 3. Attack Mapping
        ev_dicts = [e.dict() for e in request.evidences]
        mappings = self.attack_mapper.map(masked, ev_dicts)

        # 4. Prompt Construction
        tpl = self.prompt_manager.load_prompt("summary")
        from string import Template

        prompt = Template(tpl).safe_substitute(
            event_text=masked,
            evidence_block=json.dumps(ev_dicts, ensure_ascii=False),
            rag_block=rag_context,
        )

        # 5. LLM Generation
        raw_resp = await self.gateway.generate(prompt)

        # 6. [수정] JSON Parsing Logic
        parsed = self._safe_parse_json(raw_resp)

        # 7. Result Construction
        summary = parsed.get("summary", f"Analysis of {masked[:50]}...")
        attack_ids = parsed.get("attack_mapping", [])
        if not attack_ids and mappings:
            attack_ids = [m["id"] for m in mappings]

        rec_actions = parsed.get("recommended_actions", ["Investigate logs"])

        # Confidence: Static Rule(Mapping) vs LLM Score 혼합
        rule_conf = mappings[0]["confidence"] if mappings else 0.5
        llm_conf = float(parsed.get("confidence", 0.5))
        final_conf = round(rule_conf * 0.4 + llm_conf * 0.6, 2)  # LLM 비중 상향

        # Guardrail 적용
        status = apply_guardrail(final_conf)

        return IncidentOutput(
            incident_id=request.incident_id,
            summary=summary,
            severity=parsed.get("severity", "Medium"),
            attack_mapping=attack_ids,
            recommended_actions=rec_actions,
            confidence=final_conf,
            hil_required=(status == "pending_approval"),
            status=status,
            evidence_refs=request.evidences,
            raw_response=raw_resp,
        )

    def _safe_parse_json(self, text: str) -> Dict[str, Any]:
        """LLM 출력에서 JSON 블록만 추출하여 파싱"""
        try:
            # Markdown Code Block 제거
            text = text.replace("```json", "").replace("```", "").strip()

            # JSON 시작/끝 찾기
            start = text.find("{")
            end = text.rfind("}") + 1
            if start != -1 and end != -1:
                json_str = text[start:end]
                return json.loads(json_str)
        except Exception as e:
            logger.warning(f"JSON Parse Failed: {e}. Raw: {text[:100]}...")

        return {}  # 실패 시 빈 dict 반환 (기본값 사용)
