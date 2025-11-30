import os
import json
import logging
import re
from pathlib import Path
from typing import Optional, Dict, Any, List

from app.llm.models import IncidentAnalysisRequest, IncidentOutput
from app.llm.masking.data_masking import mask_all
from app.llm.rag.rag_engine import RAGEngine
from app.llm.attack_mapper import AttackMapper
from app.llm.model_gateway import ModelGateway
from app.llm.prompt_manager import PromptManager
from app.llm.utils.guardrail import apply_guardrail

# [수정] 로그 설정을 명시적으로 초기화 (INFO 레벨 이상 출력)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("AdvisorService")
logger.setLevel(logging.INFO)


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

        self.base_dir = Path("/app/app/llm")
        self.rag = RAGEngine()
        self.attack_mapper = AttackMapper()
        self.prompt_manager = PromptManager(
            base_path=str(self.base_dir / "prompt_templates")
        )

        model_path = os.getenv(
            "LOCAL_MODEL", "/app/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf"
        )
        use_real = os.path.exists(model_path)

        self.gateway = ModelGateway(
            local_model_path=model_path,
            use_real_llm=use_real,
            enable_fallback=True,
            timeout=300,
        )

        self._load_knowledge_base()
        self._initialized = True

    def _load_knowledge_base(self):
        kb_dir = self.base_dir / "rag" / "knowledge_base"
        if kb_dir.exists():
            for f in kb_dir.glob("*.md"):
                try:
                    self.rag.index_documents(f.stem, f.read_text(encoding="utf-8"))
                except:
                    pass

    async def analyze(self, request: IncidentAnalysisRequest) -> IncidentOutput:
        logger.info(f"Analyzing Incident: {request.incident_id}")

        # 1. Masking
        masked, _ = mask_all(request.event_text)

        # 2. RAG
        hits = self.rag.retrieve(masked, top_k=2)
        rag_context = "\n".join([f"- {h['text'][:300]}..." for h in hits])

        # 3. Mapping
        ev_dicts = [e.dict() for e in request.evidences]
        mappings = self.attack_mapper.map(masked, ev_dicts)

        # 4. Prompt
        tpl = self.prompt_manager.load_prompt("summary")
        from string import Template

        prompt = Template(tpl).safe_substitute(
            event_text=masked,
            evidence_block=json.dumps(ev_dicts, ensure_ascii=False),
            rag_block=rag_context,
        )

        # 5. LLM Generate
        raw_resp = await self.gateway.generate(prompt)

        # [수정] 디버깅을 위해 WARNING 레벨로 원본 응답 강제 출력
        logger.warning(
            f"📝 [LLM Raw Response START] \n{raw_resp}\n [LLM Raw Response END]"
        )

        # 6. Parsing
        parsed = self._safe_parse_json(raw_resp)

        if not parsed:
            # 2차 시도: 텍스트 추출
            logger.warning("JSON parsing failed. Attempting text fallback extraction.")
            parsed = self._fallback_text_extract(raw_resp)
            # 추출 결과도 로그로 확인
            logger.warning(f"Fallback extracted data: {parsed}")

        # 7. Result Construction
        summary = parsed.get("summary") or f"Analysis of {masked[:50]}..."

        attack_ids = parsed.get("attack_mapping")
        if not attack_ids or not isinstance(attack_ids, list):
            if mappings:
                attack_ids = [m["id"] for m in mappings]
            else:
                attack_ids = ["UNKNOWN"]

        actions = parsed.get("recommended_actions")
        if not actions or not isinstance(actions, list):
            actions = ["Manual Investigation Required", "Check System Logs"]

        rule_conf = mappings[0]["confidence"] if mappings else 0.5
        llm_conf = float(parsed.get("confidence", 0.5))
        final_conf = round(rule_conf * 0.4 + llm_conf * 0.6, 2)

        status = apply_guardrail(final_conf)

        return IncidentOutput(
            incident_id=request.incident_id,
            summary=summary,
            severity=parsed.get("severity", "Medium"),
            attack_mapping=attack_ids,
            recommended_actions=actions,
            confidence=final_conf,
            hil_required=(status == "pending_approval"),
            status=status,
            evidence_refs=request.evidences,
            raw_response=raw_resp,
        )

    def _safe_parse_json(self, text: str) -> Dict[str, Any]:
        """
        LLM 출력에서 JSON 객체를 추출하고, 형식이 깨져있으면 복구를 시도합니다.
        """
        try:
            # 1. Markdown 코드 블럭 제거
            text = re.sub(r"```json\s*", "", text)
            text = text.replace("```", "")

            # 2. 가장 바깥쪽 { ... } 찾기 시도
            match = re.search(r"(\{.*\})", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    pass  # 정규식으로 찾았으나 내부 문법 오류인 경우, 아래 로직으로 이동

            # 3. [복구 로직] '{' 로 시작하는 부분부터 끝까지 가져와서 수리 시도
            start_idx = text.find("{")
            if start_idx != -1:
                json_str = text[start_idx:].strip()

                # 닫는 괄호가 부족한 경우 순차적으로 추가하며 파싱 시도
                for i in range(3):  # 최대 3개의 } 까지 붙여봄
                    try:
                        return json.loads(json_str + ("}" * i))
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.warning(f"JSON Parse Logic Error: {e}")

        return {}

    def _fallback_text_extract(self, text: str) -> Dict[str, Any]:
        data = {}
        m_summ = re.search(
            r"(?:Summary|Analysis):\s*(.+?)(?:\n|$)", text, re.IGNORECASE
        )
        if m_summ:
            data["summary"] = m_summ.group(1).strip()

        actions = re.findall(r"-\s*(.+)", text)
        if actions:
            data["recommended_actions"] = actions[:3]

        return data
