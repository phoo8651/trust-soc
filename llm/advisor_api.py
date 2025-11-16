from fastapi import FastAPI, HTTPException
import json, jsonschema, asyncio, re, logging, traceback
from pathlib import Path
import os
from string import Template

from llm.models import EvidenceRef, IncidentOutput
from llm.prompt_manager import PromptManager
from llm.masking.data_masking import mask_all, mask_snippet_evidence, validate_masked
from llm.model_gateway import ModelGateway
from llm.rag.rag_engine import RAGEngine
from llm.utils.llm_response_handler import determine_hil_requirement, log_incident_decision

# -------------------------
# FastAPI 앱 초기화
# -------------------------
app = FastAPI(title="Incident Advisor API")
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# -------------------------
# 프롬프트 매니저 초기화
# -------------------------
prompt_manager = PromptManager(base_path=str(Path(__file__).resolve().parent / "prompt_templates"))

# -------------------------
# LLM Gateway 초기화
# -------------------------
LLM_MODE = os.getenv("LLM_MODE", "local").lower()
if LLM_MODE == "gateway":
    model_gateway = ModelGateway(
        external_api_url=os.getenv("EXTERNAL_API_URL"),
        external_api_key=os.getenv("EXTERNAL_API_KEY"),
        local_model_path=os.path.join("llm", "models", "mistral-7b-instruct-v0.2.Q4_K_M.gguf"),
        use_real_llm=True
    )
else:
    model_gateway = ModelGateway(
        local_model_path=os.path.join("llm", "models", "mistral-7b-instruct-v0.2.Q4_K_M.gguf"),
        use_real_llm=True
    )
logger.info(f"✅ LLM Engine Loaded: {model_gateway.__class__.__name__}")

# -------------------------
# RAG Engine 초기화
# -------------------------
rag = RAGEngine()
try:
    rag.index_documents([])
except Exception as e:
    logger.warning(f"RAG 초기화 실패 (문서 없음): {e}")

# -------------------------
# JSON Schema 로드
# -------------------------
BASE_DIR = Path(__file__).resolve().parent
POSSIBLE_PATHS = [BASE_DIR / "output_schema.json", BASE_DIR.parent / "llm" / "output_schema.json"]
for p in POSSIBLE_PATHS:
    if p.exists():
        SCHEMA_PATH = p
        break
else:
    raise FileNotFoundError("❌ output_schema.json 파일을 찾을 수 없습니다.")

with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
    OUTPUT_SCHEMA = json.load(f)

def validate_schema(data: dict) -> bool:
    """LLM 출력이 JSON Schema와 일치하는지 검증"""
    try:
        jsonschema.validate(instance=data, schema=OUTPUT_SCHEMA)
        return True
    except jsonschema.ValidationError:
        return False

def validate_evidence_refs(evidences: list):
    """EvidenceRef 필드 유효성 검사"""
    allowed_types = {"raw", "yara", "hex", "webhook"}
    for e in evidences:
        if e.get("type") not in allowed_types:
            raise HTTPException(422, detail={"error_code": "EVIDENCE_INVALID", "message": f"Invalid type: {e.get('type')}"})
        for f in ["ref_id", "source", "offset", "length", "sha256"]:
            if f not in e:
                raise HTTPException(422, detail={"error_code": "EVIDENCE_INVALID", "message": f"Missing field: {f}"})
        if not isinstance(e["offset"], int) or not isinstance(e["length"], int):
            raise HTTPException(422, detail={"error_code": "EVIDENCE_INVALID", "message": "offset/length must be integer"})
        if not re.fullmatch(r"[0-9a-fA-F]{6,64}", e["sha256"]):
            raise HTTPException(422, detail={"error_code": "EVIDENCE_INVALID", "message": "Invalid sha256 format"})

def build_prompt(name: str, event_text: str, evidences: list, rag_hits: list):
    """LLM 프롬프트 생성 (RAG + Evidence 포함)"""
    tpl = prompt_manager.load_prompt(name)
    rag_block = "\n".join(f"[RAG] score={h['final_score']:.3f}\n{h['text']}\n---" for h in rag_hits)
    evidence_block = "\n".join(
        f"- ref_id: {e.get('ref_id', '')}\n  type: {e.get('type', '')}\n  source: {e.get('source', '')}\n  sha256: {e.get('sha256', '')}\n  snippet: {e.get('snippet', '')}\n  ---"
        for e in evidences
    )
    return Template(tpl).safe_substitute(event_text=event_text, evidence_block=evidence_block, rag_block=rag_block)

def safe_json_extract(raw: str) -> dict:
    """LLM 응답에서 JSON 부분만 안전하게 추출"""
    try:
        matches = re.findall(r"\{.*\}", raw, re.DOTALL)
        if matches:
            return json.loads(matches[-1])
        return {}
    except Exception:
        return {}

INCIDENTS = {}

@app.post("/analyze")
async def analyze_log(payload: dict):
    """인시던트 로그 분석 API"""
    try:
        incident_id = payload.get("incident_id", "demo")
        event_text = payload.get("event_text", "")
        evidences = payload.get("evidences", [])

        # 1️⃣ 데이터 마스킹
        event_masked, _ = mask_all(event_text)
        masked_evidences = [dict(e, snippet=mask_snippet_evidence(e.get("snippet", ""), mode=e.get("type", "raw"))) for e in evidences]

        # 2️⃣ Evidence 검증
        validate_evidence_refs(masked_evidences)

        # 3️⃣ RAG 검색
        rag_hits = rag.retrieve(event_masked, top_k=5)

        # 4️⃣ 프롬프트 생성
        prompt = build_prompt("summary", event_masked, masked_evidences, rag_hits)
        if not validate_masked(prompt):
            raise HTTPException(422, detail="Prompt contains unmasked sensitive info")

        # 5️⃣ LLM 호출
        try:
            raw_response = await model_gateway.generate(prompt)
            parsed = safe_json_extract(raw_response)
        except Exception as e:
            logger.warning(f"⚠ LLM 호출 실패: {e}")
            parsed = {"summary": "N/A","attack_mapping": ["UNKNOWN"],"recommended_actions": ["조치 불가"],"confidence": 0.0,"hil_required": True,"evidence_refs": []}

        # 6️⃣ EvidenceRef 정보 추가
        parsed["evidence_refs"] = [{k: e.get(k) for k in ["type","ref_id","source","offset","length","sha256","rule_id"]} for e in masked_evidences]

        # 7️⃣ Schema 검증
        if not validate_schema(parsed):
            raise HTTPException(422, detail={"error_code": "SCHEMA_INVALID","message": "LLM output schema mismatch"})

        # 8️⃣ Confidence/HIL 처리
        confidence = parsed.get("confidence", 1.0)
        hil_required = determine_hil_requirement(confidence)
        log_incident_decision(incident_id, confidence, hil_required)

        # 9️⃣ IncidentOutput 저장
        evidence_objs = [EvidenceRef(**e) for e in masked_evidences]
        INCIDENTS[incident_id] = IncidentOutput(
            incident_id=incident_id,
            summary=parsed.get("summary"),
            attack_mapping=parsed.get("attack_mapping", []),
            recommended_actions=parsed.get("recommended_actions", []),
            confidence=confidence,
            hil_required=hil_required,
            evidences=evidence_objs
        )

        return parsed

    except HTTPException as he:
        raise he
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, detail=str(e))

@app.get("/incidents/{id}")
def get_incident(id: str):
    """저장된 인시던트 조회"""
    if id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    return INCIDENTS[id]

@app.post("/incidents/{id}/approve")
def approve_incident(id: str):
    """인시던트 HIL 승인 처리"""
    if id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    INCIDENTS[id].hil_required = False
    return {"incident_id": id, "approved": True}

@app.get("/prompt/{name}")
def get_prompt(name: str):
    """프롬프트 내용 조회"""
    path = Path("llm/prompt_templates") / f"{name}_prompt.txt"
    if not path.exists():
        raise HTTPException(404, detail="Prompt not found")
    return {"prompt_name": name, "content": path.read_text(encoding="utf-8")}
