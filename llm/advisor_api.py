# llm/advisor_api.py
from fastapi import FastAPI, HTTPException
import json, jsonschema, asyncio, re, logging
from pathlib import Path
import os
import traceback
from string import Template

# -------------------------
# 내부 모듈 import
# -------------------------
from llm.models import EvidenceRef, IncidentOutput
from llm.prompt_manager import PromptManager
from llm.masking.data_masking import mask_all, validate_masked
from llm.model_gateway import ModelGateway
from llm.local_llm_PoC import DummyLocalLLM
from llm.utils.llm_response_handler import (
    evaluate_confidence,
    determine_hil_requirement,
    log_incident_decision,
)

# -------------------------
# FastAPI 앱 초기화
# -------------------------
app = FastAPI(title="Incident Advisor API (Step1~3 통합)")

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# -------------------------
# 프롬프트 매니저 & 모델 게이트웨이 초기화
# -------------------------
prompt_manager = PromptManager(base_path="llm/prompt_templates")

LLM_MODE = os.getenv("LLM_MODE", "local").lower()
if LLM_MODE == "gateway":
    model_gateway = ModelGateway(local_model_path="models/ggml.bin")
else:
    model_gateway = DummyLocalLLM()

logger.info(f"✅ LLM Engine Loaded: {model_gateway.__class__.__name__}")

# -------------------------
# JSON 스키마 로드
# -------------------------
BASE_DIR = Path(__file__).resolve().parent
POSSIBLE_PATHS = [
    BASE_DIR / "output_schema.json",
    BASE_DIR.parent / "llm" / "output_schema.json",
]
for p in POSSIBLE_PATHS:
    if p.exists():
        SCHEMA_PATH = p
        break
else:
    raise FileNotFoundError("❌ output_schema.json 파일을 찾을 수 없습니다.")

with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
    OUTPUT_SCHEMA = json.load(f)

def validate_schema(data: dict) -> bool:
    try:
        jsonschema.validate(instance=data, schema=OUTPUT_SCHEMA)
        return True
    except jsonschema.ValidationError:
        return False

# -------------------------
# 증거 유효성 검사
# -------------------------
def validate_evidence_refs(evidences: list):
    allowed_types = {"raw", "yara", "hex", "webhook"}
    for e in evidences:
        if e.get("type") not in allowed_types:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "EVIDENCE_INVALID", "message": f"Invalid type: {e.get('type')}"}
            )
        for f in ["ref_id", "source", "offset", "length", "sha256"]:
            if f not in e:
                raise HTTPException(
                    status_code=422,
                    detail={"error_code": "EVIDENCE_INVALID", "message": f"Missing field: {f}"}
                )
        if not isinstance(e["offset"], int) or not isinstance(e["length"], int):
            raise HTTPException(
                status_code=422,
                detail={"error_code": "EVIDENCE_INVALID", "message": "offset/length must be integer"}
            )
        if not re.fullmatch(r"[0-9a-fA-F]{6,64}", e["sha256"]):
            raise HTTPException(
                status_code=422,
                detail={"error_code": "EVIDENCE_INVALID", "message": "Invalid sha256 format"}
            )

# -------------------------
# 프롬프트 빌드
# -------------------------
def build_prompt(name: str, event_text: str, evidences: list, extra=None):
    """
    summary_prompt.txt의 placeholder 구조에 맞게 프롬프트 생성
    {event_text}, {evidence_block} 두 필드만 사용
    """
    tpl = prompt_manager.load_prompt(name)

    # evidence_block 구성
    evidence_block = "\n".join(
        f"- ref_id: {e.get('ref_id', '')}\n"
        f"  type: {e.get('type', '')}\n"
        f"  source: {e.get('source', '')}\n"
        f"  sha256: {e.get('sha256', '')}\n"
        f"  snippet: {e.get('snippet', '')}\n"
        f"  ---"
        for e in evidences
    )

    # Template.safe_substitute() 사용으로 중괄호 이슈 방지
    try:
        template = Template(tpl)
        return template.safe_substitute(event_text=event_text, evidence_block=evidence_block)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Prompt formatting failed: {str(e)}"
        )
# -------------------------
# 인시던트 저장소 (임시 메모리)
# -------------------------
INCIDENTS = {}

# -------------------------
# /analyze 엔드포인트
# -------------------------
@app.post("/analyze")
async def analyze_log(payload: dict):
    try:
        incident_id = payload.get("incident_id", "demo")
        event_text = payload.get("event_text", "")
        evidences = payload.get("evidences", [])

        # 1️⃣ 데이터 마스킹
        event_masked, _ = mask_all(event_text)
        masked_evidences = []
        for e in evidences:
            s = e.get("snippet", "")
            masked_snippet, _ = mask_all(s)
            e_copy = dict(e)
            e_copy["snippet"] = masked_snippet
            masked_evidences.append(e_copy)

        # 2️⃣ 증거 유효성 검사
        validate_evidence_refs(masked_evidences)

        # 3️⃣ 프롬프트 생성
        prompt = build_prompt("summary", event_masked, masked_evidences)

        # 3.1️⃣ 프롬프트 마스킹 검증
        if not validate_masked(prompt):
            raise HTTPException(status_code=422, detail="Prompt contains unmasked sensitive info")

        # 4️⃣ LLM 호출
        try:
            if LLM_MODE == "gateway":
                raw_response = await model_gateway.generate(prompt)
            else:
                # DummyLocalLLM는 동기 함수
                raw_response = await model_gateway.generate(prompt)
        except Exception as e:
            logger.warning(f"⚠️ Local LLM 실패: {e} → Gateway로 재시도")
            gw = ModelGateway(local_model_path="models/ggml.bin")
            raw_response = await gw.generate(prompt)

        parsed = json.loads(raw_response)

        # 5️⃣ 스키마 검증
        if not validate_schema(parsed):
            raise HTTPException(status_code=422, detail={"error_code": "SCHEMA_INVALID", "message": "LLM output schema mismatch"})

        # 6️⃣ 신뢰도 평가 및 HIL 판단
        confidence = evaluate_confidence(parsed)
        hil_required = determine_hil_requirement(confidence)
        log_incident_decision(incident_id, confidence, hil_required)

        # 7️⃣ EvidenceRef 객체 변환
        evidence_objs = [EvidenceRef(**e) for e in masked_evidences]

        # 8️⃣ IncidentOutput 생성 및 저장
        incident = IncidentOutput(
            incident_id=incident_id,
            summary=parsed.get("summary", "N/A"),
            attack_mapping=parsed.get("attack_mapping", []),
            recommended_actions=parsed.get("recommended_actions", []),
            confidence=confidence,
            hil_required=hil_required,
            evidences=evidence_objs
        )
        INCIDENTS[incident_id] = incident

        next_action = "complete" if not hil_required else "add_evidence"
        return {"incident_id": incident_id, "status": "analyzed", "next_action": next_action,
                "confidence": confidence, "hil_required": hil_required}

    except HTTPException as he:
        raise he
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------
# 부가 엔드포인트
# -------------------------
@app.get("/incidents/{id}")
def get_incident(id: str):
    if id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    return INCIDENTS[id]

@app.post("/incidents/{id}/approve")
def approve_incident(id: str):
    if id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")
    INCIDENTS[id].hil_required = False
    return {"incident_id": id, "approved": True}

@app.get("/prompt/{name}")
def get_prompt(name: str):
    path = Path("llm/prompt_templates") / f"{name}_prompt.txt"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Prompt not found")
    return {"prompt_name": name, "content": path.read_text(encoding="utf-8")}
