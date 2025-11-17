"""
Incident Advisor API
- LLM 기반 보안 이벤트 분석
- Evidence 검증 + 마스킹
- RAG(Knowledge Base) 자동 로딩
- 모델 게이트웨이 기반 LLM 호출 (fallback 포함)
- HIL(Webhook) 처리 + Idempotency
"""

from fastapi import FastAPI, HTTPException, Header
import json, jsonschema, asyncio, re, logging, traceback, time, hmac, hashlib, uuid
from pathlib import Path
import os
from string import Template
import httpx

# -------------------------
# ATT&CK 매핑 모듈
# -------------------------
from llm.attack_mapper import AttackMapper

# -------------------------
# 내부 모듈
# -------------------------
from llm.models import EvidenceRef, IncidentOutput
from llm.prompt_manager import PromptManager
from llm.masking.data_masking import mask_all  # validate_masked 는 사용 안 함
from llm.model_gateway import ModelGateway
from llm.rag.rag_engine import RAGEngine
from llm.utils.llm_response_handler import (
    determine_hil_requirement,
    log_incident_decision,
)

# -------------------------
# FastAPI 초기화
# -------------------------
app = FastAPI(title="Incident Advisor API")
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ============================================================
#  전역 엔진/매퍼/프롬프트 초기화
# ============================================================
rag = RAGEngine()
attack_mapper = AttackMapper()

prompt_manager = PromptManager(
    base_path=str(Path(__file__).resolve().parent / "prompt_templates")
)

# ============================================================
#  LLM Model Gateway 초기화 (local / external 자동 구분)
# ============================================================
LLM_MODE = os.getenv("LLM_MODE", "local").lower()

if LLM_MODE == "gateway":
    model_gateway = ModelGateway(
        local_model_path=os.path.join(
            "llm", "models", "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
        ),
        use_real_llm=True,
        enable_fallback=True,
        monitoring_enabled=True,
    )
else:
    # 기본: 로컬 모델 사용
    model_gateway = ModelGateway(
        local_model_path=os.path.join(
            "llm", "models", "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
        ),
        use_real_llm=True,
        monitoring_enabled=True,
    )

logger.info(f"✅ LLM Engine Loaded: {model_gateway.__class__.__name__}")

# ============================================================
#  RAG: Knowledge Base 문서 자동 로딩
# ============================================================
@app.on_event("startup")
async def load_rag_documents():
    """
    서버 시작 시 RAG Knowledge Base 자동 인덱싱
    llm/rag/knowledge_base/*.md 모든 문서 인덱싱
    """
    kb_dir = Path(__file__).resolve().parent / "rag" / "knowledge_base"

    if not kb_dir.exists():
        logger.warning(f"[RAG] knowledge_base 디렉토리가 없습니다: {kb_dir}")
        return

    logger.info(f"[RAG] knowledge_base 문서 로딩 시작: {kb_dir}")

    for file in kb_dir.glob("*.md"):
        try:
            text = file.read_text(encoding="utf-8")
            rag.index_documents(doc_id=file.stem, text=text)
            logger.info(f"[RAG] Loaded: {file.name}")
        except Exception as e:
            logger.error(f"[RAG] {file.name} 로딩 실패: {e}")

    logger.info("✅ [RAG] Knowledge Base 인덱싱 완료.")


# ============================================================
#  JSON Schema 로드
# ============================================================
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

# ============================================================
#  Idempotency 저장소 (메모리)
# ============================================================
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "dummy_secret")
IDEMPOTENCY_DB = {}
INCIDENTS: dict[str, IncidentOutput] = {}  # IncidentOutput 저장소


# ============================================================
#  Schema 검증 (현재는 summary_prompt 전용 스키마가 아니라, 기본 검증용)
# ============================================================
def validate_schema(data: dict) -> bool:
    """
    LLM 출력이 output_schema.json 을 만족하는지 검증
    (현재는 필요 시 수동으로 사용할 수 있음)
    """
    try:
        jsonschema.validate(instance=data, schema=OUTPUT_SCHEMA)
        return True
    except jsonschema.ValidationError as e:
        logger.warning(f"[SCHEMA] validation error: {e}")
        return False


# ============================================================
#  Evidence 검증
# ============================================================
def validate_evidence_refs(evidences: list):
    """
    Evidence 형식 검증
    - type, 필수 필드, 정수 타입, sha256 형식 체크
    """
    allowed_types = {"raw", "yara", "hex", "webhook"}

    for e in evidences:
        if e.get("type") not in allowed_types:
            raise HTTPException(
                422,
                detail={
                    "error_code": "EVIDENCE_INVALID",
                    "message": f"Invalid type: {e.get('type')}",
                },
            )

        required = ["ref_id", "source", "offset", "length", "sha256"]
        for f in required:
            if f not in e:
                raise HTTPException(
                    422,
                    detail={
                        "error_code": "EVIDENCE_INVALID",
                        "message": f"Missing field: {f}",
                    },
                )

        if not isinstance(e["offset"], int) or not isinstance(e["length"], int):
            raise HTTPException(422, detail="offset/length must be integer")

        if not re.fullmatch(r"[0-9a-fA-F]{6,64}", e["sha256"]):
            raise HTTPException(422, detail="sha256 must be hex format")


# ============================================================
#  Prompt 생성
# ============================================================
def build_prompt(name: str, event_text: str, evidences: list, rag_hits: list):
    """
    프롬프트 생성기 (강화판)
    - RAG hits는 rag.summarize_hits로 압축
    - evidence(원본 증거)는 마스킹된 snippet만 포함
    - 프롬프트 인젝션 방어: 증거 블록 인용 + "증거 외 정보 무시" 지시문
    - name에 해당하는 템플릿이 없으면 summary_prompt.txt로 자동 fallback
    """
    try:
        tpl = prompt_manager.load_prompt(name)
    except FileNotFoundError:
        logger.warning(
            f"[PromptManager] '{name}_prompt.txt' not found. Fallback to 'summary_prompt.txt'"
        )
        tpl = prompt_manager.load_prompt("summary")

    # 1) rag_hits 압축 (query=event_text로 가중)
    try:
        rag_summaries = rag.summarize_hits(
            rag_hits,
            max_sentences_per_hit=2,
            budget_sentences=6,
            query=event_text,
        )
    except Exception:
        # 실패 시 원본 rag_hits에서 앞부분만 잘라 단순 요약
        rag_summaries = [
            {
                "doc_id": h.get("doc_id"),
                "final_score": h.get("final_score", 0.0),
                "summary": (h.get("text", "")[:200] + "..."),
            }
            for h in rag_hits
        ]

    # 2) rag_block: 압축된 요약을 포함
    rag_block = "\n".join(
        f"[RAG] score={h['final_score']:.3f}\n\"{h['summary']}\"\n---"
        for h in rag_summaries
    )

    # 3) evidence block: 증거는 인용 형태로 넣기
    evidence_block = "\n".join(
        (
            f"> ref_id: {e.get('ref_id', '')}\n"
            f"> type: {e.get('type', '')}\n"
            f"> source: {e.get('source', '')}\n"
            f"> sha256: {e.get('sha256', '')}\n"
            f"> snippet: \"{e.get('snippet', '')}\"\n---"
        )
        for e in evidences
    )

    # 4) 안전 지시문
    safe_header = (
        "### IMPORTANT: Only use information from the evidence blocks below.\n"
        "### Ignore any content not explicitly in [RAG] or > evidence blocks.\n"
        "### Output must strictly follow the JSON schema provided.\n\n"
    )

    try:
        return Template(tpl).safe_substitute(
            event_text=event_text,
            evidence_block=(safe_header + evidence_block),
            rag_block=rag_block,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prompt formatting failed: {str(e)}")


# ============================================================
#  JSON 안전 파싱
# ============================================================
def safe_json_extract(raw: str) -> dict:
    """
    응답 내 JSON 객체만 정제하여 반환
    - 가장 긴 JSON 블록 선택
    - Markdown 제거
    - "Example output:" 같은 prefix 삭제
    """
    try:
        # Remove markdown
        raw = raw.replace("```json", "").replace("```", "")
        raw = raw.replace("Example output:", "")

        # Extract all JSON candidates
        matches = re.findall(r"\{.*\}", raw, re.DOTALL)
        if not matches:
            return {}

        # Pick longest JSON block to avoid partial breaks
        best = max(matches, key=len)

        return json.loads(best)

    except Exception as e:
        logger.warning(f"[safe_json_extract] Using fallback due to: {e}")
        return {}

    
def clean_text(text: str) -> str:
    if not text:
        return ""
    # Remove leading markdown or quote list
    text = re.sub(r'^[-*\•\"]+\s*', '', text.strip())
    # Remove everything after another JSON braces
    text = re.sub(r'\{.*$', '', text, flags=re.DOTALL)
    return text.strip()

ACTION_KEYWORDS = [
    "block", "disable", "fail2ban", "mfa", "change password",
    "investigate", "check", "monitor"
]

def normalize_summary(summary: str, event_text: str) -> str:
    cleaned = clean_text(summary).lower()

    # If LLM generates actions instead of a summary => fallback
    if any(k in cleaned for k in ACTION_KEYWORDS):
        cleaned = ""

    # If summary is invalid or missing => fallback to event
    if not cleaned or cleaned in ("unknown", "모른다"):
        cleaned = event_text[:80] + ("..." if len(event_text) > 80 else "")

    # Restore capitalization
    return cleaned[0].upper() + cleaned[1:] if cleaned else ""



# ============================================================
#  Webhook 요청
# ============================================================
async def send_webhook_request(url: str, body: bytes, signature: str):
    """
    Webhook 재시도(지수 백오프) 포함
    - 3초 타임아웃
    - 최대 3회 재시도 (0.2s → 0.4s → 0.8s)
    """
    async with httpx.AsyncClient(timeout=3.0) as client:
        for attempt in range(3):
            try:
                start = time.time()
                resp = await client.post(
                    url, content=body, headers={"X-Signature": f"sha256={signature}"}
                )
                logger.info(
                    f"[Webhook attempt={attempt+1}] {resp.status_code}, "
                    f"t={time.time()-start:.3f}s"
                )

                if resp.status_code == 200:
                    return True

            except Exception as e:
                logger.warning(f"[Webhook attempt {attempt+1}] failed: {e}")

            await asyncio.sleep(0.2 * (2 ** attempt))  # 0.2 → 0.4 → 0.8

    return False


# ============================================================
#  /analyze (메인 분석 엔드포인트)
# ============================================================
@app.post("/analyze")
async def analyze_log(payload: dict):
    """
    탐지 이벤트 분석 메인 엔드포인트
    - 마스킹 → RAG → AttackMapper → LLM 3-step(summary / mapping / actions)
    - Rule 기반 ATT&CK 매핑을 우선 적용 (LLM은 보조)
    - recommended_actions / evidence_refs 최소 1개 보장
    """
    try:
        # ---------------------------
        # 0. 입력 검증
        # ---------------------------
        if "event_text" not in payload:
            raise HTTPException(422, "event_text must be provided")
        if not isinstance(payload["event_text"], str):
            raise HTTPException(422, "event_text must be a string")

        incident_id = payload.get("incident_id", str(uuid.uuid4()))
        event_text = payload["event_text"]
        evidences = payload.get("evidences", [])

        # ---------------------------
        # 1. 마스킹
        # ---------------------------
        event_masked, _ = mask_all(event_text)

        # Evidence 마스킹 + snippet 강제 문자열화
        masked_evidences = [
            {
                **e,
                "snippet": str(e.get("snippet", "")),
            }
            for e in evidences
        ]

        # Evidence가 하나도 없으면 기본 raw evidence 생성
        if not masked_evidences:
            masked_evidences.append(
                {
                    "type": "raw",
                    "ref_id": incident_id,
                    "source": "event_text",
                    "offset": 0,
                    "length": len(event_masked),
                    "sha256": "deadbeef",  # TODO: 실제 SHA256 계산 로직으로 교체 가능
                    "snippet": event_masked[:80] + ("..." if len(event_masked) > 80 else ""),
                }
            )

        # Evidence 형식 검증
        validate_evidence_refs(masked_evidences)

        # ---------------------------
        # 2. RAG 검색 (실패해도 치명적이지 않음)
        # ---------------------------
        try:
            rag_hits = rag.retrieve(event_masked, top_k=5)
        except Exception as e:
            logger.warning(f"[RAG] retrieve failed: {e}")
            rag_hits = []

        # ---------------------------
        # 3. AttackMapper 선 매핑 (Rule 기반)
        # ---------------------------
        mapped_results = attack_mapper.map(event_masked, masked_evidences)

        # ATT&CK 매핑 후 중복 제거 및 가장 구체적 기술 우선
        if mapped_results:
        # confidence 높은 순 정렬
            mapped_results.sort(key=lambda x: x["confidence"], reverse=True)

            # 상위 기술(T1110) 제거 → 하위 기술(T1110.001)만 남기기
            selected = []
            seen_prefix = set()
            for item in mapped_results:
                ttp = item["id"] if "id" in item else item.get("ttp_id")
                prefix = ttp.split(".")[0]
                if prefix not in seen_prefix:
                    selected.append(item)
                    seen_prefix.add(prefix)
    
            attack_mapping = [item.get("id") or item.get("ttp_id") for item in selected]
            mapping_confidence = selected[0].get("confidence", 0.6)
        else:
            attack_mapping = ["UNKNOWN"]
            mapping_confidence = 0.4

        # ---------------------------
        # 4. LLM 3-step 호출
        # ---------------------------
        # 4-1) Summary (LLM JSON 파싱 → 정리)
        # ---------------------------
        summary_prompt = build_prompt("summary", event_masked, masked_evidences, rag_hits)
        summary_raw = await model_gateway.generate(summary_prompt)
        summary_json = safe_json_extract(summary_raw) or {}

        raw_summary = summary_json.get("summary", "")

        # summary 내용 정리
        summary = clean_text(raw_summary)

        # summary에 action 성향 키워드가 들어가면 fallback 처리
        if any(k in summary.lower() for k in ACTION_KEYWORDS):
            summary = ""

        # summary가 너무 짧거나 미Valid하면 event 기반 조정
        if not summary or summary.lower() in ("unknown", "모른다"):
            summary = event_masked[:80] + ("..." if len(event_masked) > 80 else "")

        # 최종 마무리 정규화
        summary = summary.strip()
        summary = re.sub(r"\s+", " ", summary)
        summary = summary[0].upper() + summary[1:] if summary else "Unknown event"

        # ---------------------------
        #    4-2) ATT&CK 매핑 (LLM 보조)
        # ---------------------------
        attack_prompt = build_prompt("attack_mapping", event_masked, masked_evidences, rag_hits)
        attack_raw = await model_gateway.generate(attack_prompt)
        attack_json = safe_json_extract(attack_raw)

        llm_attack_ids = []
        if isinstance(attack_json, list):
            for item in attack_json:
                if isinstance(item, dict):
                    tid = item.get("technique_id") or item.get("id")
                    if tid:
                        llm_attack_ids.append(tid)

        if not llm_attack_ids:
            llm_attack_ids = ["UNKNOWN"]

        

        # ---------------------------
        #    4-3) 대응 조치 생성
        # ---------------------------
        actions_prompt = build_prompt(
            "response_guide",
            event_masked,
            masked_evidences,
            rag_hits,
        )

        # 템플릿 내 attack_mapping_json 플레이스홀더 치환
        actions_prompt = (
            actions_prompt
            .replace("${attack_mapping_json}", json.dumps(attack_mapping))
            .replace("{attack_mapping_json}", json.dumps(attack_mapping))
        )

        actions_raw = await model_gateway.generate(actions_prompt)
        actions_json = safe_json_extract(actions_raw) or {}

        recommended_actions: list[str] = []

        # response_guide_prompt 형식 (object 리스트) → 문자열 리스트로 변환
        if isinstance(actions_json, dict) and isinstance(actions_json.get("recommended_actions"), list):
            for item in actions_json["recommended_actions"]:
                if isinstance(item, dict):
                    act = item.get("action")
                    if act:
                        recommended_actions.append(str(act).strip())
                elif isinstance(item, str):
                    recommended_actions.append(item.strip())

        # summary_prompt 에서 recommended_actions 가 나왔을 수도 있음
        if not recommended_actions and isinstance(summary_json.get("recommended_actions"), list):
            for item in summary_json["recommended_actions"]:
                if isinstance(item, str) and item.strip():
                    recommended_actions.append(item.strip())

        # 마지막 fallback
        if not recommended_actions:
            recommended_actions = ["추가 로그 수집 및 관리자 검토 필요"]

        # ======================================================
        # 5. 신뢰도 계산 & HIL 결정 (Rule + LLM + RAG)
        # ======================================================

        # 5-1) Rule 기반 신뢰도
        # 가장 구체적 기술일수록 높은 점수
        if attack_mapping != ["UNKNOWN"]:
            if any("." in tid for tid in attack_mapping):  # 하위 기술 존재 (ex. T1110.001)
                rule_confidence = 0.75
            else:  # 상위 기술만 (ex. T1110)
                rule_confidence = 0.60
        else:       
            rule_confidence = 0.40

        # 5-2) LLM Confidence 활용
        try:
            llm_confidence = float(summary_json.get("confidence", 0.5))
        except Exception:
            llm_confidence = 0.5

        # 5-3) RAG 기반 신뢰도 계산
        if rag_hits:
            rag_confidence = max(h.get("final_score", 0.0) for h in rag_hits)
            rag_confidence = min(1.0, rag_confidence) * 0.8  # 과신 방지
        else:
            rag_confidence = 0.0

        # 5-4) 가중합 (Rule + LLM + RAG)
        # 운영에서 가장 믿을 수 있는 Rule 가중을 40%로 설정
        confidence = (
            rule_confidence * 0.4 +
            llm_confidence * 0.4 +
            rag_confidence * 0.2
        )

        confidence = round(min(max(confidence, 0.0), 1.0), 2)

        # 5-5) 최종 HIL 필요 여부 결정
        # 0.7 이상이면 자동 승인, 미만이면 승인 요청
        hil_required = confidence < 0.70
        status = "pending_approval" if hil_required else "approved"


        # ======================================================
        # 6. IncidentOutput 저장 (Pydantic)
        # ======================================================
        evidence_objs = [EvidenceRef(**e) for e in masked_evidences]

        INCIDENTS[incident_id] = IncidentOutput(
            summary=summary,
            attack_mapping=attack_mapping,
            recommended_actions=recommended_actions,
            confidence=confidence,
            hil_required=hil_required,
            evidence_refs=evidence_objs,
            status=status,
        )

        # 의사결정 로그
        log_incident_decision(incident_id, confidence, hil_required)

        # ======================================================
        # 7. 최종 응답
        # ======================================================
        return {
            "incident_id": incident_id,
            "summary": summary,
            "attack_mapping": attack_mapping,
            "recommended_actions": recommended_actions,
            "confidence": confidence,
            "hil_required": hil_required,
            "status": status,
            # API 응답에는 원본 evidences 구조 유지
            "evidence_refs": [
                {
                    "type": e["type"],
                    "ref_id": e["ref_id"],
                    "source": e["source"],
                    "offset": e["offset"],
                    "length": e["length"],
                    "sha256": e["sha256"],
                }
                for e in masked_evidences
            ],
        }

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, str(e))


# ============================================================
#  /webhooks/hil (HIL Webhook 엔드포인트)
# ============================================================
@app.post("/webhooks/hil")
async def send_hil_webhook(payload: dict, idempotency_key: str = Header(None)):
    """
    HIL Required 발생 시 외부 시스템으로 Webhook 전송
    - Idempotency-Key 기반 중복 방지
    - HMAC SHA256 서명 포함
    - 재시도(3회)
    """
    url = payload.get("callback_url")
    if not url:
        raise HTTPException(422, "Missing callback_url")
    if not idempotency_key:
        raise HTTPException(422, "Missing Idempotency-Key header")

    # 중복 요청 방지
    if idempotency_key in IDEMPOTENCY_DB:
        return {"status": "duplicate", "incident_id": IDEMPOTENCY_DB[idempotency_key]}

    body = json.dumps(payload).encode()
    signature = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()

    success = await send_webhook_request(url, body, signature)
    if not success:
        raise HTTPException(503, "Webhook send failed after retries")

    incident_id = payload.get("incident_id", str(uuid.uuid4()))
    IDEMPOTENCY_DB[idempotency_key] = incident_id

    return {"status": "sent", "incident_id": incident_id}


# ============================================================
#  Incident 조회 API
# ============================================================
@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """
    Incident 분석 결과 조회 API
    - IncidentOutput(Pydantic) 내용을 그대로 반환
    """
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")

    return INCIDENTS[incident_id].dict()


# ============================================================
#  Incident 승인 API (HIL 처리)
# ============================================================
@app.post("/incidents/{incident_id}/approve")
async def approve_incident(incident_id: str):
    """
    Incident 승인 API
    - hil_required 플래그를 False 로 전환
    - status="approved" 로 응답
    """
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")

    incident = INCIDENTS[incident_id]
    incident.hil_required = False

    if hasattr(incident, "status"):
        incident.status = "approved"
        status_value = incident.status
    else:
        status_value = "approved"

    return {
        "incident_id": incident_id,
        "status": status_value,
        "summary": incident.summary,
        "confidence": incident.confidence,
    }


@app.post("/incidents/{incident_id}/reject")
async def reject_incident(incident_id: str):
    """
    Incident 반려 API
    - hil_required 플래그를 True 로 유지/전환
    - status="rejected" 로 응답
    """
    if incident_id not in INCIDENTS:
        raise HTTPException(404, "Incident not found")

    incident = INCIDENTS[incident_id]
    incident.hil_required = True

    if hasattr(incident, "status"):
        incident.status = "rejected"
        status_value = incident.status
    else:
        status_value = "rejected"

    return {
        "incident_id": incident_id,
        "status": status_value,
        "summary": incident.summary,
        "confidence": incident.confidence,
    }
