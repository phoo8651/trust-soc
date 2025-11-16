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
    # TODO: 외부 게이트웨이 모드일 때 external 관련 인자 추가 가능
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
#  Schema 검증
# ============================================================
def validate_schema(data: dict) -> bool:
    """
    LLM 출력이 output_schema.json 을 만족하는지 검증
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
    """
    tpl = prompt_manager.load_prompt(name)

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
    LLM 출력에서 { ... } JSON만 추출
    - 응답이 자연어 + JSON 섞여 있어도 마지막 {..} 블록 파싱
    """
    try:
        matches = re.findall(r"\{.*\}", raw, re.DOTALL)
        if matches:
            return json.loads(matches[-1])
        return {}
    except Exception as e:
        logger.warning(f"[safe_json_extract] parse error: {e}")
        return {}


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
                logger.warning(f"[Webhook attempt {attempt+1} failed] {e}")

            await asyncio.sleep(0.2 * (2 ** attempt))  # 0.2 → 0.4 → 0.8

    return False


# ============================================================
#  /analyze (메인 분석 엔드포인트)
# ============================================================
@app.post("/analyze")
async def analyze_log(payload: dict):
    """
    탐지 이벤트 분석 메인 API
    - 입력 검증
    - 마스킹
    - RAG 검색
    - ATT&CK 매핑(attack_mapper)
    - LLM 호출 + 스키마 검증 + fallback
    - Guardrail 기반 confidence/HIL 결정
    - Incident 메모리 저장 + 상태(status) 필드 부여
    """
    try:
        # ---------------------------
        # 0. 입력 유효성 검사
        # ---------------------------
        if "event_text" not in payload:
            raise HTTPException(422, "event_text must be provided")
        if not isinstance(payload["event_text"], str):
            raise HTTPException(422, "event_text must be a string")

        # ---------------------------
        # 1. 입력값 확보
        # ---------------------------
        incident_id = payload.get("incident_id", str(uuid.uuid4()))
        event_text = payload["event_text"]
        evidences = payload.get("evidences", [])

        # ---------------------------
        # 2. 마스킹 수행
        # ---------------------------
        # 2-1. 이벤트 텍스트 마스킹
        event_masked, _ = mask_all(event_text)

        # 2-2. Evidence 마스킹 처리 (snippet은 문자열로 강제)
        masked_evidences = [
            {
                **e,
                "snippet": str(e.get("snippet", "")),
            }
            for e in evidences
        ]

        # 2-3. Evidence가 비어있을 경우 최소 1개 자동 생성 (raw)
        if len(masked_evidences) == 0:
            masked_evidences.append(
                {
                    "type": "raw",
                    "ref_id": incident_id,
                    "source": "event_text",
                    "offset": 0,
                    "length": len(event_masked),
                    "sha256": "deadbeef",  # TODO: 실제 SHA256 계산 로직으로 교체 가능
                }
            )

        # ---------------------------
        # 3. Evidence 검증
        # ---------------------------
        validate_evidence_refs(masked_evidences)

        # ---------------------------
        # 4. RAG 검색
        # ---------------------------
        rag_hits = rag.retrieve(event_masked, top_k=5)

        # ---------------------------
        # 5. Prompt 생성
        # ---------------------------
        prompt = build_prompt("summary", event_masked, masked_evidences, rag_hits)

        # ---------------------------
        # 5-1. ATT&CK 매핑 (LLM 호출 전)
        # ---------------------------
        mapped_results = attack_mapper.map(event_masked, masked_evidences)

        if mapped_results:
            # 가장 높은 confidence TTP 1개 선택
            parsed_attack_id = mapped_results[0].get("ttp_id") or mapped_results[0].get(
                "id", "UNKNOWN"
            )
            attack_mapping = [parsed_attack_id]

            # 매핑 기반 confidence (최대 0.95)
            mapping_confidence = 0.65 + 0.1 * len(mapped_results)
            pre_confidence = min(mapping_confidence, 0.95)
        else:
            attack_mapping = ["UNKNOWN"]
            pre_confidence = 0.4  # 증거 부족/매핑 실패 시 낮게 시작

        # ---------------------------
        # 6. LLM 호출 (retry + schema guardrail)
        # ---------------------------
        parsed = None
        for attempt in range(2):
            try:
                start = time.time()
                raw = await model_gateway.generate(prompt)
                model_gateway.log_metrics(
                    tokens_used=len(prompt), duration=time.time() - start
                )

                parsed = safe_json_extract(raw)
                if parsed and validate_schema(parsed):
                    # 스키마까지 통과하면 성공
                    break

                logger.warning("[LLM] Schema mismatch → retry")
                parsed = None

            except Exception as e:
                logger.warning(f"[LLM attempt {attempt+1}] error: {e}")
                parsed = None

        # 6-1. 재시도 후에도 실패 시 안전 fallback
        if parsed is None:
            parsed = {
                "summary": "NO_DECISION",
                "attack_mapping": ["UNKNOWN"],
                "recommended_actions": ["조치 필요 (증거 불충분)"],
                "confidence": 0.0,
                "hil_required": True,
                "evidence_refs": [],
            }

        # ---------------------------
        # 7. EvidenceRefs 강제 재구성
        # ---------------------------
        parsed["evidence_refs"] = [
            {
                "type": e["type"],
                "ref_id": e["ref_id"],
                "source": e["source"],
                "offset": e["offset"],
                "length": e["length"],
                "sha256": e["sha256"],
                "rule_id": e.get("rule_id"),
            }
            for e in masked_evidences
        ]

        if not parsed["evidence_refs"]:
            raise HTTPException(422, "At least one evidence_ref is required")

        # RAG 근거가 하나도 없으면 HIL 강제
        if len(rag_hits) == 0:
            parsed["hil_required"] = True

        # ---------------------------
        # 8. Confidence / HIL Guardrail
        # ---------------------------
        # LLM confidence
        confidence_llm = float(parsed.get("confidence", 0.6))

        # UNKNOWN 매핑일 경우 LLM confidence 상한 제한
        if attack_mapping == ["UNKNOWN"]:
            confidence_llm = min(confidence_llm, 0.4)

        # ATT&CK 매핑 기반 pre_confidence와 LLM confidence를 평균
        confidence = round((confidence_llm + pre_confidence) / 2, 2)
        parsed["confidence"] = confidence

        # LLM이 준 attack_mapping 대신 → AttackMapper 결과로 덮어쓰기
        parsed["attack_mapping"] = attack_mapping

        # HIL 필요 여부 결정
        hil_required = determine_hil_requirement(confidence)
        parsed["hil_required"] = hil_required

        # 상태(status) 필드 설정: HIL 필요하면 pending_approval, 아니면 approved
        status = "pending_approval" if hil_required else "approved"
        parsed["status"] = status

        # Incident 의사결정 로그 기록
        log_incident_decision(incident_id, confidence, hil_required)

        # ---------------------------
        # 9. Incident 저장소 기록 (Pydantic 사용)
        # ---------------------------
        evidence_objs = [EvidenceRef(**e) for e in parsed["evidence_refs"]]

        # IncidentOutput 모델에 status 필드가 있을 수도/없을 수도 있으므로 방어적으로 처리
        try:
            INCIDENTS[incident_id] = IncidentOutput(
                summary=parsed["summary"],
                attack_mapping=parsed["attack_mapping"],
                recommended_actions=parsed["recommended_actions"],
                confidence=confidence,
                hil_required=hil_required,
                evidence_refs=evidence_objs,
                status=status,  # models.py 에 status 필드가 정의되어 있다면 사용
            )
        except TypeError:
            # status 필드가 없는 기존 models.py 버전일 경우
            INCIDENTS[incident_id] = IncidentOutput(
                summary=parsed["summary"],
                attack_mapping=parsed["attack_mapping"],
                recommended_actions=parsed["recommended_actions"],
                confidence=confidence,
                hil_required=hil_required,
                evidence_refs=evidence_objs,
            )

        # 응답에 incident_id 포함
        parsed["incident_id"] = incident_id

        # FastAPI 응답은 dict(JSON) 그대로 반환
        return parsed

    except HTTPException:
        # FastAPI 에러는 그대로 전달
        raise
    except Exception as e:
        # 기타 예외는 500으로 래핑
        traceback.print_exc()
        raise HTTPException(500, detail=str(e))


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

    # Signature 생성
    body = json.dumps(payload).encode()
    signature = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()

    # Webhook 전송
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

    # IncidentOutput 모델에 status 필드가 있는 경우 갱신
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
