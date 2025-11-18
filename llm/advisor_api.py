#llm/advisor_api.py
"""
Incident Advisor API
- LLM 기반 보안 이벤트 분석
- Evidence 검증 + 마스킹
- RAG(Knowledge Base) 자동 로딩
- 모델 게이트웨이 기반 LLM 호출 (fallback 포함)
- HIL(Webhook) 처리 + Idempotency
"""
from fastapi.middleware.cors import CORSMiddleware
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 개발 단계: 모두 허용 (운영 시 제한 필요)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
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

# pytest 환경에서는 무조건 dummy 모델 사용
if "PYTEST_CURRENT_TEST" in os.environ:
    logger.info("🧪 Pytest 환경 감지 → Dummy LLM 사용")
    model_gateway = ModelGateway(
        local_model_path=None,
        use_real_llm=False,
        monitoring_enabled=False,
    )

elif LLM_MODE == "gateway":
    model_gateway = ModelGateway(
        local_model_path=os.path.join(
            "llm", "models", "mistral-7b-instruct-v0.2.Q4_K_M.gguf"
        ),
        use_real_llm=True,
        enable_fallback=True,
        monitoring_enabled=True,
        timeout=60,
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
            max_sentences_per_hit=1,
            budget_sentences=3,
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
    "investigate", "block", "disable", "mfa",
    "change password", "change ssh", "reset ssh",
    "reset password", "update credentials",
    "secure access", "harden"
]

def normalize_summary(summary: str, event_masked: str) -> str:
    cleaned = clean_text(summary)
    lower = cleaned.lower()


    action_patterns = [
        r"(change|reset).*(password|key)",
        r"disable.*(password|auth)",
        r"(enable|set up).*mfa",
        r"(block|deny).*ip",
        r"investigate",
        r"review",
        r"check",
        r"monitor"
    ]
    
    # LLM이 조치 문장으로 판단될 경우 → summary 취소
    if any(k in lower for k in ACTION_KEYWORDS):
        cleaned = ""
    cleaned = cleaned.strip("\"' ")
    cleaned = cleaned.rstrip(".")
    
    # summary가 없거나 "모른다"거나 "unknown"이면
    if not cleaned or lower in ("unknown", "모른다"):
        cleaned = event_masked[:80] + "..."

    # 첫 글자 대문자 처리
    return cleaned[0].upper() + cleaned[1:] if cleaned else "Unknown event"




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
    try:
        # ---------------------------
        # 0. 입력 검증
        # ---------------------------
        if "event_text" not in payload:
            raise HTTPException(422, "event_text must be provided")

        incident_id = payload.get("incident_id", str(uuid.uuid4()))
        event_text = payload["event_text"]
        evidences = payload.get("evidences", [])
        
        if not evidences:
           raise HTTPException(
               422,
               detail={
                   "error_code": "EVIDENCE_REQUIRED",
                   "message": "At least one evidence must be provided"
               }
            )       

        # ---------------------------
        # 1. 마스킹 처리
        # ---------------------------
        event_masked, _ = mask_all(event_text)

        masked_evidences = []
        for e in evidences:
            snippet = e.get("snippet")

            # evidence.data 기반 snippet 자동 추출
            data = e.get("data")
            if not snippet and isinstance(data, str):
               snippet = data[:120]

            # fallback: event_text 일부라도 넣기
            if not snippet:
               snippet = event_masked[:50]
            else:
                snippet = snippet[:50]
            

            masked_evidences.append({**e, "snippet": str(snippet)})

        # ---------------------------
        # ✨ 토큰 폭주 방지: evidence 최대 2~3개 제한
        # ---------------------------
        masked_evidences = masked_evidences[:2]

        # ---------------------------
        # Evidence validation
        # ---------------------------
        validate_evidence_refs(masked_evidences)
        
        # 2-1. YARA/HEX evidence → RAG 인덱싱 (텍스트 기반 요약만 저장)
        for e in masked_evidences:
            if e.get("type") in ("yara", "hex"):
                # snippet이 없으면 event 일부라도 사용
                rag_text = e.get("snippet") or event_masked[:120]
                rag.index_documents(
                    doc_id=e["ref_id"],
                    text=str(rag_text),
                )
        # ---------------------------
        # 2. RAG 검색
        # ---------------------------
        try:
            rag_hits = rag.retrieve(event_masked, top_k=2)
        except:
            rag_hits = []

        # ---------------------------
        # 3. AttackMapper 선 매핑
        # ---------------------------
        mapped_results = attack_mapper.map(event_masked, masked_evidences)

        if mapped_results:
            mapped_results.sort(key=lambda x: x["confidence"], reverse=True)
            best = mapped_results[0]
            attack_mapping = [best.get("id")] if best.get("id") else ["UNKNOWN"]
            mapping_confidence = mapped_results[0].get("confidence", 0.6)
        else:
            attack_mapping = ["UNKNOWN"]
            mapping_confidence = 0.4

        # ======================================================
        # RULE OVERRIDE — SSH Brute Force
        # ======================================================
        ssh_fail_count = len(re.findall(r"failed ssh login", event_masked.lower()))

        if ssh_fail_count >= 3:
            attack_mapping = ["T1110.001"]
            mapping_confidence = 0.95

        # ======================================================
        # FTP → Unknown + Guardrail
        # ======================================================
        if "ftp" in event_masked.lower():
            attack_mapping = ["UNKNOWN"]
            mapping_confidence = 0.2

        # ---------------------------
        # 4. LLM Summary
        # ---------------------------
        summary_prompt = build_prompt("summary", event_masked, masked_evidences, rag_hits)
        raw_summary_response = await model_gateway.generate(summary_prompt)
        summary_json = safe_json_extract(raw_summary_response)
        
        # Missing fields 보정 (LLM JSON 일부만 생성 시)
        summary_json.setdefault("summary", event_masked[:80] + "...")
        summary_json.setdefault("attack_mapping", attack_mapping)
        summary_json.setdefault("recommended_actions", [])
        summary_json.setdefault("confidence", 0.5)
        summary_json.setdefault("evidence_refs", masked_evidences)
        summary_json.setdefault("hil_required", False)

        


        # JSON 파싱 실패 시 필수 스키마 최소값 자동 보정
        if not summary_json or not isinstance(summary_json, dict):
            logger.warning("[Summary] LLM returned invalid JSON. Applying fallback default.")
            summary_json = {
                "summary": event_masked[:80] + "...",
                "attack_mapping": attack_mapping,  # 기존 매퍼 값 반영
                "recommended_actions": ["추가 로그 수집 필요"],
                "confidence": 0.5,
                "evidence_refs": masked_evidences,
                "hil_required": True
            }

        if not validate_schema(summary_json):
           # 1회 재시도
           logger.warning("[SCHEMA] Summary schema mismatch → retry once")
           raw_retry = await model_gateway.generate(summary_prompt)
           summary_json = safe_json_extract(raw_retry)

           if not validate_schema(summary_json):
               raise HTTPException(
                   status_code=422,
                   detail={
                       "error_code": "SCHEMA_VALIDATION_FAILED",
                       "message": "LLM summary schema mismatch twice"
                   }
               )
        
        raw_summary = summary_json.get("summary", "")
        summary = normalize_summary(raw_summary, event_masked)
        logger.info(f"[Summary] raw={raw_summary!r} → normalized={summary!r}")
    

    
        # 🚨 summary에 Action 문구가 남아있을 경우 강제 복구
        lower_summary = summary.lower()
        if any(keyword in lower_summary for keyword in ACTION_KEYWORDS):
            logger.warning("[Guardrail] Summary still contains action → fallback to event_masked")
            summary = event_masked[:80] + "..."

        # 🚫 JSON 문법 잔여 따옴표 제거
        summary = summary.strip().strip("\"'")



        # ---------------------------
        # 5. Recommended Actions
        # ---------------------------
        actions_prompt = build_prompt("response_guide", event_masked, masked_evidences, rag_hits)
        actions_prompt = actions_prompt.replace("${attack_mapping_json}", json.dumps(attack_mapping))
        actions_json = safe_json_extract(await model_gateway.generate(actions_prompt)) or {}
        
        actions = []

        rec_list = actions_json.get("recommended_actions")
        if isinstance(rec_list, list):
            for item in rec_list:
                if isinstance(item, str):
                    actions.append(item.strip())
       
                    
        if not actions:
            actions = ["추가 로그 수집 및 관리자 검토 필요"]
        
        if not isinstance(actions, list):
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "SCHEMA_VALIDATION_FAILED",
                    "message": "recommended_actions must be a list"
                }
            )

        # ======================================================
        # Final Confidence — RULE + LLM + RAG
        # ======================================================
        rule_conf = mapping_confidence
        llm_conf = float(summary_json.get("confidence", 0.5))
        rag_conf = max((h.get("final_score", 0) for h in rag_hits), default=0) * 0.8

        confidence = round(
            rule_conf * 0.7 +
            llm_conf * 0.2 +
            rag_conf * 0.1,
        2)

        # Brute force 확정 시 Confidence 추가 보정
        if attack_mapping == ["T1110.001"]:
            confidence = max(confidence, 0.80)

        # 0.0 ~ 1.0 범위 클램프
        confidence = round(min(max(confidence, 0.0), 1.0), 2)

        # B안 정책: >=0.8 approved, 0.5~0.8 HIL, <0.5 reject
        hil_required = determine_hil_requirement(confidence)

        if not hil_required:
            status = "approved"
            next_action = "monitor"
        elif confidence >= 0.5:
            status = "pending_approval"
            next_action = "wait_approval"
        else:
            status = "rejected"
            next_action = "add_evidence"




        # Guardrail: FTP는 무조건 HIL
        if "ftp" in event_masked.lower():
            confidence = min(confidence, 0.5)
            hil_required = True
            status = "pending_approval"
            next_action = "wait_approval"

        # ======================================================
        # Save + Response
        # ======================================================
        INCIDENTS[incident_id] = IncidentOutput(
            summary=summary,
            attack_mapping=attack_mapping,
            recommended_actions=actions,
            confidence=confidence,
            hil_required=hil_required,
            evidence_refs=[EvidenceRef(**e) for e in masked_evidences],
            status=status,
        )
        
        # ======================================================
        # (선택) HIL 자동 Webhook 호출 – callback_url 이 들어왔을 때만
        # ======================================================
        callback_url = "http://localhost:10555/webhooks/test-receiver"
        
        if hil_required and callback_url:
            try:
                body = {
                    "incident_id": incident_id,
                    "status": status,
                    "summary": summary,
                    "confidence": confidence,
                    "evidence_refs": masked_evidences,
                }
                body_bytes = json.dumps(body).encode()
                signature = hmac.new(
                    WEBHOOK_SECRET.encode(),
                    body_bytes,
                    hashlib.sha256
                ).hexdigest()
                # 외부 수신기는 /webhooks/test-receiver 처럼 X-Signature 헤더 검증
                asyncio.create_task(send_webhook_request(callback_url, body_bytes, signature))
            except Exception as _:
                # Webhook 실패해도 본 API 응답은 그대로 진행
                pass
        # ---------------------------
        # next_action 자동 설정
        # ---------------------------
        if hil_required:
            next_action = "wait_approval"
        else:
            next_action = "monitor"


        return {
            "incident_id": incident_id,
            "summary": summary,
            "attack_mapping": attack_mapping,
            "recommended_actions": actions,
            "confidence": confidence,
            "hil_required": hil_required,
            "status": status,
            "evidence_refs": masked_evidences,
            "next_action": next_action,
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
    HIL Required → 외부 시스템에 Webhook 전송
    - Signature + Timestamp + Idempotency 강화
    """
    url = payload.get("callback_url")
    if not url:
        raise HTTPException(422, "Missing callback_url")

    timestamp = payload.get("timestamp")
    if not timestamp:
        raise HTTPException(401, "Missing timestamp in webhook payload")

    signature_header = payload.get("signature")
    if not signature_header:
        raise HTTPException(401, "Missing signature")

    # Timestamp 5분 이내 검증 (Replay Attack 방지)
    if abs(time.time() - float(timestamp)) > 300:
        raise HTTPException(401, "Signature expired")

    # Idempotency 필수 + DB 조회
    if not idempotency_key:
        raise HTTPException(422, "Missing Idempotency-Key header")

    if idempotency_key in IDEMPOTENCY_DB:
        return {"status": "duplicate", "incident_id": IDEMPOTENCY_DB[idempotency_key]}

    # Payload 전체에 대한 서명 검증
    expected_sig = hmac.new(
        WEBHOOK_SECRET.encode(),
        json.dumps(payload).encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature_header, expected_sig):
        raise HTTPException(401, "Invalid signature hash")

    # 정상 → DB 저장
    incident_id = payload.get("incident_id")
    IDEMPOTENCY_DB[idempotency_key] = incident_id

    return {"status": "accepted", "incident_id": incident_id}

@app.post("/webhooks/test-receiver")
async def webhook_receiver(payload: dict, x_signature: str = Header(None)):
    """
    테스트 Webhook 수신기 (서명 검증 포함)
    Swagger UI에서 분석 후 Webhook 테스트 가능
    """
    if not x_signature:
        raise HTTPException(401, "Missing X-Signature")

    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        json.dumps(payload).encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(x_signature.replace("sha256=", ""), expected):
        raise HTTPException(401, "Invalid signature")

    logger.info(f"[Webhook Receiver] OK payload={payload}")
    return {"status": "ack", "received": payload}

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

@app.get("/healthz")
async def health_check():
    return {"status": "ok"}

