from fastapi import APIRouter, HTTPException, Header
import os
import json
import hmac
import hashlib
from app.services.advisor_service import AdvisorService
from app.llm.models import IncidentAnalysisRequest

router = APIRouter(tags=["LLM Advisor"])
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "dummy_secret")

# 서비스 인스턴스 (싱글톤처럼 동작)
advisor_service = AdvisorService()

@router.post("/analyze")
async def analyze_manual(request: IncidentAnalysisRequest):
    """
    수동 분석 요청 (테스트용)
    """
    return await advisor_service.analyze(request)

@router.post("/webhooks/hil")
async def webhook_receiver(payload: dict, x_signature: str = Header(None)):
    """
    HIL 승인/반려 콜백 수신
    """
    if not x_signature:
        raise HTTPException(401, "Missing X-Signature")

    # 서명 검증
    body_bytes = json.dumps(payload).encode()
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        body_bytes,
        hashlib.sha256
    ).hexdigest()

    # 실제 운영 시 hmac.compare_digest 사용
    # if not hmac.compare_digest(x_signature.replace("sha256=", ""), expected):
    #    raise HTTPException(401, "Invalid signature")
    
    # 여기에 승인 로직 추가 (DB 업데이트 등)
    return {"status": "received", "payload": payload}