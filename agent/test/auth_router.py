# coding: utf-8
from typing import Optional, Dict, Any
from fastapi import APIRouter
from pydantic import BaseModel

from auth_core import issue_tokens

router = APIRouter(prefix="/auth", tags=["auth"])

class RegisterRequest(BaseModel):
    client_id: str
    host: str
    agent_version: Optional[str] = "0.1.0"
    secret_proof: Optional[str] = None

@router.post("/register")
async def register_agent(req: RegisterRequest) -> Dict[str, Any]:
    # MVP: 검증은 생략하고 토큰만 발급
    subject = f"{req.client_id}:{req.host}"
    tokens = issue_tokens(subject, ttl_minutes=60)
    return {"status": "ok", **tokens}
