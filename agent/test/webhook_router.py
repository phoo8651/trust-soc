# -*- coding: utf-8 -*-
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict

router = APIRouter(prefix="/webhook", tags=["webhook"])

class WebhookMsg(BaseModel):
    channel: str = "dev"
    title: str
    body: str
    extra: Dict[str, str] = {}
    incident_id: Optional[str] = None

@router.post("/send")
async def send_webhook(msg: WebhookMsg):
    # TODO: Slack/Discord 연동은 추후. 지금은 에코 응답.
    return {"ok": True, "echo": msg.dict()}
