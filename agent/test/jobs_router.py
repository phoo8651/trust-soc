# -*- coding: utf-8 -*-
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, List, Dict

router = APIRouter(prefix="/agent", tags=["jobs"])

class JobDTO(BaseModel):
    job_id: str
    type: str
    args: Dict[str, str] = {}
    issued_at: Optional[str] = None
    signature: Optional[str] = None

@router.get("/jobs/pull", response_model=List[JobDTO])
async def pull_jobs(client_id: str, host: Optional[str] = None, max_jobs: int = 1):
    # 임시: 빈 목록(서버 준비 전)
    return []

class JobResult(BaseModel):
    job_id: str
    status: str  # SUCCESS|FAILED|TIMEOUT
    stdout: Optional[str] = None
    stderr: Optional[str] = None

@router.post("/jobs/result")
async def post_job_result(result: JobResult):
    return {"ok": True}
