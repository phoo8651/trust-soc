from fastapi import APIRouter, Depends, Request, Header
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.controllers.ingest_controller import IngestController

router = APIRouter()

@router.post("/ingest/logs", status_code=202)
async def ingest_logs(
    request: Request,
    db: Session = Depends(get_db),
    # Swagger Headers
    authorization: str = Header(..., alias="Authorization"),
    idem_key: str = Header(..., alias="X-Idempotency-Key"),
    req_ts: str = Header(..., alias="X-Request-Timestamp"),
    payload_hash: str = Header(..., alias="X-Payload-Hash"),
):
    body = await request.body()
    ctrl = IngestController(db)
    return await ctrl.handle_request(body, request.headers)