from fastapi import (
    APIRouter,
    Request,
    Depends,
    HTTPException,
    Query,
)
from fastapi.templating import Jinja2Templates
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import inspect
from pathlib import Path
import json
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.all_models import (
    Agent,
    Incident,
    RawLog,
    Event,
    Job,
    Policy,
    AuditLog,
    IdempotencyKey,
)
from app.core.pdf_utils import create_incident_pdf

router = APIRouter()

# 템플릿 경로 설정
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# URL 경로용 이름과 실제 모델 클래스 매핑
TABLE_MAP = {
    "agents": Agent,
    "incidents": Incident,
    "raw_logs": RawLog,
    "events": Event,
    "jobs": Job,
    "audit_logs": AuditLog,
    "policies": Policy,
    "idempotency": IdempotencyKey,
}


@router.get("/", include_in_schema=False)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """
    메인 대시보드
    """
    total_agents = db.query(Agent).count()
    total_logs = db.query(RawLog).count()
    total_incidents = db.query(Incident).count()
    pending = db.query(Incident).filter(Incident.status == "pending_approval").count()

    recents = db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()
    jobs = db.query(Job).order_by(Job.created_at.desc()).limit(5).all()

    # 부트스트랩 시크릿 가져오기 (BootstrapManager가 있다면)
    try:
        from app.core.bootstrap import BootstrapManager

        current_secret = BootstrapManager.get_current_secret()
    except ImportError:
        current_secret = "dev"

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "stats": {
                "agents": total_agents,
                "logs": total_logs,
                "incidents": total_incidents,
                "pending": pending,
            },
            "bootstrap_secret": current_secret,
            "incidents": recents,
            "jobs": jobs,
        },
    )


@router.get("/incidents", include_in_schema=False)
async def incident_list(request: Request, db: Session = Depends(get_db)):
    """
    사고 전체 목록 조회
    """
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(50).all()
    return templates.TemplateResponse(
        "incidents.html", {"request": request, "incidents": incidents}
    )


@router.get("/db/{table_name}", include_in_schema=False)
async def view_table(
    request: Request, table_name: str, limit: int = 100, db: Session = Depends(get_db)
):
    """
    DB 테이블 조회 (Read-Only)
    """
    if table_name not in TABLE_MAP:
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "error": f"Unknown table: {table_name}",
                "stats": {},
                "incidents": [],
                "jobs": [],
            },
        )

    model = TABLE_MAP[table_name]

    # 1. 컬럼 이름 추출
    inspector = inspect(model)
    columns = [c.key for c in inspector.mapper.column_attrs]

    # 2. 데이터 조회
    query = db.query(model)
    if "created_at" in columns:
        query = query.order_by(model.created_at.desc())
    elif "ts" in columns:
        query = query.order_by(model.ts.desc())

    items = query.limit(limit).all()

    # 3. 데이터 가공
    rows = []
    for item in items:
        row = []
        for col in columns:
            val = getattr(item, col)
            if isinstance(val, (dict, list)):
                val = json.dumps(val, ensure_ascii=False)
            if isinstance(val, str) and len(val) > 50:
                val = val[:50] + "..."
            row.append(val)
        rows.append(row)

    return templates.TemplateResponse(
        "db_view.html",
        {
            "request": request,
            "current_table": table_name,
            "tables": list(TABLE_MAP.keys()),
            "columns": columns,
            "rows": rows,
            "limit": limit,
        },
    )


# 실시간 알림 폴링 엔드포인트
@router.get("/api/updates")
async def check_updates(
    last_check: float = Query(...),  # [수정] Query 임포트 필요했던 부분
    db: Session = Depends(get_db),
):
    """
    클라이언트가 보낸 시간(last_check) 이후에 생성된 Incident가 있는지 확인
    """
    check_time = datetime.fromtimestamp(last_check, timezone.utc)

    new_incident = (
        db.query(Incident)
        .filter(Incident.created_at > check_time)
        .order_by(Incident.created_at.desc())
        .first()
    )

    if new_incident:
        return {
            "has_new": True,
            "incident": {
                "id": new_incident.incident_id,
                "summary": new_incident.summary,
                "confidence": new_incident.confidence,
                "status": new_incident.status,
                "time": new_incident.created_at.isoformat(),
            },
        }

    return {"has_new": False}


@router.get("/incidents/{incident_id}/pdf")
async def download_incident_pdf(incident_id: str, db: Session = Depends(get_db)):
    """
    특정 사고 보고서 PDF 다운로드
    """
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # PDF 생성
    pdf_buffer = create_incident_pdf(incident)

    # 파일명 설정
    filename = f"report_{incident_id.split('-')[-1]}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
