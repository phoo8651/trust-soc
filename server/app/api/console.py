from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import inspect
from app.core.bootstrap import BootstrapManager
from pathlib import Path
import json

from app.core.database import get_db

# 모든 모델 임포트
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

router = APIRouter()
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
    # ... (기존 대시보드 코드 유지) ...
    # (기존 코드가 있다면 그대로 두세요, 여기서는 생략)
    total_agents = db.query(Agent).count()
    total_logs = db.query(RawLog).count()
    total_incidents = db.query(Incident).count()
    pending = db.query(Incident).filter(Incident.status == "pending_approval").count()

    recents = db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()
    jobs = db.query(Job).order_by(Job.created_at.desc()).limit(5).all()

    current_secret = BootstrapManager.get_current_secret()

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
    # ... (기존 코드 유지) ...
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(50).all()
    return templates.TemplateResponse(
        "incidents.html", {"request": request, "incidents": incidents}
    )


# [New] DB 뷰어 라우터 추가
@router.get("/db/{table_name}", include_in_schema=False)
async def view_table(
    request: Request, table_name: str, limit: int = 100, db: Session = Depends(get_db)
):
    if table_name not in TABLE_MAP:
        # 잘못된 테이블 요청 시 대시보드로 리다이렉트 혹은 에러
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

    # 2. 데이터 조회 (최신순 정렬 시도)
    query = db.query(model)

    # created_at이나 ts 컬럼이 있으면 내림차순 정렬
    if "created_at" in columns:
        query = query.order_by(model.created_at.desc())
    elif "ts" in columns:
        query = query.order_by(model.ts.desc())

    items = query.limit(limit).all()

    # 3. 템플릿에서 렌더링하기 좋게 데이터 가공 (Dict List로 변환)
    rows = []
    for item in items:
        row = []
        for col in columns:
            val = getattr(item, col)
            # 딕셔너리나 리스트 등 객체 타입은 문자열로 변환
            if isinstance(val, (dict, list)):
                val = json.dumps(val, ensure_ascii=False)
            # 너무 긴 문자열 자르기
            if isinstance(val, str) and len(val) > 50:
                val = val[:50] + "..."
            row.append(val)
        rows.append(row)

    return templates.TemplateResponse(
        "db_view.html",
        {
            "request": request,
            "current_table": table_name,
            "tables": list(TABLE_MAP.keys()),  # 사이드바 메뉴용
            "columns": columns,
            "rows": rows,
            "limit": limit,
        },
    )
