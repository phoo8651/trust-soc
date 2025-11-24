import html
from typing import List

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from db import get_db
import model
from security import SecurityContext, apply_rls, get_security_context, require_role

router = APIRouter()


def _esc(val) -> str:
    if val is None:
        return ""
    return html.escape(str(val))


def _render_table(headers: List[str], rows: List[List[str]]) -> str:
    head_html = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body_html = "".join(
        "<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f"<table><thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table>"


@router.get("/console", response_class=HTMLResponse)
def console(
    db: Session = Depends(get_db),
    ctx: SecurityContext = Depends(get_security_context),
):
    require_role(ctx, "SOC_ADMIN")
    apply_rls(db, ctx.tenant_id)

    jobs_pending = (
        db.query(model.Job)
        .filter(model.Job.client_id == ctx.tenant_id, model.Job.status.in_(("pending", "ready")))
        .order_by(model.Job.created_at.desc())
        .limit(30)
        .all()
    )
    jobs_done = (
        db.query(model.Job)
        .filter(model.Job.client_id == ctx.tenant_id, model.Job.status.in_(("delivered", "done", "error")))
        .order_by(model.Job.created_at.desc())
        .limit(30)
        .all()
    )
    results = (
        db.query(model.JobResult)
        .join(model.Job, model.Job.job_id == model.JobResult.job_id)
        .filter(model.Job.client_id == ctx.tenant_id)
        .order_by(model.JobResult.reported_at.desc())
        .limit(30)
        .all()
    )
    
    parts = [
        "<html><head><style>body{font-family:Arial,sans-serif;padding:16px;}table{border-collapse:collapse;margin-bottom:18px;}th,td{border:1px solid #ccc;padding:6px 8px;font-size:13px;}th{background:#f5f5f5;text-align:left;}h2{margin-top:24px;}code{background:#f2f2f2;padding:2px 4px;border-radius:3px;}</style></head><body>",
        f"<h1>Console</h1>",
    ]

    parts.append("<h2>등록된 대기열</h2>")
    parts.append(
        _render_table(
            ["ID", "에이전트", "타입", "상태", "만료 일시", "등록 일시"],
            [
                [
                    j.job_id,
                    j.agent_id,
                    j.job_type,
                    j.status,
                    j.expires_at,
                    j.created_at,
                ]
                for j in jobs_pending
            ],
        )
    )

    parts.append("<h2>완성된 큐</h2>")
    parts.append(
        _render_table(
            ["ID", "에이전트", "타입", "상태", "생성 일자"],
            [
                [j.job_id, j.agent_id, j.job_type, j.status, j.created_at]
                for j in jobs_done
            ],
        )
    )

    parts.append("<h2>결과</h2>")
    parts.append(
        _render_table(
            ["ID", "에이전트", "성공 여부", "보고 일시"],
            [
                [r.job_id, r.agent_id, r.success, r.reported_at]
                for r in results
            ],
        )
    )

    parts.append("</body></html>")
    return "".join(parts)
