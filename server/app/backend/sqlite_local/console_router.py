import html
from typing import List

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from db import get_db
import model

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


def _pager(section: str, page: int, limit: int, pending_page: int, done_page: int, result_page: int) -> str:
    def qs(new_page: int) -> str:
        return (
            f"?limit={limit}"
            f"&pending_page={pending_page if section!='pending' else new_page}"
            f"&done_page={done_page if section!='done' else new_page}"
            f"&result_page={result_page if section!='result' else new_page}"
        )

    prev_link = f'<a href="{qs(max(1, page-1))}">Prev</a>'
    next_link = f'<a href="{qs(page+1)}">Next</a>'
    return f'<div class="pager">{prev_link}&nbsp;{next_link}&nbsp;<span>page {page}</span></div>'


@router.get("/console", response_class=HTMLResponse)
def console(
    db: Session = Depends(get_db),
    limit: int = Query(10, ge=1, le=100),
    pending_page: int = Query(1, ge=1),
    done_page: int = Query(1, ge=1),
    result_page: int = Query(1, ge=1),
):
    jobs_pending = (
        db.query(model.Job)
        .filter(model.Job.status.in_(("pending", "ready")))
        .order_by(model.Job.created_at.desc())
        .offset((pending_page - 1) * limit)
        .limit(limit)
        .all()
    )
    jobs_done = (
        db.query(model.Job)
        .filter(model.Job.status.in_(("delivered", "done", "error")))
        .order_by(model.Job.created_at.desc())
        .offset((done_page - 1) * limit)
        .limit(limit)
        .all()
    )
    results = (
        db.query(model.JobResult)
        .join(model.Job, model.Job.job_id == model.JobResult.job_id)
        .order_by(model.JobResult.reported_at.desc())
        .offset((result_page - 1) * limit)
        .limit(limit)
        .all()
    )

    parts = [
        "<html><head><style>body{font-family:Arial,sans-serif;padding:16px;}table{border-collapse:collapse;margin-bottom:8px;}th,td{border:1px solid #ccc;padding:6px 8px;font-size:13px;}th{background:#f5f5f5;text-align:left;}h2{margin-top:24px;}code{background:#f2f2f2;padding:2px 4px;border-radius:3px;} .pager a{margin-right:8px;}</style></head><body>",
        "<h1>Console</h1>",
    ]

    parts.append("<h2>등록된 대기열 (pending/ready)</h2>")
    parts.append(_pager("pending", pending_page, limit, pending_page, done_page, result_page))
    parts.append(
        _render_table(
            ["ID", "에이전트", "명령", "상태", "만료 시각", "등록 시각"],
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

    parts.append("<h2>전달/완료/에러된 잡</h2>")
    parts.append(_pager("done", done_page, limit, pending_page, done_page, result_page))
    parts.append(
        _render_table(
            ["ID", "에이전트", "명령", "상태", "마지막 전달", "등록 시각"],
            [
                [j.job_id, j.agent_id, j.job_type, j.status, j.last_delivered_at, j.created_at]
                for j in jobs_done
            ],
        )
    )

    parts.append("<h2>결과</h2>")
    parts.append(_pager("result", result_page, limit, pending_page, done_page, result_page))
    parts.append(
        _render_table(
            ["ID", "에이전트", "성공 여부", "보고 시각", "출력 일부"],
            [
                [r.job_id, r.agent_id, r.success, r.reported_at, (r.output_snippet or "")[:120]]
                for r in results
            ],
        )
    )

    parts.append("</body></html>")
    return "".join(parts)
