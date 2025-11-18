import logging
from dataclasses import dataclass
from typing import Optional, Set

from fastapi import Header, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from constants import (
    ACTOR_ID_HEADER,
    ACTOR_ROLES_HEADER,
    CANON_TENANT_HEADER,
    LEGACY_TENANT_HEADER,
)

log = logging.getLogger("security")


@dataclass
class SecurityContext:
    tenant_id: str
    actor_id: str
    roles: Set[str]


def parse_roles(raw: Optional[str]) -> Set[str]:
    if not raw:
        return set()
    return {role.strip().upper() for role in raw.split(",") if role.strip()}


async def get_security_context(
    request: Request,
    tenant_header: Optional[str] = Header(None, alias=CANON_TENANT_HEADER),
    legacy_tenant: Optional[str] = Header(None, alias=LEGACY_TENANT_HEADER),
    actor_header: Optional[str] = Header(None, alias=ACTOR_ID_HEADER),
    roles_header: Optional[str] = Header("", alias=ACTOR_ROLES_HEADER),
) -> SecurityContext:
    tenant_id = getattr(request.state, "tenant_id", None) or tenant_header or legacy_tenant
    actor_id = getattr(request.state, "actor_id", None) or actor_header
    roles_raw = getattr(request.state, "actor_roles", None)
    if roles_raw is None:
        roles_raw = roles_header

    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing tenant id")
    if not actor_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="missing actor id")

    return SecurityContext(
        tenant_id=tenant_id,
        actor_id=actor_id,
        roles=parse_roles(roles_raw),
    )


def require_role(ctx: SecurityContext, role: str) -> None:
    want = role.upper()
    if want not in ctx.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role {want} required",
        )


def apply_rls(session: Session, tenant_id: str) -> None:
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant id required")

    try:
        dialect = session.bind.dialect.name
    except Exception:
        dialect = "unknown"
    if dialect != "postgresql":
        return

    try:
        session.execute(
            text("SELECT set_config('app.current_client', :tenant, true)"),
            {"tenant": tenant_id},
        )
    except SQLAlchemyError as exc:
        session.rollback()
        log.warning("RLS context set skipped (rolled back): %s", exc)
