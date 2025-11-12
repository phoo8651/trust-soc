from dataclasses import dataclass
from typing import Set

from fastapi import Header, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text  

@dataclass
class SecurityContext:
    tenant_id: str
    actor_id: str
    roles: Set[str]

def parse_roles(header_value: str) -> Set[str]:
    if not header_value:
        return set()
    return {role.strip().upper() for role in header_value.split(",") if role.strip()}

async def get_security_context(
    tenant_id: str = Header(..., alias="X-Tenant-Id"),
    actor_id: str = Header(..., alias="X-Actor-Id"),
    actor_roles: str = Header("", alias="X-Actor-Roles"),
) -> SecurityContext:
    roles = parse_roles(actor_roles)
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing tenant id")
    return SecurityContext(tenant_id=tenant_id, actor_id=actor_id, roles=roles)

def require_role(ctx: SecurityContext, role: str):
    role = role.upper()
    if role not in ctx.roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"role {role} required")

def apply_rls(session: Session, tenant_id: str):
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant id required")

   
    try:
        dialect = session.bind.dialect.name
    except Exception:
        dialect = "unknown"

    if dialect != "postgresql":
        return


    session.execute(text("SET LOCAL app.current_tenant = :tenant"), {"tenant": tenant_id})
