from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

from tenant_context import set_current_client

class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 기본 헤더 이름은 constants.py 기준
        client_id = (
            request.headers.get("X-Client-Id")
            or request.headers.get("X-Tenant-Id")
        )
        set_current_client(client_id)
        response = await call_next(request)
        return response
