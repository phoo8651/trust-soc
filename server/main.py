import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware

# 1. .env 파일 자동 생성
ENV_PATH = ".env"
DEFAULT_ENV = """# Auto-generated .env
DATABASE_URL=postgresql://user:password@postgres-service:5432/socdb
POLICY_SIGNING_SECRET=change_me_secure
JOB_SIGNING_SECRET=change_me_secure
AES_GCM_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000
# LLM Settings
LLM_MODE=local
LOCAL_MODEL=/app/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf
WEBHOOK_SECRET=change_me_webhook
PROMETHEUS_PORT=8001
"""

if not os.path.exists(ENV_PATH):
    with open(ENV_PATH, "w") as f:
        f.write(DEFAULT_ENV)
    print(f"✅ Created default .env at {os.path.abspath(ENV_PATH)}")

# 2. 모듈 임포트
from app.core.config import settings
from app.core.database import init_db
from app.core.security import set_current_client
from app.api import ingest, auth, llm_router  # llm_router 추가
from app.controllers.detect_controller import DetectController
from app.controllers.llm_controller import LLMController
from app.services.advisor_service import AdvisorService
from app.core.bootstrap import BootstrapManager
from app.api import console


# 3. 미들웨어
class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_id = request.headers.get("X-Client-Id") or request.headers.get(
            "X-Tenant-Id"
        )
        set_current_client(client_id)
        response = await call_next(request)
        return response


# 4. Lifespan (초기화 및 종료)
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🛠️  Initializing Database...")
    init_db()

    print("🔐 Starting Bootstrap Secret Rotation...")
    BootstrapManager.start()  # [New] 키 갱신 시작

    print("📚 Initializing LLM Advisor...")
    _ = AdvisorService()

    print("🚀 Starting Background Controllers...")
    detect_ctrl = DetectController()
    llm_ctrl = LLMController()

    task1 = asyncio.create_task(detect_ctrl.run_loop())
    task2 = asyncio.create_task(llm_ctrl.run_loop())

    yield

    print("🛑 Shutting down...")
    task1.cancel()
    task2.cancel()
    BootstrapManager.stop()


# 5. 앱 정의
app = FastAPI(title="Integrated SOC Server", lifespan=lifespan)
app.add_middleware(TenantContextMiddleware)

# 라우터 등록
app.include_router(auth.router)
app.include_router(ingest.router)
app.include_router(llm_router.router, prefix="/llm")  # /llm/analyze
app.include_router(console.router, prefix="/console")


@app.get("/health")
def health():
    return {"status": "ok", "env": settings.ENV_STATE}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
