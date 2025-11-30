import os
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

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

# 1. 환경설정 및 DB 초기화 모듈
from app.core.config import settings
from app.core.database import init_db
from app.core.security import set_current_client

# 2. [수정] 새로운 라우터 및 서비스 임포트
from app.api import ingest, auth, llm_router, console
from app.controllers.detect_controller import DetectController
from app.controllers.llm_controller import LLMController
from app.services.advisor_service import AdvisorService
from app.core.bootstrap import BootstrapManager

logger = logging.getLogger("main")


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
    BootstrapManager.start()

    print("📚 Initializing LLM Advisor...")
    _ = AdvisorService()  # 모델 및 RAG 로드

    # [중요] 백그라운드 컨트롤러 시작 (이 부분이 있어야 Detect 모듈이 돕니다)
    print("🚀 Starting Background Controllers...")
    detect_ctrl = DetectController()
    llm_ctrl = LLMController()

    task1 = asyncio.create_task(detect_ctrl.run_loop())
    task2 = asyncio.create_task(llm_ctrl.run_loop())

    yield

    print("🛑 Shutting down controllers...")
    task1.cancel()
    task2.cancel()
    BootstrapManager.stop()


app = FastAPI(title="Integrated SOC Server", lifespan=lifespan)
app.add_middleware(TenantContextMiddleware)


# 스키마 불일치 (Validation Error) -> 400 Bad Request 변환
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_details = exc.errors()
    logger.warning(f"⚠️ Validation Error: {error_details}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "detail": "Invalid request schema",
            "errors": error_details,  # 구체적으로 어떤 필드가 틀렸는지 알려줌
        },
    )


# 알 수 없는 서버 에러 -> 500 처리 (로그 남김)
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"❌ Server Error: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal Server Error. Please check server logs."},
    )


# 라우터 등록
app.include_router(auth.router)
app.include_router(ingest.router)
app.include_router(llm_router.router, prefix="/llm")
app.include_router(console.router, prefix="/console")


@app.get("/health")
def health():
    return {"status": "ok", "env": settings.ENV_STATE}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
