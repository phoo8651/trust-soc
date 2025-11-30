import os
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.all_schemas import RegisterRequest, RegisterResponse
from app.services.auth_service import AuthService
from app.core.bootstrap import BootstrapManager

router = APIRouter()

# 서버에 설정된 부트스트랩 비밀키 (기본값: dev)
# 실제 배포 시엔 환경변수로 안전한 값을 주입해야 함
BOOTSTRAP_SECRET = os.getenv("AGENT_BOOTSTRAP_SECRET", "dev")


@router.post("/auth/register", response_model=RegisterResponse)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    # [Update] 동적 시크릿 검증
    if not BootstrapManager.validate(req.secret_proof):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired bootstrap secret",
        )

    svc = AuthService(db)
    aid, acc, ref, exp = svc.register_agent(req.client_id, req.host, req.agent_version)

    return {
        "agent_id": aid,
        "access_token": acc,
        "refresh_token": ref,
        "expires_in": exp,
    }
