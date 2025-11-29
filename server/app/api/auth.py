from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.all_schemas import RegisterRequest, RegisterResponse
from app.services.auth_service import AuthService

router = APIRouter()

@router.post("/auth/register", response_model=RegisterResponse)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    svc = AuthService(db)
    aid, acc, ref, exp = svc.register_agent(req.client_id, req.host, req.agent_version)
    return {"agent_id": aid, "access_token": acc, "refresh_token": ref, "expires_in": exp}