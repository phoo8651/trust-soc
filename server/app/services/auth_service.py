import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.all_models import Agent, AuditLog


class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def register_agent(self, client_id: str, host: str, version: str):
        # 1. ID를 미리 명시적으로 생성
        new_agent_id = f"agent-{uuid.uuid4()}"

        access = f"acc_{uuid.uuid4().hex}"
        refresh = f"ref_{uuid.uuid4().hex}"
        # Access Token 만료 시간 설정
        ttl = settings.ACCESS_TOKEN_TTL_SECONDS
        exp = datetime.now(timezone.utc) + timedelta(seconds=ttl)

        # 2. Agent 객체 생성 (ID 포함)
        agent = Agent(
            agent_id=new_agent_id,  # 여기서 ID 할당
            client_id=client_id,
            host=host,
            agent_version=version,
            access_token=access,
            refresh_token=refresh,
            access_expires=exp,
        )
        self.db.add(agent)

        # 3. AuditLog 생성 (생성된 ID 사용)
        self.db.add(
            AuditLog(
                actor="system",
                action="register",
                subject=new_agent_id,  # None이 아닌 실제 ID값
            )
        )

        self.db.commit()

        return new_agent_id, access, refresh, ttl

    def validate_access(self, client_id: str, agent_id: str, header: str) -> bool:
        if not header or not header.startswith("Bearer "):
            return False

        token = header.split(" ")[1]

        agent = (
            self.db.query(Agent)
            .filter_by(agent_id=agent_id, client_id=client_id)
            .first()
        )
        if not agent:
            return False

        if agent.access_token != token:
            return False

        # 만료 시간 체크 (UTC 기준)
        if agent.access_expires.astimezone(timezone.utc) < datetime.now(timezone.utc):
            return False

        return True
