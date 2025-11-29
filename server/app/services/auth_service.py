import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.all_models import Agent, AuditLog

class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def register_agent(self, client_id, host, version):
        access = f"acc_{uuid.uuid4()}"
        refresh = f"rft_{uuid.uuid4()}"
        ttl = settings.ACCESS_TOKEN_TTL_SECONDS
        exp = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        
        agent = Agent(
            client_id=client_id, host=host, agent_version=version,
            access_token=access, refresh_token=refresh, access_expires=exp
        )
        self.db.add(agent)
        self.db.add(AuditLog(actor="system", subject=agent.agent_id, action="agent_register"))
        self.db.commit()
        return agent.agent_id, access, refresh, ttl

    def validate_access(self, client_id: str, agent_id: str, token_header: str) -> bool:
        if not token_header or not token_header.startswith("Bearer "): return False
        token = token_header.split(" ", 1)[1]
        
        agent = self.db.query(Agent).filter_by(agent_id=agent_id, client_id=client_id).first()
        if not agent: return False
        
        if agent.access_token != token: return False
        if agent.access_expires.astimezone(timezone.utc) < datetime.now(timezone.utc): return False
        
        return True