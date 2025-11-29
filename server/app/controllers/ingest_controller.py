import json
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.core.queues import queues
from app.services.auth_service import AuthService
from app.core.security_utils import verify_timestamp, verify_payload_hash
from app.models.all_models import IdempotencyKey

class IngestController:
    def __init__(self, db: Session):
        self.db = db
        self.auth = AuthService(db)

    async def handle_request(self, body: bytes, headers: dict):
        # 1. Security Headers Check
        try:
            verify_timestamp(headers.get("x-request-timestamp"))
            verify_payload_hash(body, headers.get("x-payload-hash"))
        except ValueError as e:
            raise HTTPException(422, detail=str(e))
            
        # 2. Parse
        try:
            data = json.loads(body)
            meta = data.get("meta", {})
            agent_id = data.get("agent_id")
            records = data.get("records", [])
            client_id = meta.get("client_id")
        except: raise HTTPException(400, "Invalid JSON")
        
        # 3. Auth Check
        if not self.auth.validate_access(client_id, agent_id, headers.get("authorization")):
            raise HTTPException(401, "Unauthorized")
            
        # 4. Idempotency Check
        ikey = headers.get("x-idempotency-key")
        if self.db.query(IdempotencyKey).filter_by(client_id=client_id, agent_id=agent_id, idem_key=ikey).first():
            return {"status": "queued", "accepted": 0, "msg": "duplicate"}
            
        # 5. Push to Queue
        for rec in records:
            await queues.detect_queue.put({
                "meta": meta, "agent_id": agent_id, "record": rec
            })
            
        # 6. Save Idempotency
        self.db.add(IdempotencyKey(client_id=client_id, agent_id=agent_id, idem_key=ikey))
        self.db.commit()
        
        return {"status": "queued", "accepted": len(records)}