import logging
from sqlalchemy.orm import Session
from app.models.all_models import Incident, Job, AuditLog
from app.core.crypto import compute_job_signature

logger = logging.getLogger("agent_ctrl")

class AgentController:
    def process_result(self, db: Session, original_item: dict, llm_result: dict):
        client_id = original_item["meta"]["client_id"]
        agent_id = original_item["agent_id"]
        action = llm_result["recommended_action"]
        
        # 1. Incident
        inc = Incident(
            client_id=client_id,
            summary=llm_result["llm_summary"],
            status="new",
            recommended_actions=[{"action": action}],
            confidence=int(llm_result["confidence"] * 100)
        )
        db.add(inc)
        
        # 2. Job (Command)
        if action == "BLOCK_IP":
            args = {"reason": "Auto Block"}
            sig = compute_job_signature("BLOCK_IP", args)
            job = Job(
                client_id=client_id, agent_id=agent_id,
                job_type="BLOCK_IP", args=args, signature=sig,
                status="ready"
            )
            db.add(job)
            logger.warning(f"⚠️ Command Issued: BLOCK_IP -> {agent_id}")
            
        db.commit()