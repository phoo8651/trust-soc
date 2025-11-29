import asyncio
import logging
from app.core.queues import queues
from app.core.database import SessionLocal
from app.services.advisor_service import AdvisorService
from app.models.all_models import Incident, Job, AuditLog
from app.llm.models import IncidentAnalysisRequest, EvidenceRef

logger = logging.getLogger("llm_ctrl")


class LLMController:
    def __init__(self):
        self.advisor = AdvisorService()

    async def run_loop(self):
        logger.info("🟣 LLM Advisor Controller Started")
        while True:
            item = await queues.llm_queue.get()
            try:
                # 큐 아이템 -> Request 변환
                req = IncidentAnalysisRequest(
                    incident_id=f"inc-{item['agent_id']}-{int(asyncio.get_event_loop().time())}",
                    event_text=str(item.get("analysis", "Unknown Threat")),
                    evidences=[],  # 필요시 추가
                )

                # 분석 실행
                result = await self.advisor.analyze(req)

                # DB 저장
                with SessionLocal() as db:
                    self._save(db, item, result)

            except Exception as e:
                logger.error(f"LLM Error: {e}")
            finally:
                queues.llm_queue.task_done()

    def _save(self, db, item, result):
        inc = Incident(
            client_id=item["meta"]["client_id"],
            summary=result.summary,
            status="new",
            recommended_actions=[{"action": a} for a in result.recommended_actions],
            confidence=int(result.confidence * 100),
        )
        db.add(inc)
        db.commit()
        logger.info(f"✅ Incident Saved: {inc.incident_id}")
