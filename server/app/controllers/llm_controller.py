import logging
import asyncio
import hashlib  # [New] 해시 계산용
from app.core.queues import queues
from app.core.database import SessionLocal
from app.services.advisor_service import AdvisorService
from app.models.all_models import Incident, Job
from app.llm.models import (
    IncidentAnalysisRequest,
    EvidenceRef,
)  # [New] EvidenceRef 임포트

logger = logging.getLogger("llm_ctrl")


class LLMController:
    def __init__(self):
        self.advisor = AdvisorService()

    async def run_loop(self):
        logger.info("🟣 LLM Advisor Controller Started")
        while True:
            item = await queues.llm_queue.get()
            try:
                # 1. Queue Item 파싱
                analysis = item.get("analysis", {})
                meta = item.get("meta", {})
                record = item.get("record", {})

                # [수정] EvidenceRef 생성 (빈 리스트 방지)
                raw_line = record.get("raw_line", "")
                evidence = EvidenceRef(
                    type="raw",
                    ref_id=f"log_{int(asyncio.get_event_loop().time())}",
                    source=record.get("source_type", "unknown"),
                    offset=0,
                    length=len(raw_line),
                    # 간단한 SHA256 계산 (필수 필드)
                    sha256=hashlib.sha256(raw_line.encode("utf-8")).hexdigest(),
                    rule_id="detect_module",
                )

                # 2. Request 생성 (증거 포함)
                req = IncidentAnalysisRequest(
                    incident_id=f"inc-{item.get('agent_id')}-{int(asyncio.get_event_loop().time())}",
                    event_text=f"Threat detected on {meta.get('host')}. Score: {analysis.get('max_score')}\nLog: {raw_line[:200]}",
                    evidences=[evidence],  # [수정] 생성한 증거 객체 전달
                )

                # 3. Advisor 분석 실행
                result = await self.advisor.analyze(req)

                # 4. 결과 저장
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
            status="new" if result.status == "pending_approval" else "active",
            recommended_actions=[{"action": a} for a in result.recommended_actions],
            confidence=int(result.confidence * 100),
            incident_metadata={
                "attack_mapping": result.attack_mapping,
                "hil_required": result.hil_required,
            },
        )
        db.add(inc)

        # 자동 대응 Job 생성 (승인된 경우)
        if result.status == "approved":
            job = Job(
                client_id=item["meta"]["client_id"],
                agent_id=item["agent_id"],
                job_type="BLOCK_IP",
                args={"reason": "LLM Auto-Response"},
                status="ready",
            )
            db.add(job)
            logger.info(f"⚡ Auto-Response Job Created: {job.job_id}")

        db.commit()
        logger.info(f"✅ Incident Created: {inc.incident_id}")
