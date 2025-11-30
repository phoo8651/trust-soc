import logging
import asyncio
from app.core.queues import queues
from app.services.detectors import DetectorService
from app.core.database import SessionLocal
from app.models.all_models import Event
from datetime import datetime, timezone

logger = logging.getLogger("detect_ctrl")


class DetectController:
    def __init__(self):
        self.detector = DetectorService()

    async def run_loop(self):
        logger.info("🟢 Detect Controller Started")
        while True:
            item = await queues.detect_queue.get()
            try:
                record = item.get("record", {})
                meta = item.get("meta", {})

                # [Debug] 처리 중인 로그 확인
                raw_sample = record.get("raw_line", "")[:50]
                # logger.debug(f"Processing: {raw_sample}...")

                # [수정] run_rule_detect 대신 run_all 호출
                # YAML 룰 기반으로 모든 탐지를 한 번에 수행합니다.
                result = self.detector.run_all(record)

                score = result.get("max_score", 0.0)

                # 점수가 있으면 로그 출력
                if score > 0:
                    logger.info(
                        f"🔍 Detected (Score: {score}): {result.get('details')}"
                    )
                    # Event 테이블에 단순 기록 (옵션)
                    self._save_event(meta, record, result)

                # [중요] 점수가 0.5 이상이면 LLM 분석 큐로 전달
                if score >= 0.5:
                    logger.info("   🚀 Threat detected! Forwarding to LLM Advisor...")
                    item["analysis"] = result
                    await queues.llm_queue.put(item)

            except Exception as e:
                logger.error(f"Detect Error: {e}")
            finally:
                queues.detect_queue.task_done()

    def _save_event(self, meta, record, result):
        """탐지된 내용을 Event 테이블에 저장"""
        try:
            with SessionLocal() as db:
                event = Event(
                    ts=datetime.now(timezone.utc),
                    client_id=meta.get("client_id"),
                    host=meta.get("host"),
                    category="rule_match",
                    severity="medium" if result["max_score"] >= 0.5 else "info",
                    summary=str(result.get("details", [])),
                    evidence_refs=result.get("details"),  # JSON 호환
                    rule_id="multi-rule",
                    ml_score=result["max_score"],
                    context=result,
                )
                db.add(event)
                db.commit()
        except Exception as e:
            logger.error(f"Failed to save event: {e}")
