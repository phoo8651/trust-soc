import logging
from app.core.queues import queues
from app.services.detectors import DetectorService

logger = logging.getLogger("detect_ctrl")

class DetectController:
    def __init__(self):
        self.detector = DetectorService()

    async def run_loop(self):
        logger.info("🟢 Detect Controller Started")
        while True:
            item = await queues.detect_queue.get()
            try:
                rec = item["record"]
                # Run detectors
                results = [
                    self.detector.run_rule_detect(rec),
                    self.detector.run_ml_detect(rec),
                    self.detector.run_yara_detect(rec)
                ]
                analysis = self.detector.aggregate(results)
                
                # Threshold Check (0.5 이상이면 LLM 분석)
                if analysis["max_score"] >= 0.5:
                    item["analysis"] = analysis
                    await queues.llm_queue.put(item)
            except Exception as e:
                logger.error(f"Detect Error: {e}")
            finally:
                queues.detect_queue.task_done()