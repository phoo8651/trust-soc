import time
import logging
from typing import Dict, Any, Optional

# 로컬 LLM 모듈 (llama.cpp 기반)
from llm.local_llm_PoC import LocalLlamaLLM

# 로그 설정
logger = logging.getLogger("ModelGateway")
logger.setLevel(logging.INFO)


class ModelGateway:
    """
    LLM 호출 게이트웨이
    - 기본: 로컬 LLM(gguf) 실행
    - 실패 시 fallback 더미 모델 호출 가능
    - 모델 호출 성능 모니터링(metrics logging)
    """

    def __init__(
        self,
        local_model_path: str,   # GGUF 모델 파일 경로
        use_real_llm: bool = True,  # 실제 LLM 사용할지 여부
        enable_fallback: bool = True,  # 실패 시 더미 모델 fallback
        monitoring_enabled: bool = True,  # 성능 로그 기록 여부
        timeout: float = 20  # 최대 응답 대기 시간
    ):
        self.timeout = timeout
        self.enable_fallback = enable_fallback
        self.monitoring_enabled = monitoring_enabled

        # 실제 모델 사용 여부에 따라 로드
        if use_real_llm:
            logger.info(f"🔹 Local LLM 모델 로드: {local_model_path}")
            self.llm = LocalLlamaLLM(model_path=local_model_path)
        else:
            logger.info("⚙ DummyLocalLLM 사용")
            from llm.local_llm_PoC import DummyLocalLLM
            self.llm = DummyLocalLLM()

    # ---------------------------------------------------------
    #  모델 호출 함수 (비동기)
    # ---------------------------------------------------------
    async def generate(self, prompt: str) -> str:
        """
        LLM 모델 호출
        - 오류 발생 시 fallback 처리
        """
        start = time.time()

        try:
            output = self.llm.generate(prompt)

        except Exception as e:
            logger.warning(f"❌ Local LLM 실행 실패: {e}")

            if not self.enable_fallback:
                raise

            # fallback: DummyLocalLLM 사용
            logger.info("⚠ Dummy 모델로 Fallback 처리")
            from llm.local_llm_PoC import DummyLocalLLM
            dummy = DummyLocalLLM()
            output = dummy.generate(prompt)

        # 성능 로그 기록
        duration = time.time() - start
        if self.monitoring_enabled:
            self.log_metrics(tokens_used=len(prompt), duration=duration)

        return output

    # ---------------------------------------------------------
    #  Metric Logging (토큰수 및 응답 시간 측정)
    # ---------------------------------------------------------
    def log_metrics(self, tokens_used: int, duration: float):
        logger.info(f"📊 [Metrics] 사용 토큰수={tokens_used}, 응답시간={duration:.2f}초")
