import time
import logging
import hashlib
import asyncio
from typing import Dict, Any

# [수정] 올바른 패키지 경로로 변경
from app.llm.local_llm_PoC import DummyLocalLLM, LocalMistralLLM

logger = logging.getLogger("ModelGateway")


class ModelGateway:
    def __init__(
        self,
        local_model_path: str,
        use_real_llm: bool = True,
        enable_fallback: bool = True,
        timeout: float = 120,  # [수정] 타임아웃 60 -> 120초 (CPU 모드 고려)
    ):
        self.timeout = timeout
        self.enable_fallback = enable_fallback
        self.mock_mode = False

        if use_real_llm:
            try:
                self.llm = LocalMistralLLM(model_path=local_model_path)
            except Exception as e:
                logger.error(f"❌ Failed to load Real LLM: {e}")
                if not enable_fallback:
                    raise e

                logger.warning("⚠️ Switching to Dummy LLM due to load failure.")
                self.llm = DummyLocalLLM()
                self.mock_mode = True
        else:
            self.llm = DummyLocalLLM()
            self.mock_mode = True

    async def generate(self, prompt: str) -> str:
        start_time = time.time()
        try:
            if self.mock_mode:
                return self.llm.generate(prompt)

            # 실제 LLM은 동기 함수이므로 별도 스레드에서 실행 (Non-blocking)
            return await asyncio.wait_for(
                asyncio.to_thread(self.llm.generate, prompt), timeout=self.timeout
            )

        except Exception as e:
            # [수정] 에러 메시지를 더 명확하게 출력
            logger.error(f"❌ Local LLM Runtime Error: {e}")

            if self.enable_fallback:
                logger.info("🔄 Activating Fallback Mechanism (Dummy Response)")
                return DummyLocalLLM().generate(prompt)
            raise e
        finally:
            duration = time.time() - start_time
            logger.info(f"⏱️ LLM Processing Time: {duration:.2f}s")
