import time
import logging
import hashlib
import asyncio
import traceback  # [New] 상세 에러 로그를 위해 추가
from typing import Dict, Any

# 패키지 경로 확인
from app.llm.local_llm_PoC import DummyLocalLLM, LocalMistralLLM

logger = logging.getLogger("ModelGateway")


class ModelGateway:
    def __init__(
        self,
        local_model_path: str,
        use_real_llm: bool = True,
        enable_fallback: bool = True,
        timeout: float = 180,  # [수정] 타임아웃 180초(3분)로 넉넉하게 증가
    ):
        self.timeout = timeout
        self.enable_fallback = enable_fallback
        self.mock_mode = False

        if use_real_llm:
            try:
                self.llm = LocalMistralLLM(model_path=local_model_path)
                logger.info(f"✅ Real LLM Loaded: {local_model_path}")
            except Exception as e:
                logger.error(f"❌ Failed to load Real LLM: {e}")
                logger.error(traceback.format_exc())  # 로딩 실패 시에도 상세 로그 출력

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

            logger.info("⏳ Sending prompt to Local LLM...")

            # [수정] 타임아웃 발생 시 명확히 잡기 위해 wait_for 사용
            return await asyncio.wait_for(
                asyncio.to_thread(self.llm.generate, prompt), timeout=self.timeout
            )

        except asyncio.TimeoutError:
            # [New] 타임아웃 에러 별도 처리
            logger.error(f"⏰ LLM Timeout! Execution took longer than {self.timeout}s")
            if self.enable_fallback:
                return self._fallback_response()
            raise TimeoutError("LLM Generation Timed Out")

        except Exception as e:
            # [New] 일반 에러 발생 시 Traceback 전체 출력
            error_msg = str(e)
            stack_trace = traceback.format_exc()

            logger.error(f"❌ Local LLM Runtime Error: {error_msg}")
            logger.error(f"🔍 Stack Trace:\n{stack_trace}")

            if self.enable_fallback:
                logger.info("🔄 Activating Fallback Mechanism (Dummy Response)")
                return self._fallback_response()
            raise e

        finally:
            duration = time.time() - start_time
            logger.info(f"⏱️ LLM Processing Time: {duration:.2f}s")

    def _fallback_response(self):
        """Fallback 시 사용할 더미 응답 생성"""
        return DummyLocalLLM().generate("fallback")
