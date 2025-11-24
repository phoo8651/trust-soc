#llm/local_llm_PoC.py
import os
import json
import asyncio
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_MISTRAL_MODEL = os.getenv(
  "LOCAL_MODEL",
  os.path.join("llm", "models", "mistral-7b-instruct-v0.2.Q4_K_M.gguf"),
)

# -----------------------------------------------------
# ① DummyLocalLLM: 개발용 모의 응답
# -----------------------------------------------------
class DummyLocalLLM:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        logger.info(f"[DummyLocalLLM] initialized (model_path={self.model_path})")

    def generate(self, prompt: str) -> str:
        logger.info("[DummyLocalLLM] generating mock response")
        parsed: Dict[str, Any] = {
            "summary": "모의 요약 (dummy)",
            "attack_mapping": ["T1595"],
            "recommended_actions": ["로그 모니터링 강화"],
            "confidence": 0.5,
            "evidence_refs": [
                {
                    "type": "raw",
                    "ref_id": "log_001",
                    "source": "auth.log",
                    "offset": 0,
                    "length": 100,
                    "sha256": (
                        "abcdef1234567890abcdef1234567890"
                        "abcdef1234567890abcdef1234567890"
                    ),
                }
            ],
            "hil_required": False,
        }
        return json.dumps(parsed, ensure_ascii=False)


# -----------------------------------------------------
# ② LocalMistralLLM: mistral-7b-instruct GGUF 로컬 모델 연결
# -----------------------------------------------------
class LocalMistralLLM:
    def __init__(self, model_path: Optional[str] = None):
        from llama_cpp import Llama  # 런타임 엔진 (GGUF용)

        # 경로가 명시되지 않으면 Mistral 기본 모델 사용
        self.model_path = model_path or DEFAULT_MISTRAL_MODEL

        self.llm = Llama(
            model_path=self.model_path,
            n_ctx=1024,   # 컨텍스트 길이
            n_threads=4,  # CPU 스레드 수 (환경에 맞게 조정 가능)
            verbose=False
        )

    def generate(self, prompt, max_tokens: int = 256, temperature: float = 0.0):
        logger.info("[LocalMistralLLM] Generating with mistral-7b-instruct...")
        try:
            output = self.llm(
                prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=1.0,
                stop=["}"],
            )
        except Exception as e:
            logger.error(f"🔥 LocalMistralLLM crashed: {e}")
            raise
        
        return output["choices"][0]["text"]
        #return output["choices"][0]["text"].strip()


