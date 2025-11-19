#llm/local_llm_PoC.py
import os
import json
import asyncio
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

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
                    "sha256":
                        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                }
            ],
            "hil_required": False
        }
        return json.dumps(parsed, ensure_ascii=False)


# -----------------------------------------------------
# ② LocalLlamaLLM: 실제 llama.cpp 모델 연결
# -----------------------------------------------------
class LocalLlamaLLM:
    def __init__(self, model_path=None):
        from llama_cpp import Llama
        
        self.model_path = model_path
        
        self.llm = Llama(
            model_path=self.model_path,
            n_ctx=1024,   # ★ 1024
            n_threads=4,  # ★ 4 threads only
            verbose=False
        )

    def generate(self, prompt, max_tokens=256, temperature=0.0):
        logger.info("[LocalLlamaLLM] Generating with real model...")
        try:
            output = self.llm(
                prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                top_p=1.0,
                stop=["}"]
            )
        except Exception as e:
            logger.error(f"🔥 LocalLlamaLLM crashed: {e}")
            raise

        return output["choices"][0]["text"].strip()



