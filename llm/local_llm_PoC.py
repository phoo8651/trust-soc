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
    """
    llama.cpp 기반 로컬 LLM 어댑터
    """
    def __init__(self, model_path: Optional[str] = None, n_ctx: int = 4096, n_threads: int = 8):
        try:
            from llama_cpp import Llama
        except ImportError:
            raise ImportError("llama-cpp-python 패키지를 설치해야 합니다: pip install llama-cpp-python")

        self.model_path = model_path or os.environ.get(
            "LLM_MODEL_PATH",
            os.path.join("llm", "models", "mistral-7b-instruct-v0.2.Q4_K_M.gguf")
        )

        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"LLM 모델 파일을 찾을 수 없습니다: {self.model_path}")

        logger.info(f"[LocalLlamaLLM] Loading model from {self.model_path} ...")
        self.llm = Llama(
            model_path=self.model_path,
            n_ctx=n_ctx,
            n_threads=n_threads,
            verbose=False
        )
        logger.info("[LocalLlamaLLM] 모델 로드 완료")

    def generate(self, prompt: str, max_tokens: int = 512, temperature: float = 0.7):
    
        logger.info("[LocalLlamaLLM] Generating with real model...")

        output = self.llm(
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=0,
                top_p=1.0,
                repeat_penalty=1.1,
                stop=["</s>"]
            )
        

        text = output["choices"][0]["text"].strip()

        # JSON 파싱 시도
        try:
            parsed = json.loads(text)
            return json.dumps(parsed, ensure_ascii=False)

        except json.JSONDecodeError:
            logger.warning("[LocalLlamaLLM] ⚠️ JSON 파싱 실패. 기본 스키마로 자동 보정")

            return json.dumps({
                "summary": text[:200],  # 원문 일부
                "attack_mapping": [],
                "recommended_actions": [],
                "confidence": 0.0,
                "evidence_refs": [],
                "hil_required": True
            }, ensure_ascii=False)

