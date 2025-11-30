import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_MISTRAL_MODEL = os.getenv(
    "LOCAL_MODEL",
    os.path.join("llm", "models", "mistral-7b-instruct-v0.2.Q4_K_M.gguf"),
)


class DummyLocalLLM:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        logger.info(f"[DummyLocalLLM] initialized (model_path={self.model_path})")

    def generate(self, prompt: str) -> str:
        logger.info("[DummyLocalLLM] generating mock response")
        # (기존 더미 로직 유지)
        parsed: Dict[str, Any] = {
            "summary": "모의 요약 (dummy)",
            "attack_mapping": ["T1595"],
            "recommended_actions": ["로그 모니터링 강화"],
            "confidence": 0.5,
            "evidence_refs": [],
            "hil_required": False,
        }
        return json.dumps(parsed, ensure_ascii=False)


class LocalMistralLLM:
    def __init__(self, model_path: Optional[str] = None):
        from llama_cpp import Llama

        self.model_path = model_path or DEFAULT_MISTRAL_MODEL

        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model not found: {self.model_path}")

        # [수정 1] 컨텍스트 윈도우 증가 (입력+출력 합계 용량)
        # 기존 1024 -> 4096 (Mistral 모델의 여유 공간 확보)
        self.llm = Llama(
            model_path=self.model_path, n_ctx=4096, n_gpu_layers=-1, verbose=False
        )

    def generate(self, prompt: str) -> str:
        # [수정 2] 생성 최대 길이 증가 (출력 용량)
        # 기존 256 -> 2048 (긴 보고서도 잘리지 않도록 충분히 확보)
        try:
            output = self.llm(
                prompt,
                max_tokens=2048,
                temperature=0.1,
                top_p=0.95,
                stop=["</s>", "END_JSON"],  # 종료 조건 명확화
                echo=False,
            )
            return output["choices"][0]["text"]
        except Exception as e:
            logger.error(f"🔥 LocalMistralLLM crash: {e}")
            raise
