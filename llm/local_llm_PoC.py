# llm/locol_llm.PoC.py
'''from llama_cpp import Llama


MODEL_PATH = "C:/Users/ngh11/trust-soc/llm/models/mistral-7b-instruct-v0.2.Q4_K_M.gguf"

# 모델 로드
llm = Llama(model_path=MODEL_PATH, n_ctx=2048, n_threads=6)

# 테스트 프롬프트
prompt = """SYSTEM:
당신은 보안 로그를 분석하는 AI입니다.
다음 로그의 공격 징후를 요약하세요.

USER:
[EVENT]
2025-11-02 14:11:33 - POST /app/login - suspicious payload detected

[TOP-K EVIDENCES]
ref_id: log_001
type: raw
source: web_log
snippet: "payload contains eval() function"

OUTPUT_SCHEMA:
{
  "type": "object",
  "properties": {
    "summary": {"type": "string"},
    "attack_mapping": {"type": "array", "items": {"type": "string"}},
    "recommended_actions": {"type": "array", "items": {"type": "string"}},
    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    "evidence_refs": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "type": {"type": "string", "enum": ["raw", "yara", "hex", "webhook"]},
          "ref_id": {"type": "string"},
          "source": {"type": "string"},
          "offset": {"type": "integer"},
          "length": {"type": "integer"},
          "sha256": {"type": "string"},
          "rule_id": {"type": "string"}
        },z
        "required": ["type", "ref_id", "source", "offset", "length", "sha256"]
      }
    },
    "hil_required": {"type": "boolean"}
  },
  "required": ["summary", "attack_mapping", "recommended_actions", "confidence", "evidence_refs", "hil_required"]
}

"""
'''
# llm/local_llm_PoC.py
"""
Dummy local LLM PoC for development.
Provides async generate(prompt) -> JSON string.
"""

import json
import asyncio
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class DummyLocalLLM:
    def __init__(self, model_path: str = None):
        self.model_path = model_path
        logger.info(f"[DummyLocalLLM] model_path: {self.model_path}")

    async def generate(self, prompt: str) -> str:
        """
        Simulated async generation. Returns a JSON string compatible with output_schema.json.
        In real usage, call llama.cpp/MLC-LLM wrapper (async) here.
        """
        # simulate latency
        await asyncio.sleep(0.05)
        # produce predictable mock output (ensure evidence_refs present)
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
                    "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                }
            ],
            "hil_required": False
        }
        return json.dumps(parsed)


'''def generate(self, prompt: str) -> str:
    # 단순히 프롬프트를 echo 하는 PoC 예시
    return '{"summary": "모의 요약", "attack_mapping": ["모름"], "recommended_actions": ["모름"], "confidence": 0.5, "hil_required": false}'
'''