# llm/locol_llm.PoC.py
from llama_cpp import Llama


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
  "summary": "",
  "confidence_explanation": "",
  "evidence_refs_used": []
}
"""

print("🧠 LLM 응답 생성 중...")
response = llm(prompt=prompt, max_tokens=256, temperature=0.7, stop=["</s>"])
print(response["choices"][0]["text"])

import json

class DummyLocalLLM:
    def generate(self, prompt: str) -> str:
        # prompt를 받아서 JSON 문자열을 리턴 (실제 LLM 흉내)
        fake = {
            "summary": "Spring4Shell 의심 공격 발생",
            "attack_mapping": ["T1190 - Exploit Public-Facing Application"],
            "recommended_actions": ["WAF 룰 강화", "취약 버전 패치 적용"],
            "confidence": 0.88,
            "evidence_refs": [
                {
                    "type": "yara",
                    "ref_id": "yara_001",
                    "source": "web_log",
                    "offset": 123,
                    "length": 256,
                    "sha256": "aabbccddeeff1122334455",
                    "rule_id": "SPRING4SHELL_WEB"
                }
            ],
            "hil_required": False
        }
        return json.dumps(fake, ensure_ascii=False)