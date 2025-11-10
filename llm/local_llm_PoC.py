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
    def __init__(self, model_path: str = None):
        self.model_path = model_path
        print(f"[DummyLocalLLM] model_path: {self.model_path}")
        
    def generate(self, prompt: str) -> str:
        return json.dumps({
        "summary": "모의 요약",
        "attack_mapping": ["모름"],
        "recommended_actions": ["모름"],
        "confidence": 0.5,
        "evidence_refs": [{"type":"raw","ref_id":"log_001","source":"auth.log","offset":0,"length":150,"sha256":"abc123"}],
        "hil_required": False
    })

    '''def generate(self, prompt: str) -> str:
        # 단순히 프롬프트를 echo 하는 PoC 예시
        return '{"summary": "모의 요약", "attack_mapping": ["모름"], "recommended_actions": ["모름"], "confidence": 0.5, "hil_required": false}'
    '''