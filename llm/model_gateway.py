# llm_advisor/model_gateway.py
import os
import time
import asyncio
import json
from typing import Optional
import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from local_llm_PoC import DummyLocalLLM

# 간단한 circuit breaker
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, reset_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.fail_count = 0
        self.opened_at = None

    def record_failure(self):
        self.fail_count += 1
        if self.fail_count >= self.failure_threshold:
            self.opened_at = time.time()

    def record_success(self):
        self.fail_count = 0
        self.opened_at = None

    def is_open(self) -> bool:
        if self.opened_at is None:
            return False
        if (time.time() - self.opened_at) > self.reset_timeout:
            # auto reset
            self.fail_count = 0
            self.opened_at = None
            return False
        return True

# rate limiter (async)
class AsyncRateLimiter:
    def __init__(self, max_concurrent: int = 4):
        self._sem = asyncio.Semaphore(max_concurrent)

    async def __aenter__(self):
        await self._sem.acquire()
    async def __aexit__(self, exc_type, exc, tb):
        self._sem.release()

# Gateway
class ModelGateway:
    def __init__(self,
                 external_api_url: Optional[str] = None,
                 external_api_key: Optional[str] = None,
                 local_model_path: Optional[str] = None,
                 allowlist: Optional[list] = None):
        self.external_api_url = external_api_url or os.getenv("EXTERNAL_API_URL")
        self.external_api_key = external_api_key or os.getenv("EXTERNAL_API_KEY")
        self.allowlist = allowlist or os.getenv("ALLOWED_MODELS", "gpt-4o-mini").split(",")
        self.circuit = CircuitBreaker(int(os.getenv("CB_FAILURE_THRESHOLD", 3)),
                                      int(os.getenv("CB_RESET_TIMEOUT", 60)))
        self.rate_limiter = AsyncRateLimiter(max_concurrent=int(os.getenv("GATEWAY_MAX_CONC", 4)))
        self.local = DummyLocalLLM(model_path=local_model_path)
        self.timeout = int(os.getenv("GATEWAY_TIMEOUT", 15))

    async def _call_external(self, prompt: str, model: str = None) -> str:
        if self.circuit.is_open():
            raise RuntimeError("External circuit open")
        model = model or self.allowlist[0]
        # 간단한 sync HTTP call을 async에서 실행
        def do_call():
            headers = {"Authorization": f"Bearer {self.external_api_key}"} if self.external_api_key else {}
            payload = {"model": model, "messages": [{"role": "user", "content": prompt}]}
            resp = requests.post(self.external_api_url, headers=headers, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, do_call)
        # 외부 응답에서 텍스트 추출 (OpenAI 형식 가정)
        choices = result.get("choices", [])
        text = ""
        if choices:
            text = choices[0].get("message", {}).get("content", "") or choices[0].get("text", "")
        return text

    async def _call_local(self, prompt: str) -> str:
        # local generate는 sync로 구현되어 있음. run_in_executor로 감쌀 것
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.local.generate, prompt)

    async def generate(self, prompt: str, prefer_external: bool = True) -> str:
        """메인 호출 함수: 우선 외부 -> 실패 시 로컬 폴백"""
        async with self.rate_limiter:
            if prefer_external and self.external_api_url:
                try:
                    text = await self._call_external(prompt)
                    self.circuit.record_success()
                    return text
                except Exception as e:
                    # 기록 후 폴백
                    self.circuit.record_failure()
                    # 로그 남기기
                    print(f"[gateway] external failed: {e}; falling back to local")
            # 폴백
            try:
                text = await self._call_local(prompt)
                return text
            except Exception as e:
                print(f"[gateway] local failed: {e}")
                raise

# 사용 예시:
# gateway = ModelGateway(external_api_url="https://api.openai.com/v1/chat/completions", external_api_key="sk-...", local_model_path="models/ggml.bin")
# text = await gateway.generate("hello")
