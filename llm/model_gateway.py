# llm/model_gateway.py
import os
import time
import asyncio
import requests
import json
from llm.local_llm_PoC import DummyLocalLLM, LocalLlamaLLM
from llm.masking.data_masking import validate_masked


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
            self.fail_count = 0
            self.opened_at = None
            return False
        return True


class AsyncRateLimiter:
    def __init__(self, max_concurrent: int = 4):
        self._sem = asyncio.Semaphore(max_concurrent)

    async def __aenter__(self):
        await self._sem.acquire()

    async def __aexit__(self, exc_type, exc, tb):
        self._sem.release()


class ModelGateway:
    """
    외부 API → 로컬 LLM 폴백 구조
    """
    def __init__(self, external_api_url=None, external_api_key=None, local_model_path=None, use_real_llm=False):
        self.external_api_url = external_api_url or os.getenv("EXTERNAL_API_URL")
        self.external_api_key = external_api_key or os.getenv("EXTERNAL_API_KEY")
        self.allowlist = os.getenv("ALLOWED_MODELS", "gpt-4o-mini").split(",")
        self.use_fake_external = bool(int(os.getenv("USE_FAKE_EXTERNAL", "0")))
        self.circuit = CircuitBreaker()
        self.rate_limiter = AsyncRateLimiter()
        self.timeout = int(os.getenv("GATEWAY_TIMEOUT", 15))

        # LLM 선택
        if use_real_llm or bool(int(os.getenv("USE_REAL_LLM", "0"))):
            self.local = LocalLlamaLLM(model_path=local_model_path)
        else:
            self.local = DummyLocalLLM(model_path=local_model_path)

    async def _call_external(self, prompt: str, model: str = None) -> str:
        if self.use_fake_external:
            await asyncio.sleep(0.2)
            return json.dumps({
                "summary": "모의 요약",
                "attack_mapping": ["T9999"],
                "recommended_actions": ["모의 조치"],
                "confidence": 0.9,
                "hil_required": False
            })

        if self.circuit.is_open():
            raise RuntimeError("External circuit open")

        model = model or self.allowlist[0]

        def do_call():
            headers = {"Authorization": f"Bearer {self.external_api_key}"} if self.external_api_key else {}
            payload = {"model": model, "messages": [{"role": "user", "content": prompt}]}
            resp = requests.post(self.external_api_url, headers=headers, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, do_call)

        choices = result.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "") or choices[0].get("text", "")
        return ""

    async def _call_local(self, prompt: str) -> str:
        # 동기 LLM도 항상 await 가능하도록 run_in_executor로 감싸기
        loop = asyncio.get_event_loop()
        if asyncio.iscoroutinefunction(self.local.generate):
            return await self.local.generate(prompt)
        else:
            return await loop.run_in_executor(None, self.local.generate, prompt)

    async def generate(self, prompt: str, prefer_external: bool = True) -> str:
        async with self.rate_limiter:
            if not validate_masked(prompt):
                raise ValueError("Prompt failed masking validation")

            # 외부 API 우선
            if prefer_external and self.external_api_url:
                try:
                    text = await self._call_external(prompt)
                    self.circuit.record_success()
                    return text
                except Exception as e:
                    self.circuit.record_failure()
                    print(f"[gateway] External call failed: {e}. Falling back to local.")

            # 로컬 LLM
            try:
                text = await self._call_local(prompt)
                return text
            except Exception as e:
                print(f"[gateway] Local model failed: {e}")
                raise
