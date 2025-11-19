# llm/exp/runner.py -> prompt>response 자동 실험 스크립트
import json
from typing import List, Callable

def run_experiment(cases: List[dict], prompt_variants: List[str], call_llm: Callable):
    results = []
    for case in cases:
        for i, tpl in enumerate(prompt_variants):
            prompt = tpl.format(**case)
            raw = call_llm(prompt)
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = {"error": "invalid_json", "raw": raw}
            results.append({"case": case.get("id"), "variant": i, "parsed": parsed})
    return results
