# llm/prompt_manager.py
import os
from typing import Dict

class PromptManager:
    """
    LLM 프롬프트 템플릿을 관리하는 클래스
    - 템플릿 캐싱
    """

    def __init__(self, base_path: str = "llm/prompt_templates"):
        self.base_path = base_path
        self.cache: Dict[str, str] = {}

    def load_prompt(self, name: str) -> str:
        """name='summary' -> summary_prompt.txt 로드"""
        if name in self.cache:
            return self.cache[name]

        filename = f"{name}_prompt.txt"
        file_path = os.path.join(self.base_path, filename)

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Prompt not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.cache[name] = content
        return content

    def list_prompts(self):
        """사용 가능 프롬프트 목록"""
        if not os.path.exists(self.base_path):
            return []
        return [
            f.replace("_prompt.txt", "")
            for f in os.listdir(self.base_path)
            if f.endswith("_prompt.txt")
        ]

    def reload_prompts(self):
        """캐시 초기화"""
        self.cache.clear()
        print("[PromptManager] Cache cleared.")
