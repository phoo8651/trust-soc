#llm\prompt_manager.py
import os
from typing import Dict

class PromptManager:
    """
    LLM 프롬프트 템플릿을 관리하는 클래스.
    지정된 디렉토리에서 prompt 파일을 읽어오고, 캐싱 처리함.
    """

    def __init__(self, base_path: str = "llm/prompt_templates"):
        """
        base_path: 프롬프트 템플릿이 저장된 기본 폴더 경로
        """
        self.base_path = base_path
        self.cache: Dict[str, str] = {}

    def load_prompt(self, name: str) -> str:
        """
        지정한 이름의 프롬프트 템플릿을 로드함.
        예: name="summary" → llm/prompt_templates/summary_prompt.txt
        """
        # 캐시되어 있으면 바로 반환
        if name in self.cache:
            return self.cache[name]

        # 파일명 매핑 규칙
        filename = f"{name}_prompt.txt"
        file_path = os.path.join(self.base_path, filename)

        # 파일 존재 확인
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Prompt not found: {file_path}")

        # 파일 읽기
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # 캐시에 저장 후 반환
        self.cache[name] = content
        return content

    def list_prompts(self):
        """
        현재 디렉토리에 존재하는 모든 프롬프트 파일 목록 반환
        """
        if not os.path.exists(self.base_path):
            return []

        files = os.listdir(self.base_path)
        return [f.replace("_prompt.txt", "") for f in files if f.endswith("_prompt.txt")]

    def reload_prompts(self):
        """
        캐시 초기화
        """
        self.cache.clear()
        print("[PromptManager] Cache cleared.")
