import os
import logging
from typing import Dict, Optional
from pathlib import Path  # [New] pathlib 사용

logger = logging.getLogger("prompt_manager")


class PromptManager:
    """
    LLM 프롬프트 템플릿을 관리하는 클래스
    """

    def __init__(self, base_path: Optional[str] = None):
        # 경로가 주어지지 않으면, 현재 파일 위치 기준으로 templates 폴더를 찾음
        if base_path is None:
            # __file__ : 현재 소스코드의 절대 경로
            # .parent  : 현재 소스코드의 디렉토리 (app/llm)
            self.base_path = Path(__file__).resolve().parent / "prompt_templates"
        else:
            self.base_path = Path(base_path)

        self.cache: Dict[str, str] = {}

        # 경로 디버깅용 로그 (경로가 꼬였을 때 확인용)
        # logger.info(f"PromptManager initialized at: {self.base_path}")

    def load_prompt(self, name: str) -> str:
        """
        name='summary' -> summary_prompt.txt 로드
        """
        if name in self.cache:
            return self.cache[name]

        filename = f"{name}_prompt.txt"
        file_path = self.base_path / filename  # Path 객체는 / 연산자로 경로 결합 가능

        if not file_path.exists():
            raise FileNotFoundError(f"Prompt not found: {file_path}")

        # encoding='utf-8' 명시 권장
        with file_path.open("r", encoding="utf-8") as f:
            content = f.read()

        self.cache[name] = content
        return content

    def list_prompts(self):
        """사용 가능 프롬프트 목록"""
        if not self.base_path.exists():
            return []

        return [
            f.name.replace("_prompt.txt", "")
            for f in self.base_path.glob("*_prompt.txt")
        ]
