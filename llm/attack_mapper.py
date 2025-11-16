"""
MITRE ATT&CK 기반 매핑 엔진
- 로그/증거에서 키워드 + 정규표현식 기반 탐지
- confidence = 규칙 점수 + LLM confidence
"""
import json
import re
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "attack_db" / "enterprise_techniques.json"

KEYWORD_RULES = {
    r"failed login|authentication failed|brute.*force": "T1110",
    r"powershell|execution policy": "T1059",
    r"mimikatz|credential dump": "T1003",
    r"sql injection|db error": "T1190",
    r"exfil": "T1041",
}

class AttackMapper:
    def __init__(self):
        self.db = json.loads(DB_PATH.read_text(encoding="utf-8"))

    def get_by_id(self, tid: str):
        return next((i for i in self.db if i["id"] == tid), None)

    def map(self, event_text: str, evidences: list):
        text = event_text.lower() + " ".join(
            e.get("snippet", "").lower() for e in evidences
        )

        matched = []
        for pat, tid in KEYWORD_RULES.items():
            if re.search(pat, text):
                info = self.get_by_id(tid)
                matched.append({
                    "id": tid,
                    "name": info.get("name") if info else tid,
                    "score": 1.0  # 기본 점수
                })

        return matched
