"""
MITRE ATT&CK 기반 매핑 엔진 - 강화 버전
- 키워드/정규표현식 기반 탐지 개선
- SSH 브루트포스 등 패턴 확장
- confidence 기반 우선 매핑
"""
import re

class AttackMapper:
    def __init__(self):
        self.rules = [
            {
                "id": "T1110.001",
                "name": "Brute Force - Password Guessing",
                "patterns": [
                    r"failed ssh",
                    r"ssh login failed",
                    r"authentication failed",
                    r"failed password",
                    r"password authentication failed",
                    r"invalid user",
                    r"too many authentication failures",
                    r"brute",
                ],
                "confidence": 0.85,
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "patterns": [
                    r"ssh",
                    r"login",
                    r"password",
                ],
                "confidence": 0.60,
            }
        ]

    def map(self, event_text: str, evidences: list):
        results = []
        text = event_text.lower()

        for rule in self.rules:
            for p in rule["patterns"]:
                if re.search(p, text):
                    results.append({
                        "ttp_id": rule["id"],
                        "confidence": rule["confidence"]
                    })
                    break

        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results
