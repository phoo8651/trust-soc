# server/app/llm/attack_mapper.py
import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class AttackMapper:
    STATIC_WEIGHT = 0.7
    LLM_WEIGHT = 0.3

    def __init__(self) -> None:
        self.tech_index: Dict[str, Dict[str, Any]] = {}
        self._load_mitre_db()

        self.rule_priority = {
            "high": 0.05,
            "medium": 0.03,
            "low": 0.01,
        }

        self.allowlist = {"T1110.001": True}
        self.denylist = {}

        # [수정] 규칙 대폭 추가
        self.rules: List[Dict[str, Any]] = [
            # 1. SSH Brute Force
            {
                "id": "T1110.001",
                "name": "Password Brute Force",
                "severity": "high",
                "confidence": 0.80,
                "patterns": [
                    r"failed ssh",
                    r"ssh login failed",
                    r"password authentication failed",
                    r"invalid user",
                ],
            },
            # 2. Scheduled Task
            {
                "id": "T1053.005",
                "name": "Scheduled Task",
                "severity": "medium",
                "confidence": 0.65,
                "patterns": [
                    r"schtasks",
                    r"scheduled task",
                ],
            },
            # 3. Web Shell
            {
                "id": "T1505.003",
                "name": "Web Shell",
                "severity": "high",
                "confidence": 0.85,
                "patterns": [
                    r"webshell",
                    r"\.php\?cmd=",
                    r"cmd\.exe /c",
                ],
            },
            # 4. [NEW] RCE / Reverse Shell (Unix Shell)
            {
                "id": "T1059.004",
                "name": "Command and Scripting Interpreter: Unix Shell",
                "severity": "critical",
                "confidence": 0.95,
                "patterns": [
                    r"/bin/bash",
                    r"/bin/sh",
                    r"/dev/tcp/",  # Bash Reverse Shell
                    r"nc\s+.*-e",  # Netcat Execute
                    r"exec\s+5<>/dev/tcp",
                    r"python.*import\s+socket.*connect",
                    r"curl\s+.*\|\s*bash",  # Pipe to bash
                ],
            },
            # 5. [NEW] SQL Injection (Public-Facing Application Exploit)
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application (SQLi)",
                "severity": "high",
                "confidence": 0.90,
                "patterns": [
                    r"sqlmap",
                    r"union.*select",
                    r"information_schema",
                    r"benchmark\(",
                    r"sleep\(\d+\)",
                    r"or\s+1=1",
                    r"select\s+.*\s+from",
                ],
            },
        ]

    def _load_mitre_db(self) -> None:
        # 경로 수정 (현재 파일 위치 기준)
        base_dir = Path(__file__).resolve().parent
        # attack_db 폴더가 같은 레벨에 있다고 가정
        path = base_dir / "attack_db" / "enterprise_techniques.json"

        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for item in data:
                    t_id = item.get("id")
                    if t_id:
                        self.tech_index[t_id] = {
                            "description": item.get("description", ""),
                            "examples": item.get("examples", []),
                            "related_techniques": item.get("related_techniques", []),
                            "platforms": item.get("platforms", []),
                            "detection_hints": item.get("detection_hints", []),
                        }
                logger.info(
                    "[AttackMapper] Loaded %d MITRE techniques", len(self.tech_index)
                )
            except Exception as e:
                logger.error("[AttackMapper] JSON Load Failed: %s", e)
        else:
            logger.warning("[AttackMapper] MITRE DB not found at %s", path)

    def _lookup_name(self, ttp_id: str, fallback: str) -> str:
        return self.tech_index.get(ttp_id, {}).get("name", fallback)

    def map(
        self,
        event_text: str,
        evidences: List[Dict[str, Any]],
        llm_suggestions: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:

        text = (event_text or "").lower()
        # Evidence의 snippet들도 매핑 대상에 포함
        snippets = " ".join(str(e.get("snippet", "")) for e in evidences).lower()
        combined = f"{text} {snippets}"

        results: Dict[str, Dict[str, Any]] = {}

        # --- (1) Static Rule Matching ---
        for rule in self.rules:
            # 정규식 매칭 확인
            matched = [p for p in rule["patterns"] if re.search(p, combined)]
            if not matched:
                continue

            if self.denylist.get(rule["id"], False):
                continue

            ttp_id = rule["id"]

            # 점수 계산 (기본 점수 + 매칭 패턴 수 보너스)
            conf = rule["confidence"] + (0.02 * (len(matched) - 1))
            conf = min(1.0, conf)

            results[ttp_id] = {
                "id": ttp_id,
                "name": self._lookup_name(ttp_id, rule["name"]),
                "severity": rule["severity"],
                "confidence": round(conf, 2),
                "matched_patterns": matched,
                "source": "static",
            }

        # --- (2) LLM Suggestions Merge (Optional) ---
        if llm_suggestions:
            for item in llm_suggestions:
                ttp_id = item.get("id")
                if not ttp_id:
                    continue

                if ttp_id not in results:
                    # LLM only
                    results[ttp_id] = {
                        "id": ttp_id,
                        "name": self._lookup_name(ttp_id, ttp_id),
                        "severity": "medium",
                        "confidence": 0.5,  # LLM 단독은 신뢰도 낮게 시작
                        "source": "llm",
                    }
                else:
                    # Hybrid Boost (Static + LLM 둘 다 탐지 시 점수 상향)
                    results[ttp_id]["confidence"] = min(
                        1.0, results[ttp_id]["confidence"] + 0.1
                    )
                    results[ttp_id]["source"] = "hybrid"

        # 결과 리스트 변환 및 정렬
        final = list(results.values())
        final.sort(key=lambda x: x["confidence"], reverse=True)

        return final
