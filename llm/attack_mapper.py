# llm/attack_mapper.py
"""
MITRE ATT&CK Hybrid 매핑 엔진
- Rule 기반 Static 매핑
- evidence 기반 confidence 보정
- LLM 보조 매핑 (fallback + hybrid boost)
- 화이트리스트/블랙리스트 정책
- severity 기반 priority 보정
- MITRE DB metadata enrich
"""

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

        # priority for confidence boost
        self.rule_priority = {
            "high": 0.05,
            "medium": 0.03,
            "low": 0.01,
        }

        # allow/deny lists
        self.allowlist = {
            "T1110.001": True,
        }
        self.denylist = {
            # 예: 특정 환경 오탐 제거용
            # "T1110": True,
        }

        self.rules: List[Dict[str, Any]] = [
            {
                "id": "T1110.001",
                "name": "Brute Force: Password Guessing",
                "severity": "high",
                "confidence": 0.80,
                "patterns": [
                    r"failed ssh",
                    r"ssh login failed",
                    r"password authentication failed",
                    r"invalid user",
                    r"too many authentication failures",
                    r"authentication failure",
                ],
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "severity": "medium",
                "confidence": 0.60,
                "patterns": [
                    r"brute force",
                    r"multiple failed login",
                    r"login attempt",
                ],
            },
            {
                "id": "T1053.005",
                "name": "Scheduled Task",
                "severity": "medium",
                "confidence": 0.65,
                "patterns": [
                    r"schtasks\.exe",
                    r"scheduled task",
                    r"task scheduler",
                    r"new task .* /ru system",
                    r"created new task",
                ],
            },
            {
                "id": "T1505.003",
                "name": "Web Shell",
                "severity": "high",
                "confidence": 0.70,
                "patterns": [
                    r"webshell",
                    r"web shell",
                    r"\.php\?cmd=",
                    r"cmd\.exe /c",
                    r"wget .* /tmp/",
                ],
            },
        ]

    def _load_mitre_db(self) -> None:
        base_dir = Path(__file__).resolve().parent
        candidates = [
            base_dir / "attack_db" / "enterprise_techniques.json",
            base_dir.parent / "llm" / "attack_db" / "enterprise_techniques.json",
        ]

        for path in candidates:
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
                    logger.info("[AttackMapper] Loaded %d MITRE techniques", len(self.tech_index))
                    return
                except Exception as e:
                    logger.error("[AttackMapper] Failed: %s", e)
                    return

        logger.warning("[AttackMapper] MITRE DB not found → no metadata")

    def _lookup_name(self, ttp_id: str, fallback: str) -> str:
        return self.tech_index.get(ttp_id, {}).get("name", fallback)

    def map(
        self,
        event_text: str,
        evidences: List[Dict[str, Any]],
        llm_suggestions: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:

        text = (event_text or "").lower()
        snippets = " ".join(str(e.get("snippet", "")) for e in evidences).lower()
        combined = f"{text} {snippets}"

        results: Dict[str, Dict[str, Any]] = {}

        # evidence bonus
        evidence_count = len(evidences)
        has_yara_hex = any(e.get("type") in ("yara", "hex") for e in evidences)

        evidence_bonus = min(0.15, 0.05 * evidence_count)
        if has_yara_hex:
            evidence_bonus += 0.05

        # --- (1) Static 매핑 ---
        for rule in self.rules:
            matched = [p for p in rule["patterns"] if re.search(p, combined)]
            if not matched:
                continue

            if self.denylist.get(rule["id"], False):
                continue

            base = rule["confidence"]
            pattern_bonus = 0.03 * (len(matched) - 1)
            conf = base + evidence_bonus + pattern_bonus

            # severity priority boost
            conf += self.rule_priority.get(rule["severity"], 0.0)

            # allowlist boost
            if self.allowlist.get(rule["id"], False):
                conf += 0.05

            ttp_id = rule["id"]
            conf = round(min(1.0, conf), 2)

            results[ttp_id] = {
                "id": ttp_id,
                "name": self._lookup_name(ttp_id, rule["name"]),
                "severity": rule["severity"],
                "confidence": conf,
                "matched_patterns": matched,
                "source": "static",
            }

        # --- (2) LLM fallback 보조 ---
        if llm_suggestions:
            for item in llm_suggestions:
                ttp_id = item["id"]
                llm_conf = item.get("confidence", 0.5)

                if self.denylist.get(ttp_id, False):
                    continue

                # LLM only
                if ttp_id not in results:
                    results[ttp_id] = {
                        "id": ttp_id,
                        "name": self._lookup_name(ttp_id, ttp_id),
                        "severity": "medium",
                        "confidence": round(llm_conf * 0.8, 2),
                        "matched_patterns": [],
                        "source": "llm_fallback",
                    }
                else:
                    # Hybrid confidence
                    sc = results[ttp_id]["confidence"]
                    conf = sc * self.STATIC_WEIGHT + llm_conf * self.LLM_WEIGHT
                    results[ttp_id]["confidence"] = round(min(1.0, conf), 2)
                    results[ttp_id]["source"] = "hybrid"

        # enrich metadata
        final = []
        for r in results.values():
            meta = self.tech_index.get(r["id"], {})
            r["tech_meta"] = meta
            final.append(r)

        final.sort(key=lambda x: x["confidence"], reverse=True)
        return final
