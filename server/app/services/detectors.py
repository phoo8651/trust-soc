import os
import re
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger("detectors")


class DetectorService:
    def __init__(self, rules_dir: str = None):
        # 기본 경로는 /app/app/rules (Docker 내부 기준)
        if rules_dir is None:
            base_dir = Path(__file__).resolve().parent.parent  # app/
            rules_dir = base_dir / "rules"

        self.rules_dir = Path(rules_dir)
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        """YAML 파일에서 룰을 로딩하고 정규식을 컴파일합니다."""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            return

        loaded_count = 0
        for rule_file in sorted(self.rules_dir.glob("*.yaml")):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    rule_def = yaml.safe_load(f)

                    # 정규식 패턴 미리 컴파일 (성능 최적화)
                    if "patterns" in rule_def:
                        rule_def["_compiled_patterns"] = [
                            re.compile(p, re.IGNORECASE) for p in rule_def["patterns"]
                        ]

                    self.rules.append(rule_def)
                    loaded_count += 1
            except Exception as e:
                logger.error(f"Failed to load rule {rule_file}: {e}")

        logger.info(f"✅ Loaded {loaded_count} detection rules from {self.rules_dir}")

    def run_all(self, record: dict) -> dict:
        """로드된 룰을 기반으로 탐지 수행"""
        raw = record.get("raw_line", "").lower()
        record_tags = set(record.get("tags", []))

        max_score = 0.0
        details = []

        for rule in self.rules:
            matched = False

            # 1. 태그 매칭 (Optional)
            if "tags" in rule:
                # 룰에 정의된 태그 중 하나라도 레코드 태그에 포함되면 매칭
                if not set(rule["tags"]).intersection(record_tags):
                    continue  # 태그가 안 맞으면 이 룰은 건너뜀 (AND 조건이 아닌 필터링 용도라면 로직 조정 가능)
                    # 여기서는 'tags' 필드가 있으면 해당 태그가 있을 때만 검사하는 로직으로 구현 예시
                    # 만약 단순히 키워드/패턴 매칭만 원하면 이 블록 제거/수정 가능
                    pass
                else:
                    # 태그가 매칭되면 바로 탐지 성공으로 간주할 수도 있고, 아래 패턴 검사를 추가로 할 수도 있음
                    matched = True

            # 2. 키워드 매칭 (단순 문자열 포함)
            if not matched and "keywords" in rule:
                for kw in rule["keywords"]:
                    if kw.lower() in raw:
                        matched = True
                        break

            # 3. 정규식 패턴 매칭
            if not matched and "_compiled_patterns" in rule:
                for pattern in rule["_compiled_patterns"]:
                    if pattern.search(raw):
                        matched = True
                        break

            # 매칭 성공 시 결과 추가
            if matched:
                score = float(rule.get("score", 0.0))
                max_score = max(max_score, score)
                details.append(
                    {
                        "type": rule.get("type", "rule"),
                        "rule_id": rule.get("rule_id"),
                        "desc": rule.get("description"),
                    }
                )

        return {"max_score": max_score, "details": details}
