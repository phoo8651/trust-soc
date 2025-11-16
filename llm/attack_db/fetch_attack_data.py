"""
MITRE ATT&CK DB 자동 다운로드 + 정규화 스크립트
필드 최소화: id, name, description, platforms, detection hints
"""
import requests
import json
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
SAVE = Path(__file__).resolve().parent / "enterprise_techniques.json"

def fetch():
    res = requests.get(URL, timeout=10)
    data = res.json()
    result = []

    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            ext = obj.get("external_references", [{}])[0]
            result.append({
                "id": ext.get("external_id"),
                "name": obj.get("name"),
                "description": obj.get("description", ""),
                "platforms": obj.get("x_mitre_platforms", []),
                "examples": [],
                "related_techniques": obj.get("x_mitre_is_subtechnique", False),
                "detection_hints": obj.get("x_mitre_detection", "")
            })

    SAVE.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"MITRE Techniques Saved: {len(result)} → {SAVE}")

if __name__ == "__main__":
    fetch()
