#llm/tests/test_analyze_strict.py

import pytest
from fastapi.testclient import TestClient
from llm.advisor_api import app

client = TestClient(app)

# ✅ 공통 유효 기본 evidence
valid_evidence = {
    "type": "raw",
    "ref_id": "log001",
    "source": "auth.log",
    "offset": 10,
    "length": 200,
    "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "snippet": "Failed login attempt"
}

# -------------------------
# 유효 케이스 5개
# -------------------------
valid_cases = [
    {
        "name": "Valid Case 1 - 기본 케이스",
        "payload": {
            "incident_id": "valid_001",
            "event_text": "Suspicious login detected",
            "evidences": [valid_evidence]
        },
        "expected": 200
    },
    {
        "name": "Valid Case 2 - 다른 type(raw)",
        "payload": {
            "incident_id": "valid_002",
            "event_text": "Network anomaly found",
            "evidences": [{**valid_evidence, "type": "hex"}]
        },
        "expected": 200
    },
    {
        "name": "Valid Case 3 - 길이 큰 offset",
        "payload": {
            "incident_id": "valid_003",
            "event_text": "Multiple failed SSH logins",
            "evidences": [{**valid_evidence, "offset": 9999}]
        },
        "expected": 200
    },
    {
        "name": "Valid Case 4 - 여러 evidences",
        "payload": {
            "incident_id": "valid_004",
            "event_text": "Phishing attempt detected",
            "evidences": [
                valid_evidence,
                {**valid_evidence, "ref_id": "log002", "type": "yara"}
            ]
        },
        "expected": 200
    },
    {
        "name": "Valid Case 5 - sha256 대문자 허용",
        "payload": {
            "incident_id": "valid_005",
            "event_text": "Unusual port scan",
            "evidences": [{**valid_evidence, "sha256": "ABCDEF123456ABCDEF"}]
        },
        "expected": 200
    },
]

# -------------------------
# 무효 케이스 5개
# -------------------------
invalid_cases = [
    {
        "name": "Invalid Case 1 - type 잘못됨",
        "payload": {
            "incident_id": "invalid_001",
            "event_text": "Invalid type",
            "evidences": [{**valid_evidence, "type": "invalid_type"}]
        },
        "expected": 422
    },
    {
        "name": "Invalid Case 2 - 필드 누락(ref_id 없음)",
        "payload": {
            "incident_id": "invalid_002",
            "event_text": "Missing ref_id",
            "evidences": [{k: v for k, v in valid_evidence.items() if k != "ref_id"}]
        },
        "expected": 422
    },
    {
        "name": "Invalid Case 3 - offset 정수 아님",
        "payload": {
            "incident_id": "invalid_003",
            "event_text": "Offset not int",
            "evidences": [{**valid_evidence, "offset": "zero"}]
        },
        "expected": 422
    },
    {
        "name": "Invalid Case 4 - sha256 형식 잘못됨",
        "payload": {
            "incident_id": "invalid_004",
            "event_text": "Bad sha256",
            "evidences": [{**valid_evidence, "sha256": "12345"}]
        },
        "expected": 422
    },
    {
        "name": "Invalid Case 5 - evidences 빈 리스트",
        "payload": {
            "incident_id": "invalid_005",
            "event_text": "No evidence",
            "evidences": []
        },
        "expected": 422
    },
]


# -------------------------
# 테스트 실행
# -------------------------
@pytest.mark.parametrize("case", valid_cases + invalid_cases)
def test_analyze_strict(case):
    print(f"\n▶ Running: {case['name']}")
    response = client.post("/analyze", json=case["payload"])
    print(f"Response ({case['name']}):", response.status_code, response.json())
    assert response.status_code == case["expected"], f"{case['name']} failed: got {response.status_code}"
