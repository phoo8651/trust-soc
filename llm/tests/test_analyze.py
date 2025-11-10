import pytest
from fastapi.testclient import TestClient
from llm.advisor_api import app

client = TestClient(app)


# ===============================
# ✅ 정상 입력 (Valid Case)
# ===============================
def test_valid_case_1():
    payload = {
        "incident_id": "demo-001",
        "event_text": "Suspicious network scan detected from external IP.",
        "evidences": [
            {"type": "log", "ref_id": "e1", "snippet": "Nmap scan attempt detected"}
        ]
    }

    response = client.post("/analyze", json=payload)
    print("Response JSON:", response.json())

    assert response.status_code == 200
    data = response.json()

    assert data["incident_id"] == "demo-001"
    assert "summary" in data
    assert data["severity"] == "Low"
    assert "attack_mapping" in data
    assert "recommended_actions" in data
    assert isinstance(data["evidences"], list)
    assert data["evidences"][0]["ref_id"] == "e1"


# ===============================
# ⚠️ 비정상 입력 (Invalid Schema)
# ===============================
@pytest.mark.parametrize("bad_payload", [
    {},  # 필수 필드 누락
    {"incident_id": "x", "event_text": 123, "evidences": []},  # 타입 불일치
    {"incident_id": "x", "event_text": "ok"},  # evidences 누락
])
def test_invalid_request_schema(bad_payload):
    response = client.post("/analyze", json=bad_payload)
    print("Invalid case response:", response.json())
    assert response.status_code == 422  # FastAPI 자동 스키마 검증 실패


# ===============================
# 🧠 LLM 처리 중 예외 발생 시 (Mock)
# ===============================
def test_internal_error(monkeypatch):
    # LLM 내부 analyze_incident를 강제로 예외 발생시킴
    from llm import advisor_api

    async def mock_fail(*args, **kwargs):
        raise RuntimeError("LLM internal failure")

    monkeypatch.setattr(advisor_api.llm_engine, "analyze_incident", mock_fail)

    payload = {
        "incident_id": "demo-err",
        "event_text": "Testing exception handling",
        "evidences": [{"type": "log", "ref_id": "e99"}]
    }

    response = client.post("/analyze", json=payload)
    print("Error case response:", response.json())
    assert response.status_code == 500
    assert "LLM internal failure" in response.json()["detail"]
