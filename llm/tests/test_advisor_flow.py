#통합 테스트
from fastapi.testclient import TestClient
from advisor_api import app

client = TestClient(app)

def test_analyze_and_get():
    res = client.post("/analyze", json={"dummy": "data"})
    assert res.status_code == 200
    inc_id = res.json()["incident_id"]

    res = client.get(f"/incidents/{inc_id}")
    data = res.json()
    assert "summary" in data
    assert "confidence" in data
    assert "evidence_refs" in data
