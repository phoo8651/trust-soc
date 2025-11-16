# tests/test_analyze_strict.py > 스키마 에러 테스트
from fastapi.testclient import TestClient
from advisor_api import app

client = TestClient(app)

def test_analyze_missing_event_text_fails():
    payload = {
        "yara_hits": [],
        "hex_matches": []
    }
    resp = client.post("/analyze", json=payload)
    assert resp.status_code == 422


def test_analyze_invalid_event_text_type():
    payload = {
        "event_text": 12345,  # invalid type
        "yara_hits": [],
        "hex_matches": []
    }
    resp = client.post("/analyze", json=payload)
    assert resp.status_code == 422
