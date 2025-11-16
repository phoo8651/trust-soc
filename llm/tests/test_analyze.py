# tests/test_analyze.py > 기본 기능 테스트

import json
from fastapi.testclient import TestClient
from advisor_api import app

client = TestClient(app)

def test_analyze_basic_response():
    payload = {
        "event_text": "Failed SSH login from 192.168.0.10",
        "yara_hits": [],
        "hex_matches": []
    }

    resp = client.post("/analyze", json=payload)
    assert resp.status_code == 200

    data = resp.json()

    # Required Fields
    assert "summary" in data
    assert "attack_mapping" in data
    assert "recommended_actions" in data
    assert "confidence" in data
    assert "evidence_refs" in data
    assert "hil_required" in data

    assert isinstance(data["summary"], str)
    assert isinstance(data["attack_mapping"], list)
    assert isinstance(data["recommended_actions"], list)
    assert isinstance(data["confidence"], float)
    assert isinstance(data["evidence_refs"], list)
    assert isinstance(data["hil_required"], bool)

    # Evidence ref format validation
    if data["evidence_refs"]:
        ref = data["evidence_refs"][0]
        for key in ["type", "ref_id", "source", "offset", "length", "sha256"]:
            assert key in ref
