# tests/test_advisor_flow.py > end-to-end 흐름 + HIL 조건 테스트
from fastapi.testclient import TestClient
from advisor_api import app

client = TestClient(app)

def test_full_flow_hil_and_confidence_logic():
    payload = {
        "event_text": "Suspicious PowerShell execution detected: base64 command",
        "yara_hits": [],
        "hex_matches": []
    }

    resp = client.post("/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    # Basic schema checks
    for key in [
        "summary",
        "attack_mapping",
        "recommended_actions",
        "confidence",
        "evidence_refs",
        "hil_required"
    ]:
        assert key in data

    # Evidence refs format check
    for ref in data["evidence_refs"]:
        for key in ["type", "ref_id", "source", "offset", "length", "sha256"]:
            assert key in ref

    # Confidence ranges must be valid
    assert 0 <= data["confidence"] <= 1

    # HIL Required Logic: if confidence < 0.8 -> hil_required = True
    # (기본 guardrail 규칙)
    if data["confidence"] < 0.8:
        assert data["hil_required"] is True
    else:
        assert data["hil_required"] in (False, True)  # auto approve or human approve
