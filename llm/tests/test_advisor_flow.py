# tests/test_advisor_flow.py

import pytest
from fastapi.testclient import TestClient
from llm.advisor_api import app


client = TestClient(app)


def test_ssh_bruteforce_auto_approved():
    payload = {
        "event_text": "Multiple failed SSH login from 10.0.0.5 for user root",
        "evidences": [
            {
                "type": "raw",
                "ref_id": "E1",
                "source": "auth.log",
                "offset": 0,
                "length": 120,
                "sha256": "abcdef",
                "snippet": "Failed SSH login from 10.0.0.5 for user root"
            }
        ]
    }

    res = client.post("/analyze", json=payload)
    assert res.status_code == 200

    data = res.json()
    print("TEST SSH:", data)

    assert data["attack_mapping"] == ["T1110.001"]
    assert data["confidence"] >= 0.8
    assert data["hil_required"] is False
    assert data["status"] == "approved"


def test_scheduled_task_requires_hil():
    payload = {
        "event_text": "schtasks.exe created new task /ru system",
        "evidences": [
            {
                "type": "raw",
                "ref_id": "EV123",
                "source": "system.log",
                "offset": 0,
                "length": 80,
                "sha256": "abcdef",
                "snippet": "schtasks.exe created new task /ru system"
            }
        ]
    }

    res = client.post("/analyze", json=payload)
    assert res.status_code == 200

    data = res.json()
    print("TEST SCHEDULED TASK:", data)

    assert data["attack_mapping"] == ["T1053.005"]
    assert 0.5 <= data["confidence"] < 0.8
    assert data["hil_required"] is True
    assert data["status"] == "pending_approval"


def test_ftp_always_hil():
    payload = {
        "event_text": "FTP login attempt from 192.168.0.10",
        "evidences": [
            {
                "type": "raw",
                "ref_id": "E2",
                "source": "ftp.log",
                "offset": 0,
                "length": 100,
                "sha256": "123456",
                "snippet": "FTP login attempt from 192.168.0.10"
            }
        ]
    }

    res = client.post("/analyze", json=payload)
    assert res.status_code == 200

    data = res.json()
    print("TEST FTP:", data)

    assert data["attack_mapping"] == ["UNKNOWN"]
    assert data["hil_required"] is True
    assert data["status"] == "pending_approval"
