# llm_advisor/test_models.py
import pytest
from llm.advisor_api import IncidentOutput, EvidenceRef
from pydantic import ValidationError 



def test_evidence_ref_valid():
    e = EvidenceRef(
        type="raw",
        ref_id="log_001",
        source="auth.log",
        offset=0,
        length=10,
        sha256="abc123def456...",
        rule_id=None
    )
    assert e.type == "raw"

def test_evidence_ref_invalid_type():
    # type이 enum에 맞지 않으면 ValidationError
    with pytest.raises(ValidationError):
        EvidenceRef(
            type="invalid_type",
            ref_id="log_002",
            source="auth.log",
            offset=0,
            length=10,
            sha256="abc123def456..."
        )

def test_incident_output_valid():
    e = EvidenceRef(
        type="raw",
        ref_id="log_001",
        source="auth.log",
        offset=0,
        length=10,
        sha256="abc123def456..."
    )
    incident = IncidentOutput(
        summary="Test summary",
        attack_mapping=["malware_detected"],
        recommended_actions=["notify_admin"],
        confidence=0.9,
        evidence_refs=[e],
        hil_required=False
    )
    assert incident.confidence == 0.9
    assert incident.hil_required is False

def test_incident_output_empty_attack_mapping():
    e = EvidenceRef(
        type="raw",
        ref_id="log_001",
        source="auth.log",
        offset=0,
        length=10,
        sha256="abc123def456..."
    )
    # attack_mapping가 빈 리스트이면 ValidationError
    with pytest.raises(ValidationError):
        IncidentOutput(
            summary="Test summary",
            attack_mapping=[],
            recommended_actions=["notify_admin"],
            confidence=0.9,
            evidence_refs=[e],
            hil_required=False
        )

def test_incident_output_confidence_out_of_range():
    e = EvidenceRef(
        type="raw",
        ref_id="log_001",
        source="auth.log",
        offset=0,
        length=10,
        sha256="abc123def456..."
    )
    # confidence가 0~1 범위를 벗어나면 ValidationError
    with pytest.raises(ValidationError):
        IncidentOutput(
            summary="Test summary",
            attack_mapping=["attack"],
            recommended_actions=["action"],
            confidence=1.5,
            evidence_refs=[e],
            hil_required=False
        )
