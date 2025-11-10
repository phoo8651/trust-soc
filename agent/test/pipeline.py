# -*- coding: utf-8 -*-
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from schemas import IngestMeta, RecordItem


@dataclass
class DetectionOutcome:
    category: str
    severity: str
    summary: str
    rule_id: str
    ml_score: float
    attack_mapping: List[Dict[str, Any]]
    recommended_actions: List[Dict[str, Any]]
    confidence: float
    status: str


def _lower(s: str) -> str:
    return s.lower()


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract_url(raw_line: str) -> str:
    match = re.search(r'"[A-Z]+\s+([^"\s]+)', raw_line)
    if match:
        return match.group(1)[:512]
    return "/"


def _extract_status(raw_line: str) -> str:
    match = re.search(r'"\s+(\d{3})\b', raw_line)
    if match:
        return match.group(1)
    return "0"


def _extract_ip(raw_line: str) -> str:
    match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", raw_line)
    if match:
        return match.group(1)
    return "0.0.0.0"


def normalize_record(meta: IngestMeta, record: RecordItem) -> Dict[str, Any]:
    raw_bytes = record.raw_line.encode("utf-8", errors="ignore")
    sha = _hash_bytes(raw_bytes)

    ecs_lite = {
        "timestamp": record.ts.isoformat(),
        "client.id": meta.client_id,
        "host.name": meta.host,
        "log.source": record.source_type,
        "event.original": record.raw_line[:2048],
        "network.client.ip": _extract_ip(record.raw_line),
        "http.response.status_code": _extract_status(record.raw_line),
        "url.path": _extract_url(record.raw_line),
    }

    return {
        "sha256": sha,
        "ecs": ecs_lite,
        "raw_bytes_len": len(raw_bytes),
    }


def detect_threat(normalized: Dict[str, Any], record: RecordItem) -> DetectionOutcome:
    raw_lower = _lower(record.raw_line)
    status_code = normalized["ecs"]["http.response.status_code"]

    if "failed password" in raw_lower or "unauthorized" in raw_lower:
        severity = "high"
        rule_id = "SSH_BF_5M"
        category = "authentication"
        summary = "SSH brute-force pattern detected"
        attack = [{"id": "T1110", "confidence": 0.8, "why": ["failed password burst"]}]
        recommended = [
            {
                "step": "Lock impacted accounts and review SSH access logs for anomalies",
                "auto": False,
                "severity": "High",
            }
        ]
        confidence = 0.78
        status = "hil_required"
        ml_score = 0.84
    elif status_code.startswith(("4", "5")):
        severity = "medium"
        rule_id = "HTTP_ERROR_RATE"
        category = "web_access"
        summary = f"HTTP error response observed ({status_code})"
        attack = [{"id": "T1190", "confidence": 0.5, "why": ["elevated http errors"]}]
        recommended = [
            {
                "step": "Inspect recent HTTP error responses for intrusion attempts",
                "auto": False,
                "severity": "Medium",
            }
        ]
        confidence = 0.55
        status = "review"
        ml_score = 0.52
    else:
        severity = "low"
        rule_id = "HTTP_ACCESS_BASELINE"
        category = "web_access"
        summary = "Baseline access log ingested"
        attack = [{"id": "TA0002", "confidence": 0.2, "why": ["normal access pattern"]}]
        recommended = [
            {
                "step": "No immediate action required; monitor for deviations",
                "auto": True,
                "severity": "Low",
            }
        ]
        confidence = 0.3
        status = "observed"
        ml_score = 0.15

    return DetectionOutcome(
        category=category,
        severity=severity,
        summary=summary,
        rule_id=rule_id,
        ml_score=ml_score,
        attack_mapping=attack,
        recommended_actions=recommended,
        confidence=confidence,
        status=status,
    )


def build_evidence_refs(raw_id: int, normalized: Dict[str, Any], outcome: DetectionOutcome) -> List[Dict[str, Any]]:
    ecs = normalized["ecs"]
    return [
        {
            "type": "raw",
            "ref_id": f"raw:{raw_id}",
            "source": ecs["log.source"],
            "sha256": normalized["sha256"],
            "offset": 0,
            "length": normalized["raw_bytes_len"],
            "rule_id": outcome.rule_id,
        }
    ]


def build_event_payload(
    meta: IngestMeta,
    record: RecordItem,
    raw_id: int,
    normalized: Dict[str, Any],
    outcome: DetectionOutcome,
) -> Dict[str, Any]:
    evidence_refs = build_evidence_refs(raw_id, normalized, outcome)
    ecs = normalized["ecs"]
    ua_hash = _hash_bytes(ecs.get("event.original", "").encode("utf-8"))[:32]

    return {
        "category": outcome.category,
        "severity": outcome.severity,
        "summary": outcome.summary,
        "evidence_refs": evidence_refs,
        "rule_id": outcome.rule_id,
        "ml_score": outcome.ml_score,
        "source_ip_enc": _hash_bytes(ecs["network.client.ip"].encode("utf-8")),
        "url_path": ecs["url.path"],
        "ua_hash": ua_hash,
        "context": {
            "ecs_lite": ecs,
            "normalized_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def build_incident_payload(
    meta: IngestMeta,
    outcome: DetectionOutcome,
    normalized: Dict[str, Any],
    agent_id: str,
) -> Dict[str, Any]:
    incident_id = f"inc-{uuid.uuid4()}"
    ecs = normalized["ecs"]
    metadata = {
        "schema_version": "1.0.0",
        "ecs_lite": ecs,
        "agent_id": agent_id,
        "prompt_version": "2025.10.22",
    }

    return {
        "incident_id": incident_id,
        "summary": outcome.summary,
        "category": outcome.category,
        "attack_mapping": outcome.attack_mapping,
        "recommended_actions": outcome.recommended_actions,
        "confidence": outcome.confidence,
        "status": outcome.status,
        "incident_metadata": metadata,
    }


def process_record(
    meta: IngestMeta,
    record: RecordItem,
    raw_id: int,
    agent_id: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    normalized = normalize_record(meta, record)
    outcome = detect_threat(normalized, record)
    event_payload = build_event_payload(meta, record, raw_id, normalized, outcome)
    incident_payload = build_incident_payload(meta, outcome, normalized, agent_id)
    return event_payload, incident_payload
