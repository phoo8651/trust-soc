from dataclasses import dataclass
from typing import List, Optional


@dataclass
class EvidenceRef:
    type: str
    ref_id: str
    source: str
    offset: int
    length: int
    sha256: str
    rule_id: Optional[str] = None
    snippet: Optional[str] = None  # analyze 응답에서 반환됨

    def to_dict(self) -> dict:
        out = {
            "type": self.type,
            "ref_id": self.ref_id,
            "source": self.source,
            "offset": self.offset,
            "length": self.length,
            "sha256": self.sha256,
        }
        if self.rule_id:
            out["rule_id"] = self.rule_id
        if self.snippet:
            out["snippet"] = self.snippet
        return out

    @staticmethod
    def from_dict(d: dict) -> "EvidenceRef":
        return EvidenceRef(
            type=d["type"],
            ref_id=d["ref_id"],
            source=d["source"],
            offset=d["offset"],
            length=d["length"],
            sha256=d["sha256"],
            rule_id=d.get("rule_id"),
            snippet=d.get("snippet")
        )


@dataclass
class IncidentOutput:
    summary: str
    attack_mapping: List[str]
    recommended_actions: List[str]
    confidence: float
    evidence_refs: List[EvidenceRef]
    hil_required: bool
    status: str

    @staticmethod
    def from_dict(d: dict) -> "IncidentOutput":
        return IncidentOutput(
            summary=d["summary"],
            attack_mapping=d["attack_mapping"],
            recommended_actions=d["recommended_actions"],
            confidence=d["confidence"],
            evidence_refs=[EvidenceRef.from_dict(e) for e in d["evidence_refs"]],
            hil_required=d["hil_required"],
            status=d["status"],
        )


@dataclass
class AnalyzeResponse(IncidentOutput):
    incident_id: str
    next_action: str

    @staticmethod
    def from_dict(d: dict) -> "AnalyzeResponse":
        base = IncidentOutput.from_dict(d)
        return AnalyzeResponse(
            summary=base.summary,
            attack_mapping=base.attack_mapping,
            recommended_actions=base.recommended_actions,
            confidence=base.confidence,
            evidence_refs=base.evidence_refs,
            hil_required=base.hil_required,
            status=base.status,
            incident_id=d["incident_id"],
            next_action=d["next_action"],
        )
