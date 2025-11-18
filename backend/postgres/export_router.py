from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from db import get_db
from metrics import EXPORT_PII_BLOCKED
import model
import schemas
from pii import scan_incident_payload

router = APIRouter()

@router.get("/export/json", response_model=schemas.ExportIncidentResponse)
def export_incident(incident_id: str = Query(...), db: Session = Depends(get_db)):
    inc = db.query(model.Incident).filter(
        model.Incident.incident_id == incident_id
    ).first()

    if not inc:
        raise HTTPException(status_code=404, detail="not found")

    payload = {
        "incident_id": inc.incident_id,
        "summary": inc.summary,
        "attack_mapping": inc.attack_mapping or [],
        "recommended_actions": inc.recommended_actions or [],
        "confidence": float(inc.confidence) if inc.confidence else 0.0,
        "status": inc.status,
        "created_at": inc.created_at,
    }

    hits = scan_incident_payload(payload)
    if hits:
        if EXPORT_PII_BLOCKED:
            EXPORT_PII_BLOCKED.labels(incident_id=incident_id).inc()
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail={"message": "pii_detected", "pii_types": sorted(hits)},
        )

    return payload
