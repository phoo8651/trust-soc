from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from db import get_db
import model, schemas

router = APIRouter()

@router.get("/export/json", response_model=schemas.ExportIncidentResponse)
def export_incident(incident_id: str = Query(...), db: Session = Depends(get_db)):
    inc = db.query(model.Incident).filter(
        model.Incident.incident_id == incident_id
    ).first()

    if not inc:
        raise HTTPException(status_code=404, detail="not found")

    return {
        "incident_id": inc.incident_id,
        "summary": inc.summary,
        "attack_mapping": inc.attack_mapping or [],
        "recommended_actions": inc.recommended_actions or [],
        "confidence": float(inc.confidence) if inc.confidence else 0.0,
        "status": inc.status,
        "created_at": inc.created_at,
    }
