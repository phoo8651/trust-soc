import requests
from typing import Optional, List
from .models import (
    EvidenceRef,
    AnalyzeResponse,
    IncidentOutput
)
from .exceptions import (
    APIRequestError,
    SchemaValidationError
)


class TrustSocLLMClient:
    """
    LLM Advisor API 전용 Python SDK
    - analyze
    - get_incident
    - approve_incident
    - reject_incident
    - health
    """

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip("/")

    # ---------------------------
    # /analyze
    # ---------------------------
    def analyze(
        self,
        event_text: str,
        evidences: List[EvidenceRef],
        incident_id: Optional[str] = None,
        callback_url: Optional[str] = None
    ) -> AnalyzeResponse:

        url = f"{self.base_url}/analyze"

        payload = {
            "event_text": event_text,
            "evidences": [e.to_dict() for e in evidences]
        }

        if incident_id:
            payload["incident_id"] = incident_id

        if callback_url:
            payload["callback_url"] = callback_url

        resp = requests.post(url, json=payload)

        if resp.status_code != 200:
            raise APIRequestError(resp.status_code, resp.text)

        data = resp.json()

        try:
            return AnalyzeResponse.from_dict(data)
        except Exception as e:
            raise SchemaValidationError(f"Invalid analyze response: {e}")

    # ---------------------------
    # /incidents/{id}
    # ---------------------------
    def get_incident(self, incident_id: str) -> IncidentOutput:
        url = f"{self.base_url}/incidents/{incident_id}"
        resp = requests.get(url)

        if resp.status_code != 200:
            raise APIRequestError(resp.status_code, resp.text)

        try:
            return IncidentOutput.from_dict(resp.json())
        except Exception as e:
            raise SchemaValidationError(f"Invalid incident output: {e}")

    # ---------------------------
    # approve/reject
    # ---------------------------
    def approve_incident(self, incident_id: str):
        url = f"{self.base_url}/incidents/{incident_id}/approve"
        resp = requests.post(url)

        if resp.status_code != 200:
            raise APIRequestError(resp.status_code, resp.text)

        return resp.json()

    def reject_incident(self, incident_id: str):
        url = f"{self.base_url}/incidents/{incident_id}/reject"
        resp = requests.post(url)

        if resp.status_code != 200:
            raise APIRequestError(resp.status_code, resp.text)

        return resp.json()

    # ---------------------------
    # health
    # ---------------------------
    def health(self):
        url = f"{self.base_url}/healthz"
        resp = requests.get(url)

        if resp.status_code != 200:
            raise APIRequestError(resp.status_code, resp.text)

        return resp.json()
