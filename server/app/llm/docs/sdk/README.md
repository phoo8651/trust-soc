# trust_soc_llm SDK

LLM Incident Advisor API를 위한 Python SDK.

## Installation
(로컬에서 사용 시)

## Usage

```python
from trust_soc_llm import TrustSocLLMClient, EvidenceRef

client = TrustSocLLMClient("http://localhost:8000")

evidence = EvidenceRef(
    type="raw",
    ref_id="log001",
    source="auth.log",
    offset=0,
    length=120,
    sha256="aabbccddeeff"
)

resp = client.analyze(
    event_text="Failed SSH login from 1.2.3.4",
    evidences=[evidence]
)

print(resp.summary, resp.attack_mapping)
