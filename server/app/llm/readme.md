

## 📌 README.md (리눅스 설치 + 실행 가이드)

````markdown
# 🔐 Trust-SOC LLM Advisor  
> Incident Advisor API (LLM + RAG + ATT&CK 매핑 + HIL)

이 프로젝트는 보안 이벤트를 자동 분석하고 MITRE ATT&CK 기반 매핑 및 Human-in-the-Loop(HIL) 검증 시스템을 제공합니다.  
로컬 LLM + RAG + 규칙 매핑을 결합한 **하이브리드 SOC 분석 어시스턴트** 입니다.

---

## 🚀 Features

- 🤖 **로컬 LLM 분석 (Mistral 7B)**
- 📚 **RAG 기반 근거 문서 인용**
- 🔐 **민감 데이터 마스킹**
- 🎯 **MITRE ATT&CK Hybrid 매핑**
- 👨‍💻 **HIL 승인 + Webhook 통합**
- 📌 **Confidence Guardrails**

---

## 🛠️ Installation (Linux)

### 1️⃣ Clone the Repository

```bash
cd trust-soc/llm
````

### 2️⃣ Run Install Script

```bash
chmod +x install.sh
./install.sh
```

📌 설치 내용

* Python3 + venv 환경 구성
* llama-cpp-python 설치
* 모델 자동 다운로드 (Mistral 7B Q4_K_M)
* `.env` 구성

---

## ▶️ Running the API Server

```bash
source venv/bin/activate
uvicorn llm.advisor_api:app --reload --host 0.0.0.0 --port 10555
```

### 📌 Server URL

```
http://localhost:10555
```

### 📚 Swagger UI

```
http://localhost:10555/docs
```

---

## 🔍 Example API Request

**POST /analyze**

```json
{
  "event_text": "Failed SSH login from 10.0.0.5 for user root",
  "evidences": [
    {
      "type": "raw",
      "ref_id": "E1",
      "source": "auth.log",
      "offset": 0,
      "length": 120,
      "sha256": "abcdef123456",
      "snippet": "Failed SSH login from 10.0.0.5"
    }
  ]
}
```

---

## 🧪 Test Webhook Endpoint

서버는 HIL 시 다음 URL로 Webhook 전송합니다:

```
POST http://localhost:10555/webhooks/test-receiver
```

헤더: `X-Signature (sha256)` 검증 적용됨.

---

## ⚙️ Environment Variables (.env)


| 변수명            | 설명                   |
| ---------------- | -------------------- |
| `LLM_MODE`       | `local` or `gateway` |
| `LOCAL_MODEL`    | 로컬 LLM 모델 경로         |
| `WEBHOOK_SECRET` | Webhook 서명 검증 Key    |

---

## 📌 Project Structure

```
llm/
├── advisor_api.py         # FastAPI 엔드포인트
├── attack_mapper.py       # MITRE ATT&CK 매핑 엔진
├── install.sh             # Linux Setup Script (⬅️)
├── local_llm_PoC.py       # Llama/Dummy LLM Wrapper
├── rag/                   # RAG Engine + Vector Search
├── utils/                 # Confidence / JSON Handling
├── masking/               # PII/Secret Masking
└── prompt_templates/      # LLM Prompt Templates
```





