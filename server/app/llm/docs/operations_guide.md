# Operations Guide – LLM Incident Advisor

본 문서는 운영/운용자가 LLM Advisor를 안정적으로 운영하기 위한 가이드이다.

---

# 1. 운영 개요

LLM Advisor는 다음 구성요소로 운영됨:

- FastAPI Backend
- Local LLM (Llama.cpp + mistral-7b-instruct Q4_K_M)
- RAG Engine (embedding index)
- MITRE AttackMapper
- HIL(Webhook) 시스템

---

# 2. 서버 실행 방법

## 2.1 로컬 실행 (기본)
uvicorn app.llm.advisor_api:app --reload --port 8000


## 2.2 LLM_MODE=local
export LLM_MODE=local

---

# 3. 모델 파일 관리

## 모델 위치
server\app\llm\models\Mistral-7B-Instruct-v0.2


## 정책
- Git에 포함되지 않음
- 다운로드 후 로컬 캐시 유지
- 파일 크기 큼 → 배포 시 별도 S3/artifact로 관리 권장

---

# 4. RAG 인덱스 관리

### Knowledge Base 위치
server/app/llm/rag/knowledge_base/*.md



### 불필요 문서 제거
rag.remove_document(doc_id) # 실질 삭제는 되지만 운영에 노출된 API 없음


---

# 5. Webhook 운영 정책

## 5.1 Webhook 검증 방식
- `X-Signature: sha256=<HMAC>`
- Payload 전체 HMAC
- Timestamp 5분 이내여야 함

## 5.2 Webhook 재시도 정책
- 0.2s → 0.4s → 0.8s
- 최대 3회
- timeout: 3sec

---

# 6. Metrics & Logging

### Gateway Log -> modelGatway 로컬 llm 호출 로그
- tokens_used : 입력  prompt 길이
- duration(sec)

### Webhook Log
- status code
- retry count

# 7. 환경 변수 정리

| 변수 | 설명 |
|------|------|
| LLM_MODE | local |
| WEBHOOK_SECRET | Webhook HMAC secret |
| PYTEST_CURRENT_TEST | pytest 모드 강제 Dummy LLM |

---

# 8. 운영자 Checklist
- KB 문서 최신 유지
- 운영자가 수동으로 SHA256체크 권장
- Webhook Secret 로테이션
- 서버 재시작 후 RAG 정상 로딩 확인

