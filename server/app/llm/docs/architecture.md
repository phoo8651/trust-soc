# LLM Advisor Architecture Document

## Overview
LLM Advisor는 보안 이벤트를 자동 분석하고,  
RAG 기반 지식 추출 → 마스킹 → 증거 기반 매핑 → LLM 요약/조치 생성 → HIL(Webhook) → 승인 흐름까지  
하나의 일관된 파이프라인으로 제공한다.

---

## Architecture Diagram


::contentReference[oaicite:0]{index=0}


---

## 1. High-Level Flow
1. **Client → /analyze 요청**
2. **Data Masking Layer**에서 민감 정보 제거
3. **Evidence Validation**
4. **RAG Engine**이 KB 문서를 색인 및 관련 정보 검색
5. **AttackMapper**가 MITRE ATT&CK 규칙 기반 매핑
6. **PromptManager**가 Summary Prompt / Response Guide Prompt 생성
7. **Model Gateway**가 local LLM(gpt-gguf) 또는 fallback Dummy LLM 호출
8. **LLM Output Handler**가 JSON 스키마 검증 및 Guardrail 수행
9. Confidence 기반 **HIL 여부 결정**
10. HIL 필요 시 **Webhook 전송**
11. Incident 저장 후 클라이언트에게 최종 응답

---

## 2. Component Breakdown

### 2.1 Masking Layer
- IP / Email / RRN / Secret Token / User ID 마스킹
- API 응답 및 LLM 프롬프트 안전을 위해 필수

### 2.2 RAG Engine
- knowledge_base/*.md 자동 인덱싱
- sentence-transformers 기반 embedding
- FAISS 또는 in-memory index fallback
- hits → 요약(summarize_hits) → prompt 삽입

### 2.3 AttackMapper
- static 규칙 기반 매핑
- evidence 기반 confidence boost
- allow/deny list 지원
- LLM fallback hybrid 전략 지원


### 2.4 HIL(Approval) System
- Confidence < 0.80 → HIL 필요
- Webhook 서명(HMAC-SHA256) + Timestamp + 재시도 백오프
- Idempotency Key 기반 중복 전송 방지

---

## 3. Dataflow Diagram (텍스트 버전)

Client
↓ POST /analyze
Masking Layer
↓
Evidence Validator
↓
RAG Engine → (KB 검색)
↓
Attack Mapper
↓
Prompt Manager (summary/response)
↓
Response Normalizer / Guardrail
↓
Confidence Decision
↓ ↘ (HIL Required)
Incident Store Webhook Sender
↓
Client Response


---

## 4. Deployment Architecture

### Local-only mode (default)
FastAPI ← ModelGateway(LocalLlamaLLM)
↓
Mistral-7B-Instruct-v0.2


## 5. Data Storage
- RAG 문서: 메모리 인덱스(InMemory or FAISS)
- Incident 저장(/analyze 내부에서만): In-memory dict
- Idempotency Key: In-memory dict (PoC)

---

## 6. Security Layers
- Evidence schema validation
- HMAC Signature verification
- Timestamp anti-replay
- Prompt Injection Guardrail

---
