# Threat Model – LLM Incident Advisor

본 문서는 LLM Advisor 시스템의 위협 요소를 STRIDE 관점으로 분석한다.

---

# 1. STRIDE Threat Categories

## 🟦 1. Spoofing (스푸핑)
### 잠재 위협
- 공격자가 Webhook Signature를 위조하여 승인/반려 신호를 보내는 경우
- 공격자가 변조된 evidence 제출

### 대응
- Webhook signature: HMAC-SHA256 + secret key
- Timestamp 5분 이내 체크
- Idempotency Key 검증
- Evidence 필드 기반 strict schema validation

---

## 🟧 2. Tampering (변조)
### 위협
- Prompt Injection으로 LLM 출력 변조
- evidence data 위조(sha256 불일치)

### 대응
- RAG hits 요약 압축(summarize_hits)로 prompt 오염 최소화
- evidence_block은 snippet 기반 "quoted-only"
- sha256 양식 검증
- prompt: "증거 외 정보 무시" guardrail 적용

---

## 🟨 3. Repudiation (부인)
### 위협
- 외부 시스템이 Webhook 재전송을 부인
- 승인/반려 절차 기록 누락

### 대응
- Webhook 로그 기록
- Idempotency Key로 중복 처리 기록
- IncidentDecision 로깅 API

---

## 🟥 4. Information Disclosure (정보 유출)
### 위협
- LLM Prompt에 민감 정보 그대로 포함
- event_text에 PII 포함

### 대응
- Masking Layer로 IP/Email/RRN/Token 등 자동 마스킹
- Evidence snippet도 마스킹된 event_text 기반

---

## 🟩 5. Denial of Service (DoS)
### 위협
- LLM 호출 남용
- 비정상 webhook flooding
- RAG 인덱스 대량 삽입

### 대응
- 요청당 evidence 최대 2개 제한
- webhook timeout + 백오프
- 향후 rate-limit 적용 가능 구조

---

## 🟪 6. Elevation of Privilege
### 위협
- 승인/반려 API를 임의 호출
- 승인 권한을 가진 외부 시스템 가장

### 대응
- Webhook은 callback-only
- 서명 기반 source validation

---

# 2. LLM 관련 Threats

## Prompt Injection
- 공격자가 evidence 안에 "ignore previous instructions" 삽입 가능  
→ 해결: evidence는 snippet만 제공, quoted-only

## Training Data Leakage
- local LLM만 사용



---

# 3. Residual Risks
- 모델 자체의 오탐/미탐(LLM 특성)
- 메모리 인시던트 저장 PoC 단계 (향후 DB 필요)
- Secret 파일 관리 필요

---

# 4. Conclusion
현재 시스템은 PoC 단계에서 요구되는 최소 수준의 방어체계를 갖추었으며,  
추후 운영 환경에서는 DB 기반 저장소, Rate Limit, Secret Vault 적용이 권장된다.
