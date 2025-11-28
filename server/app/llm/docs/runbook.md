# Runbook – LLM Incident Advisor

본 문서는 장애 또는 사고 발생 시 운영자가 즉시 수행해야 할 절차를 정의한다.

---

# 1. 목적
- 장애 대응 절차 통일
- LLM 출력 오류 시 복구 가이드 제공
- Webhook 장애 대응
- 운영 시간 단축

---

# 2. 장애 유형별 Runbook

---

## 🟥 2.1 LLM 응답 비정상 (JSON 파싱 실패)
### 증상
- "SCHEMA_VALIDATION_FAILED"
- LLM이 JSON 이외 문자열 출력

### 조치 절차
1) API 로그에서 `summary_prompt` 재시도 여부 확인  
2) Local LLM 로그에서 crash 여부 확인  
3) fallback DummyLLM 작동 
4) 재현 요청으로 문제 prompt 확인  


## 🟧 2.2 Webhook 실패 (timeout / 5xx)

### 조치
1) Webhook receiver 서버 상태 확인  
2) Signature mismatch → secret 로테이션  
3) Receiver 로그에서 payload 크기/JSON 오류 검사  
4) retry 3회 실패 시 수동 HIL 승인 필요

---

## 🟨 2.3 RAG 인덱스 오류

### 증상
- RAG hits empty
- summarize_hits 에러

### 조치
1) KB 문서 경로 존재 확인  
2) KB 파일 UTF-8 인코딩 확인  

---

## 🟦 2.4 AttackMapper 오탐/미탐

### 조치
1) 공격 패턴 추가/수정 (`attack_mapper.py`)  
2) severity 수정  
3) allowlist/denylist 조정  
4) 재배포 후 /healthz 확인

---

## 🟩 2.5 GPT 모델 성능 저하

### 조치
- CPU 점유율 확인
- 토큰 길이 초과 여부 검증


---

# 3. HIL 승인/반려 절차
1) Incident 조회
GET /incidents/{id}

2) 문제가 명확하면 승인:
POST /incidents/{id}/approve

3) 불명확하면 반려:
POST /incidents/{id}/reject
---

# 4. Secret / Key Rotation Procedure

1) 새로운 WEBHOOK_SECRET 발급  
2) Receiver 서버 환경 변수 업데이트  
3) Advisor 서버 환경 변수 업데이트  
4) Advisor 재시작  
5) Webhook 테스트 송신  
6) 정상 수신 확인 후 완료

---

# 5. 점검 Checklist
- Masking 정상 동작 확인
- Webhook signature 확인
- RAG hit 정상 여부
- Attack mapping confidence 값 정상 여부

---

# 6. FAQ

### Q. LLM이 왜 계속 같은 답을 내놓나요?  
A. temperature=0.0 설정으로 deterministic 동작함.

### Q. 왜 evidence가 두 개로 제한됨?  
A. 프롬프트 크기 폭주 방지.

### Q. "ftp" 포함되면 무조건 HIL 왜 발동됨?  
A. Guardrail 정책: 오탐 가능성 높아 HIL 강제.



