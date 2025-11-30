# Trust SOC

Trust SOC is a **server log collection, detection, and advisory** solution.

- **Agent**: runs on servers, collects logs, and sends them to the solution server.
- **Solution Server**: ingests logs, normalizes & analyzes them (Rule/ML/YARA), and uses an LLM advisor to produce **MITRE ATT&CK–mapped guidance** for analysts.

---

## 1. Architecture (Very High Level)

```text
[Servers / Apps]
    ↓ logs
[Agent (otel + forwarder + controller)]
    ↓ OTLP (TLS/mTLS)
[Solution Server Ingest API]
    ↓
[Normalize → Detect (Rule/ML/YARA) → Incidents → LLM Advisor]
    ↓
[Slack / ELK / 기타 로그 플랫폼]
```

---

## 2. 주요 컴포넌트

### 2.1 Agent (서버 측)

- **otel-agent**
  - OpenTelemetry Collector.
  - 파일/애플리케이션/시스템 로그 수집.
  - 파이프라인 예:
    - `filelog/syslog/... → transform(mask_pii) → batch/queued_retry → otlphttp`.

- **secure-forwarder**
  - 로컬 HTTP(예: `127.0.0.1:19000/v1/logs`)로 **otel-agent의 OTLP/HTTP** 수신.
  - 로컬 토큰 검증 후, 솔루션 서버 Ingest API로 **TLS1.3(+mTLS)** 전송.
  - 필요 시 HMAC-SHA256 서명 헤더 추가.

- **agent-controller**
  - 솔루션 서버 **Control API**를 주기적으로 폴링.
  - 명령 예: `ping`, `reload_agent`, `update_config`, `upgrade`.
  - 로컬에서 `systemd` 호출 등으로 적용 후, **실행 결과를 서버에 ACK**.

---

### 2.2 Solution Server

- **Backend (FastAPI)**
  - `POST /ingest/logs` – Agent 로그 수신.
  - Agent 제어용 Control API, Webhook/HIL, Export API 제공.
  - Tenant Middleware가 `X-Client-Id` 등을 사용해 **Postgres RLS**와 연동.

- **DB**
  - `raw_logs` – 원본 로그.
  - `events` – Rule/ML/YARA/Hybrid 탐지 결과.
  - `incidents` – 여러 이벤트를 묶은 인시던트 + LLM 결과.
  - `feature_rollup_*` – ML용 롤업 피처.
  - 파티셔닝 및 RLS 적용.

- **Detect 모듈**
  - `ml_detect`: 롤업 피처 기반 이상 탐지(예: Isolation Forest, EWMA).
  - `yara_batch_scanner`: 파일/압축 해제 결과에 YARA 룰 적용.
  - `hybrid_detect`: ML 점수 + YARA 매치 등 결합, 최종 점수/심각도 산출.

- **LLM Advisor**
  - 별도 FastAPI 서비스.
  - 인시던트 + evidence를 입력으로 받아:
    - ATT&CK 매핑, 요약, 대응 가이드, confidence/HIL 여부를 생성.
  - LLM 응답은 JSON Schema로 검증.

---

## 3. 모듈 간 호출 / 통신 구조

### 3.1 데이터 경로 (로그 → 탐지 → LLM)

1. **앱/OS** → 로그 파일 / syslog / 컨테이너 stdout 기록.
2. **otel-agent**
   - 로그를 tail/수신 → 마스킹·샘플링·배치 → **OTLP/HTTP**로 secure-forwarder에 전송.
3. **secure-forwarder**
   - 로컬 토큰 검증.
   - 솔루션 서버의 `POST /ingest/logs`로 **TLS1.3(+mTLS)** 전송  
     (Authorization + timestamp/nonce/idempotency/payload-hash/HMAC 등).
4. **Backend Ingest**
   - 토큰/타임스탬프/해시/멱등성 검증.
   - `raw_logs` (및 초기 `events`/`audit`)에 저장.
5. **Detect Workers**
   - 롤업/피처 생성 → ML 이상 탐지 → YARA 검사 → Hybrid 탐지 이벤트(`events`) 생성.
6. **Incident & LLM**
   - Backend가 관련 이벤트를 묶어 `incidents` 생성.
   - LLM Advisor에 인시던트 요청 → ATT&CK 매핑·요약·대응 가이드 수신.
   - 결과를 `incidents`에 저장 후, Slack/ELK/Webhook 등으로 알림.

### 3.2 제어 경로 (Agent 원격 제어)

1. **Console/관리자** → Backend Control API로 Agent Job 생성  
   (예: `RULES_RELOAD`, `CERT_ROTATE`, `UPGRADE`).
2. **Backend** → DB에 Job 저장 (타입, payload, expires_at, idempotency_key, signature).
3. **agent-controller**
   - 주기적으로 Control API를 **Pull**.
   - 서명/만료/멱등/속도제한 검사 후 로컬에서 실행.
4. 실행 후 **결과/로그를 ACK** API로 전송 → DB에 상태·감사 기록 저장.

### 3.3 LLM 연동 경로

1. Backend → LLM Advisor `POST /advisor/analyze` (인시던트 JSON).
2. LLM Advisor:
   - 필요 시 벡터스토어/RAG로 문맥 조회.
   - LLM 호출 → JSON Schema 검증 및 guardrail 적용.
3. LLM Advisor → Backend: ATT&CK 매핑, summary, recommended_actions 반환.

---

## 4. 대략적인 디렉터리 구조 (예시)

```text
agent/
  etc/
    agent.yaml           # OTel Collector 설정
    .env                 # Agent/forwarder/controller 설정
  secure-forwarder/
    secure-forwarder.py
  agent.controller/
    agent_controller.py

server/
  app/
    backend/
      main.py            # FastAPI 엔트리
      db.py              # DB 연결
      models.py          # raw_logs/events/incidents 등
      ingest_router.py
      control_router.py
      ...
    detect/
      ml_detect.py
      hybrid_detect.py
      yara_batch_scanner.py
    llm/
      advisor_api.py
      model_gateway.py
      attack_mapper.py
```

---

## 5. 참고

- 이 README는 **구조와 모듈 간 통신 체계 요약**에 집중되어 있습니다.
- 실제 포트/엔드포인트/환경변수는 코드 및 설정 파일  
  (`agent/etc/agent.yaml`, `server/app/backend/*.py` 등)을 참고하세요.
