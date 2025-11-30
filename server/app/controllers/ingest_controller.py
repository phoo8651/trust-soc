import json
import hashlib
from datetime import datetime, timezone
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.core.queues import queues
from app.services.auth_service import AuthService
from app.core.security_utils import verify_timestamp, verify_payload_hash
from app.models.all_models import IdempotencyKey, RawLog


class IngestController:
    def __init__(self, db: Session):
        self.db = db
        self.auth = AuthService(db)

    async def handle_request(self, body: bytes, headers: dict):
        # 1. 헤더 추출
        req_ts = headers.get("x-request-timestamp")
        payload_hash = headers.get("x-payload-hash")
        idem_key = headers.get("x-idempotency-key")
        nonce = headers.get("x-nonce")  # [수정] Nonce 추출

        # 2. 보안 헤더 검증
        try:
            verify_timestamp(req_ts)
            verify_payload_hash(body, payload_hash)
        except ValueError as e:
            raise HTTPException(422, str(e))

        try:
            data = json.loads(body)
        except:
            raise HTTPException(400, "Invalid JSON")

        meta = data.get("meta", {})
        client_id = meta.get("client_id")
        agent_id = data.get("agent_id")
        host = meta.get("host")

        # 3. 인증 체크
        if not self.auth.validate_access(
            client_id, agent_id, headers.get("authorization")
        ):
            raise HTTPException(401, "Unauthorized")

        # 4. 멱등성 체크 (Idempotency)
        if self.db.query(IdempotencyKey).filter_by(idem_key=idem_key).first():
            return {"status": "queued", "accepted": 0, "msg": "duplicate"}

        # 5. 로그 처리 (DB 저장 + 큐 적재)
        records = data.get("records", [])
        raw_logs_to_save = []

        for rec in records:
            # (1) 분석 큐에 적재
            await queues.detect_queue.put(
                {"meta": meta, "agent_id": agent_id, "record": rec}
            )

            # (2) raw_logs 테이블 저장용 객체 생성
            raw_line = rec.get("raw_line", "")
            line_hash = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()

            log_entry = RawLog(
                ts=rec.get("ts"),
                client_id=client_id,
                host=host,
                agent_id=agent_id,
                source_type=rec.get("source_type"),
                raw_line=raw_line,
                hash_sha256=line_hash,
                tags=rec.get("tags"),
            )
            raw_logs_to_save.append(log_entry)

        # 6. 일괄 저장
        if raw_logs_to_save:
            self.db.add_all(raw_logs_to_save)

        # [수정] 멱등성 키 저장 시 nonce와 ts_bucket 추가
        # ts_bucket은 간단히 timestamp의 앞부분(분 단위 등)을 사용하거나 날짜를 사용
        ts_bucket = (
            req_ts[:16]
            if req_ts
            else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
        )

        self.db.add(
            IdempotencyKey(
                client_id=client_id,
                agent_id=agent_id,
                idem_key=idem_key,
                nonce=nonce,  # [New] 필수
                ts_bucket=ts_bucket,  # [New] 필수
            )
        )

        self.db.commit()
        return {"status": "queued", "accepted": len(records)}
