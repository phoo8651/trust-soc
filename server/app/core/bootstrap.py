import asyncio
import secrets
import logging
from typing import Optional

logger = logging.getLogger("bootstrap")


class BootstrapManager:
    """
    에이전트 등록용 Bootstrap Secret을 관리하는 싱글톤 클래스.
    5분마다 새로운 랜덤 키로 갱신합니다.
    """

    _instance = None
    _secret: str = "initializing..."
    _task: Optional[asyncio.Task] = None
    _interval: int = 300  # 5분 (300초)

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(BootstrapManager, cls).__new__(cls)
        return cls._instance

    @classmethod
    def get_current_secret(cls) -> str:
        return cls._secret

    @classmethod
    def validate(cls, input_secret: str) -> bool:
        if not input_secret:
            return False
        # Timing Attack 방지를 위해 compare_digest 사용
        return secrets.compare_digest(cls._secret, input_secret)

    @classmethod
    async def _rotation_loop(cls):
        logger.info(
            f"🔄 Bootstrap Secret Rotation Started (Interval: {cls._interval}s)"
        )
        while True:
            try:
                # 새로운 16바이트(32자) 헥사 키 생성
                new_secret = secrets.token_hex(16)
                cls._secret = new_secret
                logger.info(f"🔑 New Bootstrap Secret Generated: {new_secret}")

                # 지정된 시간만큼 대기
                await asyncio.sleep(cls._interval)
            except asyncio.CancelledError:
                logger.info("🛑 Bootstrap Rotation Stopped.")
                break
            except Exception as e:
                logger.error(f"Secret rotation error: {e}")
                await asyncio.sleep(10)  # 에러 시 잠시 대기 후 재시도

    @classmethod
    def start(cls):
        # 서버 시작 시 즉시 키 생성 및 루프 시작
        if cls._task is None:
            cls._task = asyncio.create_task(cls._rotation_loop())

    @classmethod
    def stop(cls):
        if cls._task:
            cls._task.cancel()
            cls._task = None
