import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from .config import settings
from .security import get_current_client

logger = logging.getLogger("db")

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=20,
    max_overflow=10
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    # 모든 모델 로드 (테이블 생성을 위해 필수)
    from app.models.all_models import Agent, RawLog, Event, Incident, Job
    try:
        # checkfirst=True가 기본이므로 없으면 생성하고 있으면 넘어감
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Tables checked/created.")
    except Exception as e:
        logger.error(f"❌ DB Init Failed: {e}")
        # 운영상 치명적이므로 예외 전파 고려 가능

def get_db():
    db = SessionLocal()
    client_id = get_current_client()
    try:
        if client_id:
            # RLS 설정 (Postgres 전용)
            try:
                db.execute(text("SELECT set_config('app.current_client', :c, false)"), {"c": client_id})
            except Exception as e:
                logger.warning(f"RLS set failed: {e}")
        yield db
    finally:
        try:
            db.execute(text("RESET app.current_client"))
        except Exception:
            pass
        db.close()