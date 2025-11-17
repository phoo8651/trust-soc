import logging
import os

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger("db")


def _load_database_url() -> str:
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url
    return "postgresql+psycopg2://user:pass@localhost:5432/socdb"


DATABASE_URL = _load_database_url()
ALEMBIC_HEAD_VERSION = os.getenv("ALEMBIC_HEAD_VERSION", "").strip()

engine = create_engine(
    DATABASE_URL,
    echo=os.getenv("SQLALCHEMY_ECHO", "0") == "1",
    future=True,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def _assert_alembic_head():
    if not ALEMBIC_HEAD_VERSION:
        return
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except SQLAlchemyError as exc:
        logger.warning("unable to verify alembic version: %s", exc)
        return

    if result != ALEMBIC_HEAD_VERSION:
        logger.warning(
            "alembic version mismatch (expected=%s, actual=%s)",
            ALEMBIC_HEAD_VERSION,
            result,
        )


_assert_alembic_head()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
