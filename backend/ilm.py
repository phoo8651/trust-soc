import logging
import os
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.engine import Engine

logger = logging.getLogger("ilm")

ILM_DAYS_HOT = int(os.getenv("ILM_DAYS_HOT", "30"))
ILM_DAYS_WARM = int(os.getenv("ILM_DAYS_WARM", "90"))

TABLES = ("raw_logs", "events", "incidents")


def ensure_partitions(engine: Engine):
    start_day = datetime.now(timezone.utc).date()
    for table in TABLES:
        for offset in range(ILM_DAYS_HOT):
            _materialize_partition(engine, table, start_day + timedelta(days=offset))


def _materialize_partition(engine: Engine, table: str, day: date):
    partition_name = f"{table}_p{day.strftime('%Y%m%d')}"
    start = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    ddl = text(
        f"""
        CREATE TABLE IF NOT EXISTS {partition_name}
        PARTITION OF {table}
        FOR VALUES FROM (:start) TO (:end);
        """
    )
    try:
        with engine.begin() as conn:
            conn.execute(ddl, {"start": start, "end": end})
    except Exception as exc:  
        logger.debug("partition ensure skipped for %s (%s)", partition_name, exc)


def apply_ilm(engine: Engine):
    cutoff = datetime.now(timezone.utc) - timedelta(days=ILM_DAYS_WARM)
    sql = text(
        """
        SELECT child.relname AS partition
        FROM pg_inherits
        JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
        JOIN pg_class child ON pg_inherits.inhrelid = child.oid
        WHERE parent.relname = :table;
        """
    )
    for table in TABLES:
        try:
            with engine.begin() as conn:
                partitions = conn.execute(sql, {"table": table}).scalars().all()
                for part in partitions:
                    try:
                        suffix = part.split("_p")[-1]
                        part_day = datetime.strptime(suffix, "%Y%m%d").replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue
                    if part_day < cutoff:
                        conn.execute(text(f"DROP TABLE IF EXISTS {part}"))
                        logger.info("dropped cold partition %s", part)
        except Exception as exc:  
            logger.warning("failed ILM sweep for %s: %s", table, exc)
