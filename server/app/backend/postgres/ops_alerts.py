import logging
import os
from datetime import datetime, timezone, timedelta

from sqlalchemy import text
from sqlalchemy.engine import Engine

logger = logging.getLogger("ops_alerts")

JOB_BACKLOG_THRESHOLD = int(os.getenv("OPS_JOB_BACKLOG_THRESHOLD", "100"))
HIL_BACKLOG_MINUTES = int(os.getenv("OPS_HIL_BACKLOG_MINUTES", "60"))


def run_operational_checks(engine: Engine) -> None:
    _check_job_backlog(engine)
    _check_hil_staleness(engine)


def _check_job_backlog(engine: Engine) -> None:
    sql = text(
        """
        SELECT count(*) FROM jobs
        WHERE status IN ('pending','ready')
        """
    )
    try:
        with engine.connect() as conn:
            backlog = conn.execute(sql).scalar_one()
    except Exception as exc:  
        logger.warning("unable to check job backlog: %s", exc)
        return
    if backlog >= JOB_BACKLOG_THRESHOLD:
        logger.warning("job backlog threshold exceeded (%s >= %s)", backlog, JOB_BACKLOG_THRESHOLD)


def _check_hil_staleness(engine: Engine) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=HIL_BACKLOG_MINUTES)
    sql = text(
        """
        SELECT count(*) FROM incidents
        WHERE status = 'hil_required' AND created_at <= :cutoff
        """
    )
    try:
        with engine.connect() as conn:
            stale = conn.execute(sql, {"cutoff": cutoff}).scalar_one()
    except Exception as exc:  
        logger.warning("unable to check HIL backlog: %s", exc)
        return
    if stale:
        logger.warning("%s incidents awaiting HIL decision for over %s minutes", stale, HIL_BACKLOG_MINUTES)
