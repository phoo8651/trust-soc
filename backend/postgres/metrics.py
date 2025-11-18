try:
    from prometheus_client import Counter, Histogram
except ImportError:  # pragma: no cover - metrics optional
    Counter = None  # type: ignore
    Histogram = None  # type: ignore


def _counter(name: str, documentation: str, labelnames=None):
    if Counter:
        return Counter(name, documentation, labelnames=labelnames or ())
    return None


def _histogram(name: str, documentation: str, buckets=None):
    if Histogram:
        return Histogram(name, documentation, buckets=buckets)
    return None


INGEST_REQUESTS = _counter("soc_ingest_requests_total", "Total ingest requests", ("client_id",))
INGEST_REJECTIONS = _counter(
    "soc_ingest_rejections_total",
    "Rejected ingest requests",
    ("client_id", "status"),
)
JOBS_DELIVERED = _counter(
    "soc_jobs_delivered_total",
    "Jobs delivered to agents",
    ("agent_id", "job_type"),
)
EXPORT_PII_BLOCKED = _counter(
    "soc_export_pii_blocked_total",
    "Export responses blocked due to PII",
    ("incident_id",),
)
INGEST_LATENCY = _histogram(
    "soc_ingest_latency_seconds",
    "Ingest handler latency",
    buckets=(0.1, 0.5, 1, 2, 5),
)
E2E_LATENCY = _histogram(
    "soc_event_e2e_latency_seconds",
    "Latency from event timestamp to ingestion",
    buckets=(1, 5, 15, 30, 60, 120, 300),
)


def record_e2e_latency(event_ts):
    if not E2E_LATENCY or not event_ts:
        return
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    delta = (now - event_ts).total_seconds()
    if delta >= 0:
        E2E_LATENCY.observe(delta)
