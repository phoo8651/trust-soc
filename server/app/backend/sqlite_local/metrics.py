import logging
import math
import os
from collections import deque
from datetime import datetime, timezone

logger = logging.getLogger("metrics")

E2E_P95_TARGET_SECONDS = float(os.getenv("E2E_P95_TARGET_SECONDS", "120"))
E2E_WINDOW_SIZE = int(os.getenv("E2E_P95_WINDOW", "200"))


class PercentileWindow:
    def __init__(self, maxlen: int):
        self.samples = deque(maxlen=maxlen)

    def add(self, value: float):
        self.samples.append(max(0.0, value))

    def percentile(self, pct: float) -> float:
        if not self.samples:
            return 0.0
        data = sorted(self.samples)
        rank = max(0, min(len(data) - 1, math.ceil(len(data) * pct / 100) - 1))
        return data[rank]


_e2e_window = PercentileWindow(E2E_WINDOW_SIZE)


def record_e2e_latency(event_ts: datetime) -> float:
    if not isinstance(event_ts, datetime):
        return 0.0
    if event_ts.tzinfo is None:
        event_ts = event_ts.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    latency = (now - event_ts).total_seconds()
    _e2e_window.add(latency)
    p95 = _e2e_window.percentile(95)
    if p95 > E2E_P95_TARGET_SECONDS:
        logger.warning(
            "E2E latency gate exceeded: p95=%.2fs target=%.2fs sample_size=%s",
            p95,
            E2E_P95_TARGET_SECONDS,
            len(_e2e_window.samples),
        )
    return p95
