import json
import re
from typing import Any, Dict, Iterable, Set

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _walk(obj: Any) -> Iterable[str]:
    if obj is None:
        return
    if isinstance(obj, dict):
        for value in obj.values():
            yield from _walk(value)
    elif isinstance(obj, (list, tuple, set)):
        for value in obj:
            yield from _walk(value)
    else:
        yield str(obj)


def scan_strings(strings: Iterable[str]) -> Set[str]:
    hits: Set[str] = set()
    for text in strings:
        if EMAIL_RE.search(text):
            hits.add("email")
        if CC_RE.search(text):
            hits.add("card")
        if SSN_RE.search(text):
            hits.add("ssn")
    return hits


def scan_incident_payload(payload: Dict[str, Any]) -> Set[str]:
    serialized = json.dumps(payload, default=str)
    aggregate = list(_walk(payload))
    aggregate.append(serialized)
    return scan_strings(aggregate)
