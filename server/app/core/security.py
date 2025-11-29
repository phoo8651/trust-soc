import contextvars
from typing import Optional

_current_client: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("current_client", default=None)

def set_current_client(client_id: Optional[str]):
    _current_client.set(client_id)

def get_current_client() -> Optional[str]:
    return _current_client.get()