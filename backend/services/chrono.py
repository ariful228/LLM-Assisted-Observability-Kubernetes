"""Clock / time-source abstraction.

Everything in the system uses `now()` so tests can control time deterministically.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Callable

_time_factory: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
_lock = threading.Lock()


def now() -> datetime:
    with _lock:
        return _time_factory()


def set_time_factory(factory: Callable[[], datetime]) -> None:
    global _time_factory
    with _lock:
        _time_factory = factory


def iso(dt: datetime | None = None) -> str:
    return (dt or now()).isoformat()


def reset_time_factory() -> None:
    global _time_factory
    with _lock:
        _time_factory = lambda: datetime.now(timezone.utc)