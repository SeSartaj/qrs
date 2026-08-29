"""Clock abstraction (IoC for time)."""

from __future__ import annotations

import time
from typing import Protocol

__all__ = ["IClock", "SystemClock"]


class IClock(Protocol):
    """Provides the current Unix epoch time in seconds."""

    def now(self) -> int: ...


class SystemClock:
    """The default clock: wall-clock time."""

    def now(self) -> int:
        return int(time.time())