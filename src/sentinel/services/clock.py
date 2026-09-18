"""Clocks for provider timestamps. Tests inject their own."""

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Timezone-aware instant."""
        ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
