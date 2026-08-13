from __future__ import annotations

from abc import ABC, abstractmethod


class RateLimiter(ABC):
    """Cooldown/backoff gate on repeated authentication failures.

    ``check_allowed`` is called *before* every attempt; implementations raise
    RateLimitedError themselves rather than returning a bool, so callers
    cannot accidentally ignore the result.
    """

    @abstractmethod
    def check_allowed(self) -> None:
        """Raises RateLimitedError if currently in a cooldown window."""

    @abstractmethod
    def record_failure(self) -> None: ...

    @abstractmethod
    def record_success(self) -> None: ...

    @abstractmethod
    def seconds_until_allowed(self) -> float:
        """0.0 if not currently limited."""
