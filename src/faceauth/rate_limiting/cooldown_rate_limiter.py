"""In-memory escalating cooldown/backoff rate limiter.

Keyed by the caller's identity (typically "this local authentication
surface", not a claimed face identity - an impostor hasn't been identified
yet at the point rate limiting applies, see docs/RESEARCH.md section 13).
Time is injected via ``time_fn`` so tests can drive it deterministically
without real sleeps.

State lives only in process memory - it does not survive the process
exiting. For the real CLI/app, ``PersistentCooldownRateLimiter``
(persistent_cooldown_rate_limiter.py) is the default, precisely because a
live test found that an in-memory-only limiter provides no real protection
against repeated separate CLI invocations (each one starts a fresh
process, and therefore a fresh limiter) - see docs/THREAT_MODEL.md section
12. This class remains available and is what the fast, deterministic unit
tests use directly.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from faceauth.exceptions import RateLimitedError
from faceauth.interfaces.rate_limiter import RateLimiter
from faceauth.rate_limiting.policy import (
    RateLimitPolicy,
    RateLimitState,
    apply_failure,
    seconds_remaining,
)


class CooldownRateLimiter(RateLimiter):
    def __init__(
        self,
        max_consecutive_failures: int = 5,
        base_cooldown_seconds: float = 30.0,
        backoff_multiplier: float = 2.0,
        max_cooldown_seconds: float = 900.0,
        failure_reset_after_seconds: float = 1800.0,
        time_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self._policy = RateLimitPolicy(
            max_consecutive_failures=max_consecutive_failures,
            base_cooldown_seconds=base_cooldown_seconds,
            backoff_multiplier=backoff_multiplier,
            max_cooldown_seconds=max_cooldown_seconds,
            failure_reset_after_seconds=failure_reset_after_seconds,
        )
        self._time_fn = time_fn
        self._state = RateLimitState()

    def check_allowed(self) -> None:
        remaining = self.seconds_until_allowed()
        if remaining > 0.0:
            raise RateLimitedError(remaining)

    def record_failure(self) -> None:
        self._state = apply_failure(self._state, self._time_fn(), self._policy)

    def record_success(self) -> None:
        self._state = RateLimitState()

    def seconds_until_allowed(self) -> float:
        return seconds_remaining(self._state, self._time_fn())
