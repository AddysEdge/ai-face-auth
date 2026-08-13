"""Pure rate-limit state-transition logic, shared by the in-memory
(``CooldownRateLimiter``) and persistent (``PersistentCooldownRateLimiter``)
backends so the escalation math is defined exactly once.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitPolicy:
    max_consecutive_failures: int
    base_cooldown_seconds: float
    backoff_multiplier: float
    max_cooldown_seconds: float
    failure_reset_after_seconds: float


@dataclass(frozen=True)
class RateLimitState:
    consecutive_failures: int = 0
    last_failure_time: float | None = None
    cooldown_until: float | None = None


def apply_failure(state: RateLimitState, now: float, policy: RateLimitPolicy) -> RateLimitState:
    consecutive = state.consecutive_failures
    if (
        state.last_failure_time is not None
        and (now - state.last_failure_time) > policy.failure_reset_after_seconds
    ):
        consecutive = 0
    consecutive += 1

    cooldown_until = state.cooldown_until
    if consecutive >= policy.max_consecutive_failures:
        excess = consecutive - policy.max_consecutive_failures
        cooldown = min(
            policy.base_cooldown_seconds * (policy.backoff_multiplier**excess),
            policy.max_cooldown_seconds,
        )
        cooldown_until = now + cooldown

    return RateLimitState(
        consecutive_failures=consecutive, last_failure_time=now, cooldown_until=cooldown_until
    )


def seconds_remaining(state: RateLimitState, now: float) -> float:
    if state.cooldown_until is None:
        return 0.0
    return max(state.cooldown_until - now, 0.0)
