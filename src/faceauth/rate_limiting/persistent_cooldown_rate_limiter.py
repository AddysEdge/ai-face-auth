"""File-backed escalating cooldown/backoff rate limiter.

This is the real CLI/app's default, added after a live test found that
``CooldownRateLimiter``'s in-memory-only state provides no real brute-force
protection against repeated *separate* CLI invocations: the CLI rebuilds
its whole pipeline (including a fresh rate limiter) on every single
`faceauth authenticate` process, so five failed attempts run as five
separate short-lived processes each see zero prior failures - see
docs/THREAT_MODEL.md section 12 for the full account. Persisting failure
count / cooldown-until to a small JSON file, keyed to wall-clock time
(``time.time()``, not ``time.monotonic()`` - monotonic's epoch is
arbitrary per-process and not comparable across restarts), closes this gap.

State is a plain (unencrypted) JSON file - it contains only a failure
count and two timestamps, never anything biometric or secret, so this does
not need the DPAPI-backed protection templates get. Writes are atomic
(write to a temp file, then rename) to avoid a half-written file being
mistaken for valid state; a corrupted/unreadable state file resets to zero
failures rather than raising - see ``_load()`` for why that's a
deliberate, safe choice for a DoS-protection bookkeeping file specifically,
not a relaxation of the authentication fail-closed guarantee (which
governs identity verification, not this availability mechanism).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path

from faceauth.exceptions import RateLimitedError
from faceauth.interfaces.rate_limiter import RateLimiter
from faceauth.rate_limiting.policy import (
    RateLimitPolicy,
    RateLimitState,
    apply_failure,
    seconds_remaining,
)


class PersistentCooldownRateLimiter(RateLimiter):
    def __init__(
        self,
        state_path: Path,
        max_consecutive_failures: int = 5,
        base_cooldown_seconds: float = 30.0,
        backoff_multiplier: float = 2.0,
        max_cooldown_seconds: float = 900.0,
        failure_reset_after_seconds: float = 1800.0,
        time_fn: Callable[[], float] = time.time,
    ) -> None:
        self._policy = RateLimitPolicy(
            max_consecutive_failures=max_consecutive_failures,
            base_cooldown_seconds=base_cooldown_seconds,
            backoff_multiplier=backoff_multiplier,
            max_cooldown_seconds=max_cooldown_seconds,
            failure_reset_after_seconds=failure_reset_after_seconds,
        )
        self._time_fn = time_fn
        self._state_path = Path(state_path)
        self._state_path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> RateLimitState:
        if not self._state_path.exists():
            return RateLimitState()
        try:
            raw = json.loads(self._state_path.read_text(encoding="utf-8"))
            return RateLimitState(
                consecutive_failures=int(raw["consecutive_failures"]),
                last_failure_time=raw["last_failure_time"],
                cooldown_until=raw["cooldown_until"],
            )
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            # A corrupted bookkeeping file resets the counter rather than
            # blocking availability indefinitely or crashing authentication
            # - the fail-closed guarantee that matters (never granting on an
            # unverified identity) is untouched by this reset.
            return RateLimitState()

    def _save(self, state: RateLimitState) -> None:
        payload = {
            "consecutive_failures": state.consecutive_failures,
            "last_failure_time": state.last_failure_time,
            "cooldown_until": state.cooldown_until,
        }
        tmp_path = self._state_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload), encoding="utf-8")
        tmp_path.replace(self._state_path)  # atomic rename on the same filesystem

    def check_allowed(self) -> None:
        remaining = self.seconds_until_allowed()
        if remaining > 0.0:
            raise RateLimitedError(remaining)

    def record_failure(self) -> None:
        state = apply_failure(self._load(), self._time_fn(), self._policy)
        self._save(state)

    def record_success(self) -> None:
        self._save(RateLimitState())

    def seconds_until_allowed(self) -> float:
        return seconds_remaining(self._load(), self._time_fn())
