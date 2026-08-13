import pytest

from faceauth.exceptions import RateLimitedError
from faceauth.rate_limiting.cooldown_rate_limiter import CooldownRateLimiter


class FakeClock:
    def __init__(self, start: float = 0.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _limiter(clock: FakeClock, **overrides) -> CooldownRateLimiter:
    defaults = dict(
        max_consecutive_failures=3,
        base_cooldown_seconds=10.0,
        backoff_multiplier=2.0,
        max_cooldown_seconds=100.0,
        failure_reset_after_seconds=300.0,
        time_fn=clock,
    )
    defaults.update(overrides)
    return CooldownRateLimiter(**defaults)


def test_allows_attempts_below_failure_threshold():
    clock = FakeClock()
    limiter = _limiter(clock)
    limiter.check_allowed()  # must not raise
    limiter.record_failure()
    limiter.check_allowed()
    limiter.record_failure()
    limiter.check_allowed()  # still under max_consecutive_failures=3


def test_cooldown_triggers_at_failure_threshold():
    clock = FakeClock()
    limiter = _limiter(clock)
    for _ in range(3):
        limiter.record_failure()
    with pytest.raises(RateLimitedError) as exc_info:
        limiter.check_allowed()
    assert exc_info.value.retry_after_seconds == pytest.approx(10.0)


def test_cooldown_expires_after_the_configured_duration():
    clock = FakeClock()
    limiter = _limiter(clock)
    for _ in range(3):
        limiter.record_failure()
    clock.advance(10.01)
    limiter.check_allowed()  # must not raise now


def test_backoff_escalates_on_repeated_failures_past_threshold():
    clock = FakeClock()
    limiter = _limiter(clock)
    for _ in range(3):
        limiter.record_failure()
    assert limiter.seconds_until_allowed() == pytest.approx(10.0)
    clock.advance(10.01)
    limiter.record_failure()  # 4th consecutive failure -> backoff *2
    assert limiter.seconds_until_allowed() == pytest.approx(20.0)


def test_cooldown_is_capped_at_max_cooldown_seconds():
    clock = FakeClock()
    limiter = _limiter(clock, max_cooldown_seconds=15.0)
    for _ in range(3):
        limiter.record_failure()
    clock.advance(100)
    limiter.record_failure()
    assert limiter.seconds_until_allowed() <= 15.0


def test_success_resets_failure_count_and_cooldown():
    clock = FakeClock()
    limiter = _limiter(clock)
    for _ in range(3):
        limiter.record_failure()
    clock.advance(10.01)
    limiter.record_success()
    limiter.check_allowed()  # no cooldown remains
    for _ in range(2):
        limiter.record_failure()
    limiter.check_allowed()  # only 2 consecutive failures since reset; still allowed


def test_failure_count_resets_after_long_idle_period():
    clock = FakeClock()
    limiter = _limiter(clock)
    limiter.record_failure()
    limiter.record_failure()
    clock.advance(300.01)  # exceeds failure_reset_after_seconds
    limiter.record_failure()  # should count as failure #1, not #3
    limiter.check_allowed()  # must not raise - below threshold again
