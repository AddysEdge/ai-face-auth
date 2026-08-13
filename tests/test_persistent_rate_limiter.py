"""Tests for the file-backed rate limiter, added after a live test found
in-memory-only rate limiting provides no real protection against repeated
separate CLI invocations (each `faceauth authenticate` process starts a
fresh in-memory limiter) - see docs/THREAT_MODEL.md section 12.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from faceauth.exceptions import RateLimitedError
from faceauth.rate_limiting.persistent_cooldown_rate_limiter import PersistentCooldownRateLimiter


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _limiter(state_path: Path, clock: FakeClock, **overrides) -> PersistentCooldownRateLimiter:
    defaults = dict(
        max_consecutive_failures=3,
        base_cooldown_seconds=10.0,
        backoff_multiplier=2.0,
        max_cooldown_seconds=100.0,
        failure_reset_after_seconds=300.0,
        time_fn=clock,
    )
    defaults.update(overrides)
    return PersistentCooldownRateLimiter(state_path=state_path, **defaults)


def test_state_survives_a_simulated_process_restart(tmp_path: Path):
    """The core regression test: two SEPARATE limiter instances pointed at
    the same state file must share failure history, simulating two
    separate `faceauth authenticate` CLI invocations."""
    state_path = tmp_path / "rate_limit_state.json"
    clock = FakeClock()

    # "Process 1": two failures.
    limiter_a = _limiter(state_path, clock)
    limiter_a.record_failure()
    limiter_a.record_failure()

    # "Process 2": a brand new instance, same file - must see the prior 2
    # failures and trip the cooldown on its own 3rd failure.
    limiter_b = _limiter(state_path, clock)
    limiter_b.record_failure()
    with pytest.raises(RateLimitedError):
        limiter_b.check_allowed()


def test_cooldown_expires_and_persists_correctly_across_instances(tmp_path: Path):
    state_path = tmp_path / "rate_limit_state.json"
    clock = FakeClock()
    limiter_a = _limiter(state_path, clock)
    for _ in range(3):
        limiter_a.record_failure()

    limiter_b = _limiter(state_path, clock)
    with pytest.raises(RateLimitedError):
        limiter_b.check_allowed()

    clock.advance(10.01)
    limiter_c = _limiter(state_path, clock)
    limiter_c.check_allowed()  # cooldown expired - must not raise


def test_success_resets_persisted_state(tmp_path: Path):
    state_path = tmp_path / "rate_limit_state.json"
    clock = FakeClock()
    limiter_a = _limiter(state_path, clock)
    limiter_a.record_failure()
    limiter_a.record_failure()
    limiter_a.record_success()

    limiter_b = _limiter(state_path, clock)
    limiter_b.record_failure()
    limiter_b.check_allowed()  # only 1 failure since reset - must not raise


def test_missing_state_file_starts_clean(tmp_path: Path):
    state_path = tmp_path / "does_not_exist_yet.json"
    limiter = _limiter(state_path, FakeClock())
    limiter.check_allowed()  # must not raise


def test_corrupted_state_file_resets_rather_than_crashing(tmp_path: Path):
    state_path = tmp_path / "rate_limit_state.json"
    state_path.write_text("not valid json {{{", encoding="utf-8")
    limiter = _limiter(state_path, FakeClock())
    limiter.check_allowed()  # must not raise or crash
    limiter.record_failure()  # must not raise or crash


def test_state_file_missing_expected_keys_resets_rather_than_crashing(tmp_path: Path):
    state_path = tmp_path / "rate_limit_state.json"
    state_path.write_text('{"unexpected": "shape"}', encoding="utf-8")
    limiter = _limiter(state_path, FakeClock())
    limiter.check_allowed()  # must not raise or crash


def test_state_is_written_as_valid_json_on_disk(tmp_path: Path):
    import json

    state_path = tmp_path / "rate_limit_state.json"
    limiter = _limiter(state_path, FakeClock())
    limiter.record_failure()
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    assert raw["consecutive_failures"] == 1


def test_backoff_escalates_across_instances(tmp_path: Path):
    state_path = tmp_path / "rate_limit_state.json"
    clock = FakeClock()
    for _ in range(3):
        _limiter(state_path, clock).record_failure()
    first_wait = _limiter(state_path, clock).seconds_until_allowed()
    assert first_wait == pytest.approx(10.0)

    clock.advance(10.01)
    _limiter(state_path, clock).record_failure()  # 4th consecutive failure
    second_wait = _limiter(state_path, clock).seconds_until_allowed()
    assert second_wait == pytest.approx(20.0)
