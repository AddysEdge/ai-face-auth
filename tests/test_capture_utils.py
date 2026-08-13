"""Regression coverage for run_liveness_challenge's wall-clock deadline.

Added after a real live-webcam test found the previous frame-count-only
bound (30 frames) silently produced only ~1.0s of real window on fast
hardware - far too short for a human to react to an unannounced challenge.
See capture_utils.py's module docstring and docs/RESEARCH.md for the full
diagnosis. These tests prove the loop is now bounded by wall-clock time
first, with frame count only as a safety cap, and that the active
challenge is announced through ``on_challenge`` in real time.
"""

from __future__ import annotations

import numpy as np
import pytest

from faceauth.capture_utils import run_liveness_challenge
from faceauth.exceptions import CameraUnavailableError
from faceauth.pipeline_types import ChallengeKind
from tests.conftest import (
    AlwaysOneFaceDetector,
    FakeCamera,
    FakeDetector,
    FakeLiveness,
    FakeQualityChecker,
    make_face_box,
)


class SteppingClock:
    """Deterministic fake clock: each call advances by ``step`` seconds."""

    def __init__(self, step: float = 0.1):
        self._t = 0.0
        self._step = step

    def __call__(self) -> float:
        value = self._t
        self._t += self._step
        return value


def test_deadline_bounds_the_loop_even_with_a_huge_frame_budget():
    """Regression test for the real bug: frame count must not be the
    effective bound when it's set far higher than the deadline allows."""
    camera = FakeCamera()  # 200 frames available - far more than should be read
    camera.open()
    outcome = run_liveness_challenge(
        camera,
        AlwaysOneFaceDetector(),
        FakeQualityChecker(passed=True),
        FakeLiveness(passed=True),
        max_frames=1000,  # deliberately large - must NOT be the limiting factor
        deadline_seconds=0.5,
        time_fn=SteppingClock(step=0.1),
    )
    assert camera.read_count < 10  # bounded by the 0.5s deadline, not 1000 frames
    assert outcome.liveness_result.passed


def test_frame_count_still_caps_a_runaway_clock():
    """Safety-cap regression: if the clock never advances (or advances too
    slowly), max_frames must still prevent an infinite loop."""
    camera = FakeCamera()
    camera.open()
    run_liveness_challenge(
        camera,
        AlwaysOneFaceDetector(),
        FakeQualityChecker(passed=True),
        FakeLiveness(passed=True),
        max_frames=7,
        deadline_seconds=999.0,  # effectively unbounded by time
        time_fn=SteppingClock(step=0.0),  # clock never advances
    )
    assert camera.read_count == 7


def test_on_challenge_fires_with_the_actual_chosen_challenge():
    seen: list[ChallengeKind] = []
    liveness = FakeLiveness(passed=True)
    camera = FakeCamera()
    camera.open()
    run_liveness_challenge(
        camera,
        AlwaysOneFaceDetector(),
        FakeQualityChecker(passed=True),
        liveness,
        max_frames=3,
        deadline_seconds=5.0,
        on_challenge=seen.append,
    )
    assert seen == [ChallengeKind.BLINK]  # FakeLiveness always issues BLINK


def test_low_face_continuity_overrides_a_pass_to_denied():
    """Regression test for a real spoof finding: physically moving a photo/
    phone in front of the camera causes repeated detection dropouts. Even
    if the underlying liveness signal claims 'passed', low continuity must
    override it to a fail - never the other way around."""
    # 10 frames: face detected in only 3 of them (30% continuity, below the
    # default 0.5 threshold) - mirrors the real spoof trace's dropout pattern.
    script = [[make_face_box()] if i in (0, 4, 8) else [] for i in range(10)]
    camera = FakeCamera(frames=[np.zeros((2, 2, 3), np.uint8)] * 10)
    camera.open()
    outcome = run_liveness_challenge(
        camera,
        FakeDetector(script=script),
        FakeQualityChecker(passed=True),
        FakeLiveness(passed=True),  # underlying signal says "passed"
        max_frames=10,
        deadline_seconds=5.0,
    )
    assert not outcome.liveness_result.passed
    assert outcome.liveness_result.reason == "face_detection_unstable"
    assert outcome.liveness_result.details["face_continuity"] == pytest.approx(0.3)


def test_high_face_continuity_does_not_override_a_pass():
    script = [[make_face_box()]] * 9 + [[]]  # 90% continuity
    camera = FakeCamera(frames=[np.zeros((2, 2, 3), np.uint8)] * 10)
    camera.open()
    outcome = run_liveness_challenge(
        camera,
        FakeDetector(script=script),
        FakeQualityChecker(passed=True),
        FakeLiveness(passed=True),
        max_frames=10,
        deadline_seconds=5.0,
    )
    assert outcome.liveness_result.passed


def test_continuity_check_never_turns_a_genuine_failure_into_a_pass():
    """Fail-closed guarantee: continuity only ever downgrades pass->fail,
    never upgrades fail->pass."""
    camera = FakeCamera()
    camera.open()
    outcome = run_liveness_challenge(
        camera,
        AlwaysOneFaceDetector(),  # perfect continuity
        FakeQualityChecker(passed=True),
        FakeLiveness(passed=False, reason="genuinely_failed"),
        max_frames=10,
        deadline_seconds=5.0,
    )
    assert not outcome.liveness_result.passed
    assert outcome.liveness_result.reason == "genuinely_failed"  # not overridden


def test_continuity_check_skipped_below_minimum_frame_count():
    """With very few captured frames, the continuity ratio is too noisy to
    be meaningful - the check should not fire at all."""
    script = [[]] * 3  # 0% continuity, but only 3 frames captured
    camera = FakeCamera(frames=[np.zeros((2, 2, 3), np.uint8)] * 3)
    camera.open()
    outcome = run_liveness_challenge(
        camera,
        FakeDetector(script=script),
        FakeQualityChecker(passed=True),
        FakeLiveness(passed=True),
        max_frames=3,
        deadline_seconds=5.0,
        min_frames_for_continuity_check=5,
    )
    assert outcome.liveness_result.passed  # not overridden - too few frames to judge


def test_camera_read_errors_propagate_rather_than_being_swallowed():
    camera = FakeCamera(frames=[])  # exhausted immediately
    camera.open()
    try:
        with pytest.raises(CameraUnavailableError):
            run_liveness_challenge(
                camera,
                AlwaysOneFaceDetector(),
                FakeQualityChecker(passed=True),
                FakeLiveness(passed=True),
                max_frames=5,
                deadline_seconds=5.0,
            )
    finally:
        camera.close()
