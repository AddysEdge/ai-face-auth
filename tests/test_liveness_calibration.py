"""Unit tests for the pure blink/head-turn decision logic, grounded in real
values captured from a live webcam via scripts/calibrate_liveness.py.

The head-turn algorithm and both thresholds were redesigned after a live
enrollment test found the original design (absolute-zero-baseline
requirement, head_turn_min_ratio=0.25) failed 0/12 real attempts. Real
diagnostic data showed:
  - turn_ratio ranged roughly -0.006 to +0.084 during genuine head movement
    (peak swing ~0.09), with a persistent non-zero resting baseline
    (~0.04-0.08) due to camera-angle bias - i.e. never near true zero even
    at rest.
  - blink_score ranged roughly 0.05 (open) to ~0.49 (during a blink).
These tests encode that evidence directly, so a future change to the
thresholds must be justified against it (or superseding real data), not
just asserted.
"""

from __future__ import annotations

import pytest

from faceauth.liveness.challenge_response import decide_blink, decide_head_turn
from faceauth.pipeline_types import ChallengeKind

# Real values from a live scripts/calibrate_liveness.py run (see module docstring).
REAL_RESTING_TURN_RATIOS = [0.075, 0.084, 0.082, 0.080, 0.048, 0.067, 0.044, 0.047]
REAL_DELIBERATE_TURN_RATIOS = [0.019, 0.011, 0.008, 0.001, 0.016, 0.038, 0.050, 0.059]
REAL_BLINK_OPEN_SCORES = [0.181, 0.202, 0.245, 0.258, 0.135, 0.055]
REAL_BLINK_CLOSED_PEAK = 0.489

# Second, cleaner calibration pass with an explicit two-phase protocol (hold
# still, THEN turn and hold) rather than an ambiguous continuous trace - see
# docs/RESEARCH.md. True rest is a tight ~0.01 swing; a deliberate turn
# swings far beyond it (~0.12 relative to the resting baseline).
REAL_CLEAN_RESTING_TURN_RATIOS = [0.023, 0.022, 0.019, 0.021, 0.020, 0.019, 0.022, 0.026, 0.027, 0.020]
REAL_CLEAN_DELIBERATE_TURN_RATIOS = [0.048, 0.063, 0.076, 0.084, 0.098, 0.111, 0.115, 0.121, 0.128, 0.140]

# A third live trial: a genuinely stationary (propped, not hand-held)
# spoof photo recorded for 10s. blink_score stayed safely bounded the
# entire window; turn_ratio spiked to +0.123 at one point from ordinary
# camera/environmental jitter alone - no deliberate manipulation. This is
# why BLINK is the sole default challenge (DEFAULT_ENABLED_CHALLENGES in
# challenge_response.py) - see docs/THREAT_MODEL.md section 2.
REAL_STATIONARY_SPOOF_BLINK_SCORES = [
    0.218, 0.292, 0.267, 0.278, 0.269, 0.258, 0.245, 0.250, 0.274, 0.294,
    0.311, 0.270, 0.199, 0.230, 0.211, 0.254, 0.288, 0.260, 0.284, 0.245,
    0.258, 0.276, 0.299, 0.234, 0.290, 0.235, 0.377, 0.382, 0.321, 0.376,
    0.285, 0.236, 0.224, 0.191, 0.168, 0.253, 0.223, 0.209, 0.234, 0.223,
]
REAL_STATIONARY_SPOOF_TURN_RATIOS = [
    0.039, 0.035, 0.033, 0.028, 0.029, 0.033, 0.037, 0.038, 0.029, 0.026,
    0.036, 0.033, 0.029, 0.031, 0.040, -0.010, -0.017, -0.023, 0.005, 0.063,
    0.083, 0.123, 0.120, 0.111, 0.090, 0.076, 0.055, 0.010, 0.018,
]

# A fourth trial: real deliberate blinks (3-4 over 10s) with a real face.
# Confirmed the actual bottleneck was the low threshold, not the high one -
# every real blink peak cleared 0.40 by a wide margin (many reaching
# 0.5-0.75), but the open-eye baseline commonly sat 0.20-0.30 and only
# occasionally dipped near 0.15, making the original blink_score_low=0.15
# an unreliable gate. blink_score_low was raised to 0.20 as a result - see
# config.py. This subset spans one real peak-to-valley-to-peak cycle
# (t=7.0s-8.8s of that trial).
REAL_DELIBERATE_BLINK_SEQUENCE = [
    0.259, 0.232, 0.185, 0.148, 0.174, 0.293, 0.671, 0.538, 0.411, 0.343,
    0.297, 0.257, 0.250, 0.227, 0.223, 0.205, 0.206, 0.161, 0.165, 0.189,
    0.157, 0.174, 0.216, 0.227, 0.240, 0.287, 0.747, 0.722, 0.597,
]

DEFAULT_BLINK_HIGH = 0.40
DEFAULT_BLINK_LOW = 0.20
DEFAULT_HEAD_TURN_MIN_SWING = 0.045


def test_default_thresholds_pass_a_real_recorded_blink():
    scores = REAL_BLINK_OPEN_SCORES + [REAL_BLINK_CLOSED_PEAK] + REAL_BLINK_OPEN_SCORES
    result = decide_blink(scores, DEFAULT_BLINK_HIGH, DEFAULT_BLINK_LOW)
    assert result.passed, result.details


def test_default_thresholds_reject_a_static_photo_blink_reading():
    """A static photo/screen produces a constant reading for the whole
    window - it can never satisfy both the high and low thresholds."""
    constant_scores = [0.2] * 10
    result = decide_blink(constant_scores, DEFAULT_BLINK_HIGH, DEFAULT_BLINK_LOW)
    assert not result.passed


def test_default_thresholds_pass_a_real_recorded_head_turn_swing():
    """The two real segments together span the full observed swing
    (resting baseline ~0.08 down to a deliberate-turn low of ~0.001, up to
    ~0.059) - real data that must clear the default swing threshold."""
    turns = REAL_RESTING_TURN_RATIOS + REAL_DELIBERATE_TURN_RATIOS
    result_right = decide_head_turn(turns, ChallengeKind.TURN_HEAD_RIGHT, DEFAULT_HEAD_TURN_MIN_SWING)
    result_left = decide_head_turn(turns, ChallengeKind.TURN_HEAD_LEFT, DEFAULT_HEAD_TURN_MIN_SWING)
    # Swing is direction-agnostic (max-min along the signed axis), so both
    # directions see the same real recorded swing and must pass identically.
    assert result_right.passed, result_right.details
    assert result_left.passed, result_left.details


def test_default_thresholds_reject_a_static_photo_head_turn_reading():
    constant_turns = [0.06] * 10  # a static photo held at a fixed angle
    result = decide_head_turn(constant_turns, ChallengeKind.TURN_HEAD_RIGHT, DEFAULT_HEAD_TURN_MIN_SWING)
    assert not result.passed


def test_head_turn_old_absolute_threshold_would_have_rejected_real_data():
    """Regression documentation: the OLD design (require an absolute value
    >= 0.25, starting near absolute zero) would have failed even on this
    real, genuine head-turn data - proving the redesign, not just the
    number, was necessary."""
    turns = REAL_RESTING_TURN_RATIOS + REAL_DELIBERATE_TURN_RATIOS
    old_absolute_threshold = 0.25
    max_observed = max(abs(t) for t in turns)
    assert max_observed < old_absolute_threshold


def test_clean_resting_phase_alone_does_not_falsely_pass():
    """The tightly-controlled 'hold still' phase (spread ~0.01) must not by
    itself satisfy the swing threshold - only genuine motion should."""
    result = decide_head_turn(
        REAL_CLEAN_RESTING_TURN_RATIOS, ChallengeKind.TURN_HEAD_RIGHT, DEFAULT_HEAD_TURN_MIN_SWING
    )
    assert not result.passed, result.details


def test_clean_deliberate_turn_phase_passes_with_margin():
    """The controlled 'turn and hold' phase clears the threshold with a
    wide margin (~2.5x), not just barely."""
    result = decide_head_turn(
        REAL_CLEAN_DELIBERATE_TURN_RATIOS, ChallengeKind.TURN_HEAD_RIGHT, DEFAULT_HEAD_TURN_MIN_SWING
    )
    assert result.passed
    assert result.details["swing"] > DEFAULT_HEAD_TURN_MIN_SWING * 2


def test_head_turn_swing_is_symmetric_regardless_of_requested_direction():
    turns = [-0.02, 0.03, -0.01, 0.05, 0.0]
    right = decide_head_turn(turns, ChallengeKind.TURN_HEAD_RIGHT, 0.06)
    left = decide_head_turn(turns, ChallengeKind.TURN_HEAD_LEFT, 0.06)
    assert right.details["swing"] == pytest.approx(0.07)
    assert left.details["swing"] == pytest.approx(0.07)


def test_blink_correctly_rejects_a_genuinely_stationary_spoof_photo():
    """The security-positive finding: on real data from a truly motionless
    spoof, blink_score never approached the high threshold. The anti-spoof
    property rests entirely on blink_score_high (0.40 vs. the spoof's
    observed peak of 0.382) - the low threshold alone (0.20) is crossed by
    this data (min 0.168), which is fine and expected: the low threshold is
    a usability/transience check, not the spoof-resistance boundary."""
    result = decide_blink(REAL_STATIONARY_SPOOF_BLINK_SCORES, DEFAULT_BLINK_HIGH, DEFAULT_BLINK_LOW)
    assert not result.passed
    assert result.details["max_blink"] < DEFAULT_BLINK_HIGH


def test_default_thresholds_pass_a_real_deliberate_blink_cycle():
    """The usability fix, verified: with blink_score_low raised to 0.20,
    a real peak-to-valley-to-peak blink cycle from live data now passes."""
    result = decide_blink(REAL_DELIBERATE_BLINK_SEQUENCE, DEFAULT_BLINK_HIGH, DEFAULT_BLINK_LOW)
    assert result.passed, result.details


def test_head_turn_incorrectly_accepts_the_same_stationary_spoof_photo():
    """Documents the real, confirmed gap: the exact same stationary-spoof
    trial's turn_ratio crossed the swing threshold from ordinary jitter
    alone. This is why head-turn is excluded from
    DEFAULT_ENABLED_CHALLENGES - this test pins the evidence, not the
    (undesirable) behavior as something to preserve."""
    result = decide_head_turn(
        REAL_STATIONARY_SPOOF_TURN_RATIOS, ChallengeKind.TURN_HEAD_RIGHT, DEFAULT_HEAD_TURN_MIN_SWING
    )
    assert result.passed  # confirmed vulnerability, not a desired outcome
