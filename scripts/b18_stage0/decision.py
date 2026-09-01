"""The single decision implementation Stage 0 is allowed to use.

Every part of the Stage 0 tooling - manifest validation, analysis, the report,
and the tests - must reach a verdict through this module, and this module
reaches it through the **shipping** function:
:func:`faceauth.liveness.challenge_response.decide_blink`. Nothing here
reimplements the rule, so validation, analysis and shipping cannot drift apart.

Exactness
---------
The shipping rule is exactly::

    max(blink_scores) >= high and min(blink_scores) <= low

Both comparisons are inclusive and **exact**. An earlier revision compared
against ``high - 1e-9``, which accepted ``max=0.3999999995`` against
``high=0.40`` - a score that the shipping code rejects. A dry run whose
validator is more permissive than the system it is rehearsing produces
false confidence about the very boundary the criterion turns on.

A tolerance therefore appears in exactly one place in this codebase: the
``near_*`` helpers below, which *describe* how close a value sits to a
boundary. They never decide anything. Nothing in this module consults them.
"""

from __future__ import annotations

from typing import NamedTuple

from faceauth.liveness.challenge_response import decide_blink

#: Continuity override defaults, mirroring ``capture_utils.run_liveness_challenge``.
MIN_FRAMES_FOR_CONTINUITY_CHECK = 5

#: Descriptive only. Never used to accept, reject, or classify an outcome -
#: only to answer "how close was this to the boundary?" in a report.
NEAR_BOUNDARY = 1e-9


class Outcome(NamedTuple):
    """What the shipping stack would have recorded for a trial."""

    outcome: str  # "accepted" | "rejected"
    reason: str
    passed_blink_rule: bool  # the decision before the continuity override
    continuity_override: bool


def blink_passes(scores: list[float], high: float, low: float) -> bool:
    """The shipping blink rule, evaluated by the shipping function itself.

    ``scores`` must be non-empty; an empty observation series is not a
    decision this rule can express (see :func:`outcome_for`).
    """
    if not scores:
        raise ValueError("blink_passes requires a non-empty score series")
    return bool(decide_blink([float(s) for s in scores], float(high), float(low)).passed)


def outcome_for(
    scores: list[float],
    high: float,
    low: float,
    *,
    frames_captured: int,
    frames_with_face: int,
    min_face_continuity: float,
    min_frames_for_continuity_check: int = MIN_FRAMES_FOR_CONTINUITY_CHECK,
) -> Outcome:
    """Recompute a trial's outcome exactly as the shipping stack would.

    Mirrors ``capture_utils.run_liveness_challenge``: the blink rule decides,
    then the continuity check may override a pass into
    ``face_detection_unstable``. The override is fail-closed - it can only turn
    a pass into a failure, never the reverse.
    """
    if not scores:
        return Outcome("rejected", "no_face_observed_during_challenge", False, False)

    passed = blink_passes(scores, high, low)
    override = (
        passed
        and frames_captured >= min_frames_for_continuity_check
        and (frames_with_face / frames_captured) < float(min_face_continuity)
    )
    final = passed and not override
    if final:
        return Outcome("accepted", "blink_detected", passed, override)
    if override:
        return Outcome("rejected", "face_detection_unstable", passed, override)
    return Outcome("rejected", "no_transient_blink_detected", passed, override)


def reaches_high(value: float, high: float) -> bool:
    """Exactly the shipping comparison, for a single maximum."""
    return float(value) >= float(high)


def reaches_low(value: float, low: float) -> bool:
    """Exactly the shipping comparison, for a single minimum."""
    return float(value) <= float(low)


def near_boundary(value: float, boundary: float, tolerance: float = NEAR_BOUNDARY) -> bool:
    """Descriptive label only: is ``value`` within ``tolerance`` of ``boundary``?

    Never consulted by any decision in this package. It exists so a report can
    say "this sat on the boundary" without that observation changing anything.
    """
    return abs(float(value) - float(boundary)) <= tolerance
