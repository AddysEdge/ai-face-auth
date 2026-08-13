"""Shared capture-loop helper used by both enrollment and authentication.

Runs a bounded capture loop, feeding every frame that has exactly one
quality-passing face into the liveness provider, and keeps the most recent
such (frame, face) pair as the candidate to embed. Bounded primarily by a
**wall-clock deadline** (``deadline_seconds``), with ``max_frames`` only as
a safety cap against a pathological runaway - not the other way around.

This distinction matters and was fixed after a real live-hardware test: an
earlier version bounded purely by frame count (30 frames), which was
originally sized assuming roughly a 4-second window, but on real hardware
the full detect+quality+landmark pipeline runs fast enough that 30 frames
only spans about 1.0 second (confirmed from real log timestamps during
enrollment testing) - far too short for a human to read which challenge is
active and react. Bounding by wall-clock time makes the window's actual
duration match ``LivenessConfig.challenge_timeout_seconds`` regardless of
how fast the hardware happens to be. ``time_fn`` is injectable so this
stays deterministic and unit-testable (see docs/RESEARCH.md section 15) -
a fake clock advances synchronously with a fake camera feed in tests,
rather than requiring a real sleep.

Any CameraUnavailableError/ModelInferenceError raised by a stage propagates
to the caller rather than being swallowed here - callers (enrollment.py,
authentication.py) are responsible for converting that into an explicit
DENY/failure outcome, never an implicit success.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from faceauth.interfaces.camera import CameraProvider
from faceauth.interfaces.detector import FaceDetector
from faceauth.interfaces.liveness import LivenessProvider
from faceauth.interfaces.quality import FaceQualityChecker
from faceauth.pipeline_types import ChallengeKind, DemoState, FaceBox, Frame, LivenessResult


@dataclass(frozen=True)
class ChallengeCaptureOutcome:
    liveness_result: LivenessResult
    best_frame: Frame | None
    best_face: FaceBox | None


def run_liveness_challenge(
    camera: CameraProvider,
    detector: FaceDetector,
    quality_checker: FaceQualityChecker,
    liveness: LivenessProvider,
    max_frames: int,
    deadline_seconds: float,
    on_state: Callable[[DemoState], None] | None = None,
    on_challenge: Callable[[ChallengeKind], None] | None = None,
    time_fn: Callable[[], float] = time.monotonic,
    min_face_continuity: float = 0.5,
    min_frames_for_continuity_check: int = 5,
) -> ChallengeCaptureOutcome:
    """``on_state``/``on_challenge`` are optional UI progress callbacks (see
    demo_ui.py and cli.py) - neither affects the security decision, only
    what a caller displays while this runs.

    ``min_face_continuity`` is a fail-closed override, never a way to turn a
    failure into a pass: added after a live spoof test found that physically
    waving a phone/printed photo around in front of the camera produces the
    same kind of 2D landmark shifts (nose position, apparent head angle)
    that a genuine head-turn produces - a purely-2D-landmark liveness check
    cannot structurally tell "the head turned" apart from "a flat image was
    moved/re-angled." The real spoof-attempt trace that exposed this showed
    repeated face-detection dropouts (the phone briefly left frame or was
    detected at very different positions) that a continuously-present live
    human would not produce. If face detection wasn't continuous enough
    during the window, the attempt is rejected regardless of what the
    liveness signal itself concluded. See docs/THREAT_MODEL.md section 2/3
    for the full, honest discussion of what this does and does not fix.
    """
    if on_state is not None:
        on_state(DemoState.CHECKING_LIVENESS)
    challenge = liveness.new_challenge()
    if on_challenge is not None:
        on_challenge(challenge)

    best: tuple[Frame, FaceBox] | None = None
    face_seen = False
    start = time_fn()
    frames_captured = 0
    frames_with_face = 0

    while frames_captured < max_frames and (time_fn() - start) < deadline_seconds:
        frame = camera.read()
        frames_captured += 1
        faces = detector.detect(frame.image)
        if len(faces) != 1:
            continue
        frames_with_face += 1
        face = faces[0]
        quality = quality_checker.check(frame.image, face)
        if not quality.passed:
            continue
        if not face_seen and on_state is not None:
            on_state(DemoState.FACE_DETECTED)
            face_seen = True
        liveness.observe(frame, face)
        best = (frame, face)

    result = liveness.finalize()

    if (
        result.passed
        and frames_captured >= min_frames_for_continuity_check
        and (frames_with_face / frames_captured) < min_face_continuity
    ):
        result = LivenessResult(
            passed=False,
            reason="face_detection_unstable",
            details={**result.details, "face_continuity": frames_with_face / frames_captured},
        )

    if best is None:
        return ChallengeCaptureOutcome(liveness_result=result, best_frame=None, best_face=None)
    return ChallengeCaptureOutcome(
        liveness_result=result, best_frame=best[0], best_face=best[1]
    )
