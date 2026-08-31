"""Active challenge-response liveness via the MediaPipe Face Landmarker models.

The *models* are MediaPipe's, downloaded as the pinned ``face_landmarker.task``
bundle. The *runtime* is not: the graph around those weights is reimplemented
in ``faceauth.liveness.litert_landmarker`` on top of ``ai-edge-litert``,
because the MediaPipe wheel uploads usage telemetry to ``play.googleapis.com``
on session teardown with no supported way to disable it, which blocks
acceptance criterion B17. Thresholds, landmark indices, and the decision
functions below are unchanged by that switch - see
``docs/PHASE2_5_B17_RESEARCH.md`` for the measured agreement between the two
runtimes on the same weights.

This is the primary, default liveness signal (see docs/RESEARCH.md section 3
for why: it is deterministic, testable, and does not depend on a stale
pretrained spoof-classifier checkpoint). It issues a randomized challenge
(blink, or turn head left/right) and requires a *transient* signal within
the observation window: for blink, the tracked value must rise above a high
threshold and also dip at/below a low threshold (proving both "closed" and
"open" were observed); for head-turn, the signed ratio must *swing* by at
least a minimum amount in the requested direction (see the swing-based
design note in ``finalize()`` - an absolute-zero-baseline requirement turned
out to be unusable in practice, see docs/RESEARCH.md). That transience
requirement is what defeats a static printed photo or a frozen phone/display
image: a static image produces a constant reading for the whole window, and
a photo/screen cannot blink or turn on command at all.

Landmark indices used (MediaPipe FaceMesh's fixed canonical topology):
  - 1   : nose tip
  - 33  : right eye, outer corner
  - 263 : left eye, outer corner
Blendshape categories used: "eyeBlinkLeft", "eyeBlinkRight" (standard
ARKit-aligned blendshape names MediaPipe's Face Landmarker outputs).

Limitation stated plainly (also see docs/THREAT_MODEL.md and README): this
defeats static photo/display attacks but does NOT reliably defeat a video
replay of the legitimate user performing the same action.
"""

from __future__ import annotations

import random
from pathlib import Path

import cv2
import numpy as np

from faceauth.exceptions import LivenessError, ModelInferenceError, ModelInitializationError
from faceauth.interfaces.liveness import LivenessProvider
from faceauth.liveness.litert_landmarker import LiteRtFaceLandmarker
from faceauth.pipeline_types import ChallengeKind, FaceBox, Frame, LivenessResult

_NOSE_TIP_IDX = 1
_RIGHT_EYE_OUTER_IDX = 33
_LEFT_EYE_OUTER_IDX = 263


def _blink_score(blendshapes: dict[str, float]) -> float:
    try:
        left = blendshapes["eyeBlinkLeft"]
        right = blendshapes["eyeBlinkRight"]
    except KeyError as exc:
        raise ModelInferenceError(
            f"expected blendshape categories not present in Face Landmarker output: {exc}"
        ) from exc
    return (left + right) / 2.0


def _turn_ratio(landmarks: np.ndarray) -> float:
    """Signed nose offset between the eye corners, in inter-eye units.

    ``landmarks`` is the (478, 2) image-normalized array; indices 1 / 33 / 263
    are FaceMesh's fixed canonical topology and are unchanged from the
    MediaPipe-runtime implementation.
    """
    nose_x = float(landmarks[_NOSE_TIP_IDX][0])
    right_eye_x = float(landmarks[_RIGHT_EYE_OUTER_IDX][0])
    left_eye_x = float(landmarks[_LEFT_EYE_OUTER_IDX][0])
    eye_midpoint_x = (right_eye_x + left_eye_x) / 2.0
    inter_eye_distance = abs(left_eye_x - right_eye_x)
    if inter_eye_distance < 1e-6:
        raise ModelInferenceError("degenerate inter-eye distance from landmarks")
    return (nose_x - eye_midpoint_x) / inter_eye_distance


def decide_blink(blink_scores: list[float], high: float, low: float) -> LivenessResult:
    """Pure decision logic, factored out of finalize() so it's unit-testable
    against real calibration data without needing the Face Landmarker model
    file loaded (see docs/RESEARCH.md and tests/test_liveness_calibration.py)."""
    passed = max(blink_scores) >= high and min(blink_scores) <= low
    return LivenessResult(
        passed=passed,
        reason="blink_detected" if passed else "no_transient_blink_detected",
        details={"max_blink": max(blink_scores), "min_blink": min(blink_scores)},
    )


def decide_head_turn(turns: list[float], challenge: ChallengeKind, min_swing: float) -> LivenessResult:
    """Swing-based, not absolute-threshold: measures how far the signed
    ratio moved within the window (max - min along the requested direction)
    rather than requiring it to start near an absolute zero. Redesigned
    after live calibration (scripts/calibrate_liveness.py) found a
    persistent non-zero baseline in turn_ratio even at rest (camera-angle/
    head-pose bias specific to the test setup) - an absolute-zero
    requirement made the check nearly impossible to satisfy even with
    genuine, deliberate head turns. See docs/RESEARCH.md for the real
    measured values (peak observed swing ~0.09) that inform
    head_turn_min_swing's default."""
    direction = 1.0 if challenge is ChallengeKind.TURN_HEAD_RIGHT else -1.0
    signed = [direction * t for t in turns]
    swing = max(signed) - min(signed)
    passed = swing >= min_swing
    return LivenessResult(
        passed=passed,
        reason="head_turn_detected" if passed else "no_transient_head_turn_detected",
        details={"swing": swing},
    )


#: Default challenge pool. BLINK-only: a live spoof test found that even a
#: genuinely stationary (propped, non-hand-held) static photo can produce a
#: turn_ratio swing (+0.123 observed) that clears head_turn_min_swing
#: (0.045) - apparently from ordinary camera/environmental jitter, not even
#: deliberate manipulation - while the same trial's blink_score stayed
#: safely bounded (0.168-0.382) the entire window, never approaching either
#: blink threshold. Head-turn is not removed from the codebase (still
#: implemented, still tested) since it remains a legitimate future
#: improvement target, but it is not offered as a default security boundary
#: until it can be made robust against this failure mode - see
#: docs/THREAT_MODEL.md section 2 for the full account.
DEFAULT_ENABLED_CHALLENGES: tuple[ChallengeKind, ...] = (ChallengeKind.BLINK,)


class MediaPipeChallengeResponseLiveness(LivenessProvider):
    def __init__(
        self,
        model_asset_path: Path,
        blink_score_high: float = 0.40,
        blink_score_low: float = 0.20,
        head_turn_min_swing: float = 0.045,
        rng: random.Random | None = None,
        enabled_challenges: tuple[ChallengeKind, ...] = DEFAULT_ENABLED_CHALLENGES,
    ) -> None:
        if not enabled_challenges:
            raise ValueError("enabled_challenges must not be empty")
        if not Path(model_asset_path).exists():
            raise ModelInitializationError(
                f"Face Landmarker model bundle not found: {model_asset_path}"
            )
        try:
            self._landmarker = LiteRtFaceLandmarker(model_asset_path)
        except ModelInitializationError:
            raise
        except Exception as exc:
            raise ModelInitializationError(f"failed to load Face Landmarker: {exc}") from exc

        self._blink_score_high = blink_score_high
        self._blink_score_low = blink_score_low
        self._head_turn_min_swing = head_turn_min_swing
        self._rng = rng or random.Random()
        self._enabled_challenges = enabled_challenges

        self._challenge: ChallengeKind | None = None
        self._observations: list[dict[str, float]] = []

    def new_challenge(self) -> ChallengeKind:
        self._challenge = self._rng.choice(self._enabled_challenges)
        self._observations = []
        return self._challenge

    def observe(self, frame: Frame, face: FaceBox) -> None:
        if self._challenge is None:
            raise LivenessError("observe() called with no active challenge; call new_challenge() first")
        rgb = cv2.cvtColor(frame.image, cv2.COLOR_BGR2RGB)
        result = self._landmarker.detect(rgb)
        if result is None:
            return  # no face this instant; still within the window, just skip
        self._observations.append(
            {
                "blink": _blink_score(result["blendshapes"]),
                "turn": _turn_ratio(result["landmarks"]),
                "t": frame.timestamp,
            }
        )

    def finalize(self) -> LivenessResult:
        if self._challenge is None:
            raise LivenessError("finalize() called with no active challenge")
        challenge = self._challenge
        self._challenge = None

        if not self._observations:
            return LivenessResult(passed=False, reason="no_face_observed_during_challenge")

        if challenge is ChallengeKind.BLINK:
            blink_scores = [o["blink"] for o in self._observations]
            return decide_blink(blink_scores, self._blink_score_high, self._blink_score_low)

        turns = [o["turn"] for o in self._observations]
        return decide_head_turn(turns, challenge, self._head_turn_min_swing)
