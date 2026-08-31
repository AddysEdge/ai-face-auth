"""Tests for the landmark model's face-presence gate.

The published v1.0.0 graph does not accept landmarks because the face detector
fired. `face_landmarks_detector_graph.cc` splits the landmark model's output
tensors (kFaceLandmarksOutputTensorsNum = 2, so presence is the tensor at
declared output index 1), sigmoids the presence logit via
`TensorsToFloatsCalculator`, thresholds it with `ThresholdingCalculator` at
`min_detection_confidence` (default 0.5), and gates both the projected
landmarks and the blendshapes behind that flag with `AllowIf`.

`ThresholdingCalculator::Process` computes

    accept = static_cast<double>(value) > threshold_

so the comparison is **strictly** greater and a score of exactly 0.5 rejects.

These tests drive the gate with a fake interpreter, so they need no model
weights and run everywhere. The oracle-backed cases live in
`tests/test_real_models.py`.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from faceauth.exceptions import ModelInferenceError, ModelInitializationError
from faceauth.liveness import litert_landmarker as lm
from faceauth.liveness.litert_landmarker import LiteRtFaceLandmarker

LANDMARK_VALUES = lm._NUM_LANDMARKS * 3
RECT = (0.5, 0.5, 0.4, 0.5, 0.0)


class FakeInterpreter:
    """Minimal stand-in: returns whatever tensors the test asked for."""

    def __init__(self, tensors: dict[int, np.ndarray]):
        self._tensors = tensors
        self.invocations = 0

    def get_input_details(self):
        return [{"index": 0}]

    def set_tensor(self, index, tensor):  # noqa: ARG002
        pass

    def invoke(self):
        self.invocations += 1

    def get_tensor(self, index):
        return self._tensors[index]


def _landmarker(presence_logit: float, landmarks: np.ndarray | None = None):
    """A landmarker wired to a fake interpreter, bypassing model loading."""
    if landmarks is None:
        landmarks = np.tile(np.float32([128.0, 128.0, 0.0]), lm._NUM_LANDMARKS)
    instance = object.__new__(LiteRtFaceLandmarker)
    instance._landmarks = FakeInterpreter(
        {
            10: landmarks.reshape(1, 1, 1, LANDMARK_VALUES).astype(np.float32),
            11: np.float32([[presence_logit]]),
        }
    )
    instance._landmark_output = {"index": 10}
    instance._presence_output = {"index": 11}
    return instance


def _image() -> np.ndarray:
    return np.full((480, 480, 3), 200, np.uint8)


# ------------------------------------------------------------------ sigmoid


@pytest.mark.parametrize("logit", [-800.0, -50.0, -1.0, 0.0, 1.0, 50.0, 800.0])
def test_sigmoid_matches_the_reference_definition_without_overflowing(logit):
    """Stable in both tails; exp(800) would overflow a naive implementation."""
    value = LiteRtFaceLandmarker._sigmoid(logit)
    assert 0.0 <= value <= 1.0
    if abs(logit) <= 50.0:
        assert value == pytest.approx(1.0 / (1.0 + math.exp(-logit)), abs=1e-12)


def test_sigmoid_of_zero_is_exactly_one_half():
    """The boundary the threshold is defined against."""
    assert LiteRtFaceLandmarker._sigmoid(0.0) == 0.5


# ------------------------------------------------------------ the threshold


def test_a_logit_below_the_threshold_is_rejected():
    landmarker = _landmarker(presence_logit=-15.0)
    assert landmarker._landmarks_for(_image(), RECT) is None


def test_a_score_of_exactly_one_half_is_rejected():
    """ThresholdingCalculator uses `>`, not `>=`, so 0.5 does not pass.

    A logit of exactly 0.0 sigmoids to exactly 0.5, which makes this boundary
    testable without relying on floating-point luck.
    """
    landmarker = _landmarker(presence_logit=0.0)
    assert LiteRtFaceLandmarker._sigmoid(0.0) == lm._PRESENCE_THRESHOLD
    assert landmarker._landmarks_for(_image(), RECT) is None


def test_a_score_just_above_the_threshold_continues():
    landmarker = _landmarker(presence_logit=1e-6)
    result = landmarker._landmarks_for(_image(), RECT)
    assert result is not None
    landmarks, score = result
    assert score > lm._PRESENCE_THRESHOLD
    assert landmarks.shape == (lm._NUM_LANDMARKS, 2)


def test_a_clearly_present_face_continues():
    landmarker = _landmarker(presence_logit=10.28)
    result = landmarker._landmarks_for(_image(), RECT)
    assert result is not None
    assert result[1] == pytest.approx(0.99996, abs=1e-4)


# ----------------------------------------------------------- fail closed


@pytest.mark.parametrize("logit", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_presence_fails_closed(logit):
    """+inf would sigmoid to 1.0 and sail through the gate.

    Treating a broken model as a confident accept is the exact failure this
    check exists to prevent, so non-finite is an error rather than a value.
    """
    landmarker = _landmarker(presence_logit=logit)
    with pytest.raises(ModelInferenceError, match="not finite"):
        landmarker._landmarks_for(_image(), RECT)


def test_non_finite_landmarks_fail_closed():
    corrupt = np.tile(np.float32([128.0, 128.0, 0.0]), lm._NUM_LANDMARKS)
    corrupt[0] = np.nan
    landmarker = _landmarker(presence_logit=10.0, landmarks=corrupt)
    with pytest.raises(ModelInferenceError, match="non-finite"):
        landmarker._landmarks_for(_image(), RECT)


def test_a_wrong_sized_landmark_tensor_at_inference_fails_closed():
    landmarker = _landmarker(presence_logit=10.0)
    landmarker._landmarks._tensors[10] = np.zeros((1, 1, 1, 99), np.float32)
    with pytest.raises(ModelInferenceError, match="expected 1434"):
        landmarker._landmarks_for(_image(), RECT)


def test_a_non_scalar_presence_tensor_at_inference_fails_closed():
    landmarker = _landmarker(presence_logit=10.0)
    landmarker._landmarks._tensors[11] = np.zeros((1, 4), np.float32)
    with pytest.raises(ModelInferenceError, match="expected 1"):
        landmarker._landmarks_for(_image(), RECT)


# --------------------------------------------------- output-layout checking


def _detail(index: int, shape: tuple[int, ...], dtype=np.float32, name: str = "x"):
    return {"index": index, "name": name, "shape": np.array(shape), "dtype": dtype}


def test_the_real_layout_resolves():
    """The shipped bundle's layout, as recorded by inspection."""
    details = [
        _detail(473, (1, 1, 1, 1434), name="Identity"),
        _detail(472, (1, 1, 1, 1), name="Identity_1"),
        _detail(475, (1, 1), name="Identity_2"),
    ]
    landmark, presence = LiteRtFaceLandmarker._resolve_landmark_outputs(details)
    assert landmark["name"] == "Identity"
    assert presence["name"] == "Identity_1"


def test_too_few_outputs_fails_closed():
    with pytest.raises(ModelInitializationError, match="at least 2"):
        LiteRtFaceLandmarker._resolve_landmark_outputs([_detail(0, (1, 1434))])


def test_a_missing_landmark_tensor_fails_closed():
    details = [_detail(0, (1, 1)), _detail(1, (1, 1))]
    with pytest.raises(ModelInitializationError, match="found 0"):
        LiteRtFaceLandmarker._resolve_landmark_outputs(details)


def test_a_duplicate_landmark_tensor_fails_closed():
    """Two candidates means the choice would be a guess."""
    details = [_detail(0, (1, 1434)), _detail(1, (1, 1434)), _detail(2, (1, 1))]
    with pytest.raises(ModelInitializationError, match="found 2"):
        LiteRtFaceLandmarker._resolve_landmark_outputs(details)


def test_a_landmark_tensor_at_the_wrong_index_fails_closed():
    """The published graph splits on position, so position must hold."""
    details = [_detail(0, (1, 1)), _detail(1, (1, 1434)), _detail(2, (1, 1))]
    with pytest.raises(ModelInitializationError, match="not at the declared output index"):
        LiteRtFaceLandmarker._resolve_landmark_outputs(details)


def test_a_non_scalar_presence_output_fails_closed():
    details = [_detail(0, (1, 1434)), _detail(1, (1, 7))]
    with pytest.raises(ModelInitializationError, match="face-presence output has 7"):
        LiteRtFaceLandmarker._resolve_landmark_outputs(details)


@pytest.mark.parametrize("dtype", [np.float64, np.int32, np.uint8])
def test_a_wrong_presence_dtype_fails_closed(dtype):
    details = [_detail(0, (1, 1434)), _detail(1, (1, 1), dtype=dtype)]
    with pytest.raises(ModelInitializationError, match="face-presence output has dtype"):
        LiteRtFaceLandmarker._resolve_landmark_outputs(details)


def test_a_wrong_landmark_dtype_fails_closed():
    details = [_detail(0, (1, 1434), dtype=np.float64), _detail(1, (1, 1))]
    with pytest.raises(ModelInitializationError, match="landmark output has dtype"):
        LiteRtFaceLandmarker._resolve_landmark_outputs(details)


# --------------------------------------------- the gate short-circuits work


def test_blendshapes_are_not_computed_after_a_presence_rejection():
    """The published graph gates blendshapes behind the same flag.

    Scoring a crop the landmark stage disowned would invent a signal the
    reference pipeline never produces - and it is the blink score, which the
    liveness decision reads directly.
    """
    landmarker = _landmarker(presence_logit=-15.0)
    landmarker._detect = lambda _rgb: [
        {"score": 0.9, "xmin": 0.3, "ymin": 0.3, "xmax": 0.7, "ymax": 0.7,
         "keypoints": [(0.4, 0.45), (0.6, 0.45)] + [(0.5, 0.5)] * 4}
    ]
    calls: list[tuple] = []
    landmarker._blendshapes_for = lambda *args: calls.append(args)

    assert landmarker.detect(_image()) is None
    assert calls == [], "the blendshape model must not run after a rejection"


def test_a_passing_gate_does_reach_the_blendshape_model():
    """The negative test above would pass trivially if nothing ever ran."""
    landmarker = _landmarker(presence_logit=10.0)
    landmarker._detect = lambda _rgb: [
        {"score": 0.9, "xmin": 0.3, "ymin": 0.3, "xmax": 0.7, "ymax": 0.7,
         "keypoints": [(0.4, 0.45), (0.6, 0.45)] + [(0.5, 0.5)] * 4}
    ]
    calls: list[tuple] = []
    landmarker._blendshapes_for = lambda *args: (calls.append(args), {"eyeBlinkLeft": 0.1})[1]

    result = landmarker.detect(_image())
    assert result is not None
    assert len(calls) == 1
    assert result["presence_score"] == pytest.approx(0.9999546, abs=1e-6)


def test_the_result_carries_the_presence_score_and_no_image_data():
    landmarker = _landmarker(presence_logit=3.0)
    landmarker._detect = lambda _rgb: [
        {"score": 0.9, "xmin": 0.3, "ymin": 0.3, "xmax": 0.7, "ymax": 0.7,
         "keypoints": [(0.4, 0.45), (0.6, 0.45)] + [(0.5, 0.5)] * 4}
    ]
    landmarker._blendshapes_for = lambda *_a: {"eyeBlinkLeft": 0.0, "eyeBlinkRight": 0.0}
    result = landmarker.detect(_image())
    assert set(result) == {"landmarks", "blendshapes", "score", "presence_score"}
    assert result["presence_score"] == pytest.approx(0.95257, abs=1e-5)


# ------------------------------------------------- the provider's behaviour


def test_the_liveness_provider_records_no_observation_after_a_rejection():
    """A rejected frame must not enter the blink/turn series at all."""
    from faceauth.liveness.challenge_response import LiteRtChallengeResponseLiveness
    from faceauth.pipeline_types import FaceBox, Frame

    provider = object.__new__(LiteRtChallengeResponseLiveness)
    provider._challenge = None
    provider._observations = []
    provider._landmarker = type("R", (), {"detect": staticmethod(lambda _rgb: None)})()
    provider._challenge = __import__(
        "faceauth.pipeline_types", fromlist=["ChallengeKind"]
    ).ChallengeKind.BLINK

    face = FaceBox(x=1.0, y=1.0, width=10.0, height=10.0, confidence=0.9,
                   landmarks=((1, 1), (2, 1), (1, 2), (2, 2), (1, 3)))
    provider.observe(Frame(image=_image(), timestamp=0.0), face)
    assert provider._observations == []
