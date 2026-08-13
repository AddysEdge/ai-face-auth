"""Integration tests against the actual downloaded ONNX/task model files.

No camera is needed - these run detection/embedding/liveness inference on
synthetic images, proving the real model files load and produce
correctly-shaped, correctly-normalized output. Skipped automatically if the
model files are not present (e.g. a fresh checkout before running
scripts/fetch_models.py).
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from faceauth.config import DEFAULT_MODELS_DIR
from faceauth.exceptions import ModelInitializationError
from faceauth.pipeline_types import FaceBox, Frame

pytestmark = pytest.mark.realmodel

YUNET_PATH = DEFAULT_MODELS_DIR / "yunet_2023mar.onnx"
SFACE_PATH = DEFAULT_MODELS_DIR / "sface_2021dec.onnx"
LANDMARKER_PATH = DEFAULT_MODELS_DIR / "face_landmarker.task"

requires_models = pytest.mark.skipif(
    not (YUNET_PATH.exists() and SFACE_PATH.exists() and LANDMARKER_PATH.exists()),
    reason="model files not downloaded; run scripts/fetch_models.py",
)


def _face() -> FaceBox:
    return FaceBox(
        x=200,
        y=150,
        width=100,
        height=120,
        confidence=0.95,
        landmarks=((230, 200), (270, 200), (250, 225), (235, 250), (265, 250)),
    )


@requires_models
def test_yunet_returns_empty_list_on_blank_image():
    from faceauth.detection.yunet_detector import YuNetFaceDetector

    detector = YuNetFaceDetector(model_path=YUNET_PATH)
    image = np.zeros((480, 640, 3), dtype=np.uint8)
    assert detector.detect(image) == []


def test_yunet_raises_model_initialization_error_on_missing_file(tmp_path: Path):
    from faceauth.detection.yunet_detector import YuNetFaceDetector

    with pytest.raises(ModelInitializationError):
        YuNetFaceDetector(model_path=tmp_path / "does_not_exist.onnx")


@requires_models
def test_sface_embedder_produces_unit_normalized_128d_embedding():
    from faceauth.embedding.sface_embedding import SFaceEmbeddingModel

    model = SFaceEmbeddingModel(model_path=SFACE_PATH)
    image = np.zeros((480, 640, 3), dtype=np.uint8)
    embedding = model.embed(image, _face())
    assert embedding.vector.shape == (128,)
    assert np.isclose(np.linalg.norm(embedding.vector), 1.0, atol=1e-3)


@requires_models
def test_sface_embedder_matches_opencv_reference_implementation():
    """Cross-checks our raw-onnxruntime preprocessing against OpenCV's own
    FaceRecognizerSF.feature() reference (see docs/RESEARCH.md section 4).
    """
    import cv2

    from faceauth.embedding.sface_embedding import SFaceEmbeddingModel, _face_box_to_yunet_row

    rng = np.random.default_rng(7)
    aligned_like_image = rng.integers(0, 255, (480, 640, 3), dtype=np.uint8)

    model = SFaceEmbeddingModel(model_path=SFACE_PATH)
    ours = model.embed(aligned_like_image, _face())

    reference = cv2.FaceRecognizerSF_create(str(SFACE_PATH), "")
    row = _face_box_to_yunet_row(_face())
    aligned = reference.alignCrop(aligned_like_image, row)
    ref_raw = reference.feature(aligned).flatten()
    ref_normalized = ref_raw / np.linalg.norm(ref_raw)

    cosine = float(np.dot(ours.vector, ref_normalized))
    assert cosine > 0.999


@requires_models
def test_liveness_provider_loads_and_handles_no_face_gracefully():
    from faceauth.liveness.challenge_response import MediaPipeChallengeResponseLiveness

    provider = MediaPipeChallengeResponseLiveness(model_asset_path=LANDMARKER_PATH)
    provider.new_challenge()
    frame = Frame(image=np.zeros((480, 640, 3), dtype=np.uint8), timestamp=0.0)
    provider.observe(frame, _face())  # no real face in a blank image; must not crash
    result = provider.finalize()
    assert result.passed is False
    assert result.reason == "no_face_observed_during_challenge"


@requires_models
def test_default_enabled_challenges_is_blink_only():
    """Regression test for the real spoof finding (docs/THREAT_MODEL.md
    section 2): the default challenge pool must be BLINK-only until
    head-turn detection is hardened against stationary-photo jitter."""
    import random

    from faceauth.liveness.challenge_response import MediaPipeChallengeResponseLiveness
    from faceauth.pipeline_types import ChallengeKind

    provider = MediaPipeChallengeResponseLiveness(
        model_asset_path=LANDMARKER_PATH, rng=random.Random(0)
    )
    issued = {provider.new_challenge() for _ in range(20)}
    assert issued == {ChallengeKind.BLINK}


@requires_models
def test_enabled_challenges_can_be_explicitly_widened():
    """Head-turn remains fully implemented and selectable - just not the
    default - for future hardening/opt-in use."""
    from faceauth.liveness.challenge_response import MediaPipeChallengeResponseLiveness
    from faceauth.pipeline_types import ChallengeKind

    provider = MediaPipeChallengeResponseLiveness(
        model_asset_path=LANDMARKER_PATH,
        enabled_challenges=(ChallengeKind.TURN_HEAD_LEFT,),
    )
    assert provider.new_challenge() is ChallengeKind.TURN_HEAD_LEFT


def test_empty_enabled_challenges_rejected(tmp_path: Path):
    from faceauth.liveness.challenge_response import MediaPipeChallengeResponseLiveness

    with pytest.raises(ValueError, match="must not be empty"):
        MediaPipeChallengeResponseLiveness(
            model_asset_path=tmp_path / "irrelevant.task", enabled_challenges=()
        )
