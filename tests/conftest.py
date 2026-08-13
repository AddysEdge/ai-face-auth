"""Shared test fixtures: hand-written fakes for every pipeline interface.

Hand-written fakes (rather than a mocking library) are used for the
interfaces so each fake encodes real, inspectable behavior that tests can
assert against - matching the goal's "test behavior, not implementation
details." unittest.mock is used only where patching a third-party call
(cv2.VideoCapture) is the natural approach.
"""

from __future__ import annotations

import time
from pathlib import Path

import numpy as np
import pytest

from faceauth.exceptions import CameraUnavailableError
from faceauth.interfaces.camera import CameraProvider
from faceauth.interfaces.detector import FaceDetector
from faceauth.interfaces.embedding import FaceEmbeddingModel
from faceauth.interfaces.liveness import LivenessProvider
from faceauth.interfaces.quality import FaceQualityChecker
from faceauth.logging_utils import build_security_logger
from faceauth.pipeline_types import (
    ChallengeKind,
    Embedding,
    FaceBox,
    Frame,
    LivenessResult,
    QualityReport,
)

EMBEDDING_DIM = 8


def unit_embedding(seed_vector: list[float]) -> Embedding:
    vec = np.asarray(seed_vector, dtype=np.float32)
    norm = float(np.linalg.norm(vec))
    return Embedding(vector=vec / norm)


def make_face_box(confidence: float = 0.95) -> FaceBox:
    return FaceBox(
        x=100.0,
        y=80.0,
        width=120.0,
        height=140.0,
        confidence=confidence,
        landmarks=((130, 120), (170, 120), (150, 150), (135, 180), (165, 180)),
    )


class FakeCamera(CameraProvider):
    """Yields a fixed sequence of frames, then raises CameraUnavailableError."""

    def __init__(self, frames: list[np.ndarray] | None = None, fail_on_open: bool = False):
        self._frames = frames if frames is not None else [np.zeros((240, 320, 3), np.uint8)] * 200
        self._index = 0
        self._opened = False
        self._fail_on_open = fail_on_open
        self.close_called = False

    def open(self) -> None:
        if self._fail_on_open:
            raise CameraUnavailableError("simulated open failure")
        self._opened = True
        self._index = 0

    def read(self) -> Frame:
        if not self._opened:
            raise CameraUnavailableError("camera not open")
        if self._index >= len(self._frames):
            raise CameraUnavailableError("frame feed exhausted")
        image = self._frames[self._index]
        self._index += 1
        return Frame(image=image, timestamp=time.monotonic())

    def close(self) -> None:
        self.close_called = True
        self._opened = False

    def is_opened(self) -> bool:
        return self._opened

    @property
    def read_count(self) -> int:
        return self._index


class FakeDetector(FaceDetector):
    """Returns a scripted sequence of detection results, one entry per call.
    The last entry repeats once the script is exhausted."""

    def __init__(self, script: list[list[FaceBox]]):
        self._script = script
        self._calls = 0

    def detect(self, image: np.ndarray) -> list[FaceBox]:
        idx = min(self._calls, len(self._script) - 1)
        self._calls += 1
        return self._script[idx]


class AlwaysOneFaceDetector(FaceDetector):
    def detect(self, image: np.ndarray) -> list[FaceBox]:
        return [make_face_box()]


class FakeQualityChecker(FaceQualityChecker):
    def __init__(self, passed: bool = True, reasons: tuple[str, ...] = ()):
        self.passed = passed
        self.reasons = reasons

    def check(self, image: np.ndarray, face: FaceBox) -> QualityReport:
        return QualityReport(passed=self.passed, reasons=self.reasons)


class FakeLiveness(LivenessProvider):
    """Always issues BLINK and returns a pre-set verdict on finalize()."""

    def __init__(self, passed: bool = True, reason: str = "ok"):
        self.passed = passed
        self.reason = reason
        self.observed_count = 0
        self.challenge_started = False

    def new_challenge(self) -> ChallengeKind:
        self.challenge_started = True
        self.observed_count = 0
        return ChallengeKind.BLINK

    def observe(self, frame: Frame, face: FaceBox) -> None:
        self.observed_count += 1

    def finalize(self) -> LivenessResult:
        return LivenessResult(passed=self.passed, reason=self.reason)


class NeverObservesLiveness(LivenessProvider):
    """Simulates a challenge where no frame ever had a usable face."""

    def new_challenge(self) -> ChallengeKind:
        return ChallengeKind.BLINK

    def observe(self, frame: Frame, face: FaceBox) -> None:
        pass

    def finalize(self) -> LivenessResult:
        return LivenessResult(passed=False, reason="no_face_observed_during_challenge")


class FakeEmbedder(FaceEmbeddingModel):
    def __init__(self, fixed_vector: list[float] | None = None):
        self._fixed = fixed_vector or ([1.0] + [0.0] * (EMBEDDING_DIM - 1))
        self.embed_calls = 0

    @property
    def embedding_dim(self) -> int:
        return EMBEDDING_DIM

    def embed(self, image: np.ndarray, face: FaceBox) -> Embedding:
        self.embed_calls += 1
        return unit_embedding(self._fixed)


@pytest.fixture
def logger(tmp_path: Path):
    return build_security_logger("faceauth-test", tmp_path / "logs", "DEBUG")
