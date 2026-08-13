"""Shared data types passed between pipeline stages.

Kept dependency-free (dataclasses + numpy + enum only) so interfaces can
import this module without pulling in any concrete backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

import numpy as np


@dataclass(frozen=True)
class Frame:
    """A single BGR image frame, as produced by OpenCV's VideoCapture."""

    image: np.ndarray
    timestamp: float


@dataclass(frozen=True)
class FaceBox:
    """A detected face's bounding box and 5-point landmarks (eyes, nose, mouth corners).

    Coordinates are in pixels, in the source frame's coordinate space.
    """

    x: float
    y: float
    width: float
    height: float
    confidence: float
    landmarks: tuple[tuple[float, float], ...]  # (right_eye, left_eye, nose, r_mouth, l_mouth)

    @property
    def area(self) -> float:
        return max(self.width, 0.0) * max(self.height, 0.0)


@dataclass(frozen=True)
class QualityReport:
    passed: bool
    reasons: tuple[str, ...] = ()
    sharpness: float | None = None
    brightness: float | None = None
    face_area_ratio: float | None = None


class ChallengeKind(Enum):
    BLINK = auto()
    TURN_HEAD_LEFT = auto()
    TURN_HEAD_RIGHT = auto()


# Shared human-readable prompt text, used by both cli.py and demo_ui.py so a
# user has the same real-time instruction regardless of which frontend they
# use - see capture_utils.py's module docstring for why announcing the
# active challenge in real time matters.
CHALLENGE_PROMPTS: dict[ChallengeKind, str] = {
    ChallengeKind.BLINK: "BLINK now",
    ChallengeKind.TURN_HEAD_LEFT: "TURN YOUR HEAD LEFT now",
    ChallengeKind.TURN_HEAD_RIGHT: "TURN YOUR HEAD RIGHT now",
}


@dataclass(frozen=True)
class LivenessResult:
    passed: bool
    reason: str = ""
    details: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class Embedding:
    """An L2-normalized face embedding vector.

    __post_init__ deliberately does *not* re-normalize - callers must hand in
    an already-normalized vector, and get an assertion error if they don't,
    so a silent normalization bug can never hide behind this type.
    """

    vector: np.ndarray

    def __post_init__(self) -> None:
        if self.vector.ndim != 1:
            raise ValueError(f"embedding must be 1-D, got shape {self.vector.shape}")
        norm = float(np.linalg.norm(self.vector))
        if not np.isclose(norm, 1.0, atol=1e-3):
            raise ValueError(f"embedding must be L2-normalized, got norm={norm:.4f}")


class AuthDecision(Enum):
    GRANTED = auto()
    DENIED = auto()


@dataclass(frozen=True)
class AuthResult:
    decision: AuthDecision
    reason: str
    similarity: float | None = None
    user_id: str | None = None


@dataclass(frozen=True)
class EnrollmentResult:
    user_id: str
    num_samples_used: int
    template_id: str


@dataclass(frozen=True)
class StoredTemplate:
    """A decrypted, in-memory biometric template.

    ``sample_embeddings`` holds the individual enrollment-sample embeddings
    (not just the centroid) so a similarity engine can use a max-over-samples
    strategy instead of comparing only against the mean; see
    docs/RESEARCH.md section 8 for why both are kept.
    """

    user_id: str
    template_id: str
    centroid: Embedding
    sample_embeddings: tuple[Embedding, ...]
    created_at: float


class DemoState(Enum):
    """States surfaced by the demo UI. See docs/ARCHITECTURE.md for the state machine."""

    CAMERA_READY = auto()
    FACE_DETECTED = auto()
    CHECKING_LIVENESS = auto()
    VERIFYING_IDENTITY = auto()
    ACCESS_GRANTED = auto()
    ACCESS_DENIED = auto()
    TRY_AGAIN = auto()
    COOLDOWN_ACTIVE = auto()
