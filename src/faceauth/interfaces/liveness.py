from __future__ import annotations

from abc import ABC, abstractmethod

from faceauth.pipeline_types import ChallengeKind, FaceBox, Frame, LivenessResult


class LivenessProvider(ABC):
    """Stateful liveness/anti-spoofing check spanning a short window of frames.

    Usage: ``new_challenge()`` once, then ``observe()`` for each frame captured
    during the challenge window, then ``finalize()`` to get the verdict.
    Implementations must be safe to reuse for a new challenge after
    ``finalize()`` returns (call ``new_challenge()`` again).
    """

    @abstractmethod
    def new_challenge(self) -> ChallengeKind:
        """Pick and remember a randomized challenge for this attempt."""

    @abstractmethod
    def observe(self, frame: Frame, face: FaceBox) -> None:
        """Feed one frame captured during the active challenge window."""

    @abstractmethod
    def finalize(self) -> LivenessResult:
        """Decide whether the observed frames satisfy the active challenge."""
