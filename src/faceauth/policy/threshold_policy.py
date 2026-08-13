from __future__ import annotations

from faceauth.interfaces.policy import AuthenticationPolicy
from faceauth.pipeline_types import AuthDecision, AuthResult


class ThresholdAuthenticationPolicy(AuthenticationPolicy):
    """GRANTED iff similarity >= threshold. Ties (== threshold) grant, matching
    OpenCV's own documented "greater than or equal to" wording for the SFace
    operating point (docs/RESEARCH.md section 10)."""

    def __init__(self, threshold: float) -> None:
        self._threshold = threshold

    def decide(self, similarity: float, user_id: str) -> AuthResult:
        if similarity >= self._threshold:
            return AuthResult(
                decision=AuthDecision.GRANTED,
                reason="similarity_above_threshold",
                similarity=similarity,
                user_id=user_id,
            )
        return AuthResult(
            decision=AuthDecision.DENIED,
            reason="similarity_below_threshold",
            similarity=similarity,
            user_id=user_id,
        )
