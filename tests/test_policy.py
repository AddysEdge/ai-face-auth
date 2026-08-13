import pytest

from faceauth.pipeline_types import AuthDecision
from faceauth.policy.threshold_policy import ThresholdAuthenticationPolicy


@pytest.mark.parametrize(
    "similarity,threshold,expected",
    [
        (0.5, 0.363, AuthDecision.GRANTED),
        (0.363, 0.363, AuthDecision.GRANTED),  # boundary: tie grants (matches OpenCV's ">=")
        (0.362999, 0.363, AuthDecision.DENIED),
        (-0.9, 0.363, AuthDecision.DENIED),
        (1.0, 0.363, AuthDecision.GRANTED),
    ],
)
def test_threshold_policy_boundaries(similarity, threshold, expected):
    policy = ThresholdAuthenticationPolicy(threshold=threshold)
    result = policy.decide(similarity, "alice")
    assert result.decision is expected
    assert result.similarity == similarity
    assert result.user_id == "alice"
