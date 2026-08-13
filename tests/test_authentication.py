from pathlib import Path

import pytest

from faceauth.authentication import AuthenticationService
from faceauth.config import RateLimitConfig
from faceauth.exceptions import (
    RateLimitedError,
    TemplateCorruptedError,
)
from faceauth.interfaces.template_store import TemplateStore
from faceauth.logging_utils import build_security_logger
from faceauth.pipeline_types import AuthDecision
from faceauth.policy.threshold_policy import ThresholdAuthenticationPolicy
from faceauth.rate_limiting.cooldown_rate_limiter import CooldownRateLimiter
from faceauth.similarity.cosine_similarity import CentroidCosineSimilarityEngine
from faceauth.storage.file_template_store import FileTemplateStore
from tests.conftest import (
    AlwaysOneFaceDetector,
    FakeCamera,
    FakeDetector,
    FakeEmbedder,
    FakeLiveness,
    FakeQualityChecker,
    NeverObservesLiveness,
    make_face_box,
    unit_embedding,
)


class RaisingTemplateStore(TemplateStore):
    def __init__(self, exc: Exception):
        self._exc = exc

    def save(self, user_id, centroid, sample_embeddings):
        raise NotImplementedError

    def load(self, user_id):
        raise self._exc

    def delete(self, user_id):
        pass

    def exists(self, user_id):
        return True

    def list_users(self):
        return []


def _service(
    tmp_path: Path,
    embedder=None,
    liveness=None,
    detector=None,
    template_store=None,
    camera=None,
    quality_passed=True,
    threshold=0.363,
    require_liveness=True,
    rate_limit_overrides=None,
):
    if template_store is None:
        template_store = FileTemplateStore(data_dir=tmp_path / "templates", key_path=tmp_path / "key")
        template_store.save("alice", unit_embedding([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]), ())
    rl_cfg = RateLimitConfig(**(rate_limit_overrides or {}))
    return AuthenticationService(
        camera=camera or FakeCamera(),
        detector=detector or AlwaysOneFaceDetector(),
        quality_checker=FakeQualityChecker(passed=quality_passed),
        liveness=liveness or FakeLiveness(passed=True),
        embedder=embedder or FakeEmbedder(fixed_vector=[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]),
        template_store=template_store,
        similarity_engine=CentroidCosineSimilarityEngine(),
        policy=ThresholdAuthenticationPolicy(threshold=threshold),
        rate_limiter=CooldownRateLimiter(
            max_consecutive_failures=rl_cfg.max_consecutive_failures,
            base_cooldown_seconds=rl_cfg.base_cooldown_seconds,
            backoff_multiplier=rl_cfg.backoff_multiplier,
            max_cooldown_seconds=rl_cfg.max_cooldown_seconds,
            failure_reset_after_seconds=rl_cfg.failure_reset_after_seconds,
        ),
        logger=build_security_logger("test-auth", tmp_path / "logs", "DEBUG"),
        max_frames_per_challenge=5,
        challenge_deadline_seconds=5.0,
        require_liveness=require_liveness,
    )


def test_matching_face_is_granted(tmp_path: Path):
    service = _service(tmp_path)
    result = service.authenticate("alice")
    assert result.decision is AuthDecision.GRANTED
    assert result.similarity == pytest.approx(1.0)


def test_non_matching_face_is_denied(tmp_path: Path):
    service = _service(tmp_path, embedder=FakeEmbedder(fixed_vector=[0.0, 1.0, 0, 0, 0, 0, 0, 0]))
    result = service.authenticate("alice")
    assert result.decision is AuthDecision.DENIED
    assert result.reason == "similarity_below_threshold"


def test_unknown_user_is_denied(tmp_path: Path):
    service = _service(tmp_path)
    result = service.authenticate("bob-does-not-exist")
    assert result.decision is AuthDecision.DENIED
    assert result.reason == "unknown_user"


def test_corrupted_template_fails_closed(tmp_path: Path):
    store = RaisingTemplateStore(TemplateCorruptedError("simulated corruption"))
    service = _service(tmp_path, template_store=store)
    result = service.authenticate("alice")
    assert result.decision is AuthDecision.DENIED
    assert result.reason == "security_critical_failure"


def test_no_face_detected_is_denied(tmp_path: Path):
    service = _service(tmp_path, detector=FakeDetector(script=[[]]))
    result = service.authenticate("alice")
    assert result.decision is AuthDecision.DENIED
    # Zero faces detected across the whole window -> denied either via the
    # liveness path directly, or (as of the face-continuity check added
    # after a real spoof test - see capture_utils.py) via
    # "face_detection_unstable" (0% continuity). Either way: never granted,
    # never a crash.
    assert (
        "no_face" in result.reason
        or result.reason == "no_face_detected"
        or "face_detection_unstable" in result.reason
    )


def test_multiple_faces_detected_is_denied(tmp_path: Path):
    two_faces = [make_face_box(), make_face_box()]
    service = _service(tmp_path, detector=FakeDetector(script=[two_faces]))
    result = service.authenticate("alice")
    assert result.decision is AuthDecision.DENIED


def test_failed_liveness_denies_even_with_perfect_match(tmp_path: Path):
    service = _service(tmp_path, liveness=FakeLiveness(passed=False, reason="spoof_suspected"))
    result = service.authenticate("alice")
    assert result.decision is AuthDecision.DENIED
    assert "spoof_suspected" in result.reason


def test_liveness_not_required_when_disabled(tmp_path: Path):
    service = _service(
        tmp_path, liveness=FakeLiveness(passed=False, reason="ignored"), require_liveness=False
    )
    result = service.authenticate("alice")
    assert result.decision is AuthDecision.GRANTED


def test_camera_unavailable_fails_closed(tmp_path: Path):
    service = _service(tmp_path, camera=FakeCamera(fail_on_open=True))
    result = service.authenticate("alice")
    assert result.decision is AuthDecision.DENIED
    assert result.reason == "security_critical_failure"


def test_no_face_observed_denies_rather_than_crashing(tmp_path: Path):
    service = _service(tmp_path, liveness=NeverObservesLiveness())
    result = service.authenticate("alice")
    assert result.decision is AuthDecision.DENIED


def test_repeated_failures_trigger_rate_limiting(tmp_path: Path):
    service = _service(
        tmp_path,
        embedder=FakeEmbedder(fixed_vector=[0.0, 1.0, 0, 0, 0, 0, 0, 0]),  # always denied
        rate_limit_overrides={"max_consecutive_failures": 2, "base_cooldown_seconds": 5.0},
    )
    r1 = service.authenticate("alice")
    r2 = service.authenticate("alice")
    assert r1.decision is AuthDecision.DENIED
    assert r2.decision is AuthDecision.DENIED
    with pytest.raises(RateLimitedError):
        service.authenticate("alice")


def test_success_does_not_count_as_failure_for_rate_limiting(tmp_path: Path):
    service = _service(
        tmp_path, rate_limit_overrides={"max_consecutive_failures": 1, "base_cooldown_seconds": 5.0}
    )
    result = service.authenticate("alice")
    assert result.decision is AuthDecision.GRANTED
    # A second successful attempt must not be rate-limited.
    result2 = service.authenticate("alice")
    assert result2.decision is AuthDecision.GRANTED
