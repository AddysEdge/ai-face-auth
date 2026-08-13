from pathlib import Path

import pytest

from faceauth.config import EnrollmentConfig
from faceauth.enrollment import EnrollmentService
from faceauth.exceptions import EnrollmentFailedError
from faceauth.storage.file_template_store import FileTemplateStore
from tests.conftest import (
    AlwaysOneFaceDetector,
    FakeCamera,
    FakeEmbedder,
    FakeLiveness,
    FakeQualityChecker,
    NeverObservesLiveness,
    logger,  # noqa: F401 - fixture
)


def _service(tmp_path: Path, embedder, liveness, quality_passed=True, num_samples=3, **cfg):
    store = FileTemplateStore(data_dir=tmp_path / "templates", key_path=tmp_path / "key")
    config = EnrollmentConfig(num_samples=num_samples, **cfg)
    from faceauth.logging_utils import build_security_logger

    return EnrollmentService(
        camera=FakeCamera(),
        detector=AlwaysOneFaceDetector(),
        quality_checker=FakeQualityChecker(passed=quality_passed),
        liveness=liveness,
        embedder=embedder,
        template_store=store,
        config=config,
        logger=build_security_logger("test-enroll", tmp_path / "logs", "DEBUG"),
        max_frames_per_challenge=5,
        challenge_deadline_seconds=5.0,
    ), store


def test_enrollment_collects_configured_number_of_samples(tmp_path: Path):
    embedder = FakeEmbedder(fixed_vector=[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
    liveness = FakeLiveness(passed=True)
    service, store = _service(tmp_path, embedder, liveness, num_samples=3)

    result = service.enroll("alice")

    assert result.user_id == "alice"
    assert result.num_samples_used == 3
    stored = store.load("alice")
    assert len(stored.sample_embeddings) == 3


def test_enrollment_fails_when_liveness_never_passes(tmp_path: Path):
    embedder = FakeEmbedder()
    liveness = NeverObservesLiveness()
    service, _ = _service(tmp_path, embedder, liveness, num_samples=3)

    with pytest.raises(EnrollmentFailedError):
        service.enroll("alice")


def test_enrollment_rejects_outlier_samples(tmp_path: Path):
    """A sample whose embedding is far from the running centroid must be
    rejected and not counted toward num_samples."""

    class AlternatingEmbedder:
        embedding_dim = 8

        def __init__(self):
            self.calls = 0

        def embed(self, image, face):
            self.calls += 1
            from tests.conftest import unit_embedding

            # First two calls: consistent vector. Third call: wild outlier.
            # Fourth+ calls: back to consistent, to let enrollment finish.
            if self.calls == 3:
                return unit_embedding([0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
            return unit_embedding([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])

    embedder = AlternatingEmbedder()
    liveness = FakeLiveness(passed=True)
    service, store = _service(
        tmp_path, embedder, liveness, num_samples=3, max_outlier_cosine_distance=0.5
    )

    result = service.enroll("alice")

    assert result.num_samples_used == 3
    # The outlier call happened, but 4 embed() calls were needed (one rejected).
    assert embedder.calls == 4


def test_enrollment_does_not_write_raw_frames_by_default(tmp_path: Path):
    embedder = FakeEmbedder()
    liveness = FakeLiveness(passed=True)
    service, _ = _service(tmp_path, embedder, liveness, num_samples=3, retain_raw_frames=False)
    service.enroll("alice")
    debug_dir = tmp_path / "raw_debug"
    assert not debug_dir.exists() or not any(debug_dir.iterdir())


def test_enrollment_writes_raw_frames_only_when_explicitly_enabled(tmp_path: Path):
    from faceauth.logging_utils import build_security_logger
    from faceauth.storage.file_template_store import FileTemplateStore

    store = FileTemplateStore(data_dir=tmp_path / "templates", key_path=tmp_path / "key")
    config = EnrollmentConfig(num_samples=3, retain_raw_frames=True)
    debug_dir = tmp_path / "raw_debug"
    service = EnrollmentService(
        camera=FakeCamera(),
        detector=AlwaysOneFaceDetector(),
        quality_checker=FakeQualityChecker(passed=True),
        liveness=FakeLiveness(passed=True),
        embedder=FakeEmbedder(),
        template_store=store,
        config=config,
        logger=build_security_logger("test-enroll-raw", tmp_path / "logs", "DEBUG"),
        max_frames_per_challenge=5,
        challenge_deadline_seconds=5.0,
        raw_frame_debug_dir=debug_dir,
    )
    service.enroll("alice")
    assert debug_dir.exists()
    assert len(list(debug_dir.iterdir())) == 3


def test_enrollment_respects_attempt_budget(tmp_path: Path):
    """If quality gating always fails, enrollment must give up rather than
    loop forever."""
    embedder = FakeEmbedder()
    liveness = FakeLiveness(passed=True)
    service, _ = _service(tmp_path, embedder, liveness, quality_passed=False, num_samples=3)
    with pytest.raises(EnrollmentFailedError):
        service.enroll("alice")
