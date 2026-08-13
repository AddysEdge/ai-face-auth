"""Multi-sample enrollment orchestration.

Collects config.enrollment.num_samples independently-verified samples (each
must pass detection, quality, and a fresh liveness challenge), rejects
outlier samples against the running centroid, then stores the mean-then-
renormalized centroid embedding alongside every individual sample embedding
(see docs/RESEARCH.md section 8 for why both are kept). Raw frames are never
retained beyond the local capture loop unless
``EnrollmentConfig.retain_raw_frames`` is explicitly enabled, which logs a
loud warning every time it is used.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

import cv2
import numpy as np

from faceauth.capture_utils import run_liveness_challenge
from faceauth.config import EnrollmentConfig
from faceauth.exceptions import EnrollmentFailedError
from faceauth.interfaces.camera import CameraProvider
from faceauth.interfaces.detector import FaceDetector
from faceauth.interfaces.embedding import FaceEmbeddingModel
from faceauth.interfaces.liveness import LivenessProvider
from faceauth.interfaces.quality import FaceQualityChecker
from faceauth.interfaces.template_store import TemplateStore
from faceauth.logging_utils import SecurityLogger
from faceauth.pipeline_types import ChallengeKind, DemoState, Embedding, EnrollmentResult
from faceauth.similarity.cosine_similarity import cosine_similarity

_MAX_ATTEMPT_MULTIPLIER = 4


class EnrollmentService:
    def __init__(
        self,
        camera: CameraProvider,
        detector: FaceDetector,
        quality_checker: FaceQualityChecker,
        liveness: LivenessProvider,
        embedder: FaceEmbeddingModel,
        template_store: TemplateStore,
        config: EnrollmentConfig,
        logger: SecurityLogger,
        max_frames_per_challenge: int,
        challenge_deadline_seconds: float,
        raw_frame_debug_dir: Path | None = None,
        min_face_continuity: float = 0.5,
    ) -> None:
        self._camera = camera
        self._detector = detector
        self._quality_checker = quality_checker
        self._liveness = liveness
        self._embedder = embedder
        self._template_store = template_store
        self._config = config
        self._logger = logger
        self._max_frames_per_challenge = max_frames_per_challenge
        self._challenge_deadline_seconds = challenge_deadline_seconds
        self._raw_frame_debug_dir = raw_frame_debug_dir
        self._min_face_continuity = min_face_continuity

    def enroll(
        self,
        user_id: str,
        on_state: Callable[[DemoState], None] | None = None,
        on_challenge: Callable[[ChallengeKind], None] | None = None,
    ) -> EnrollmentResult:
        samples: list[Embedding] = []
        max_attempts = self._config.num_samples * _MAX_ATTEMPT_MULTIPLIER
        attempts = 0

        with self._camera:
            if on_state is not None:
                on_state(DemoState.CAMERA_READY)
            while len(samples) < self._config.num_samples:
                if attempts >= max_attempts:
                    self._logger.log_event(
                        "enrollment_failed_attempt_budget_exhausted",
                        level=logging.WARNING,
                        samples_collected=len(samples),
                        attempts=attempts,
                    )
                    raise EnrollmentFailedError(
                        f"could not collect {self._config.num_samples} valid samples "
                        f"within {max_attempts} attempts (collected {len(samples)})"
                    )
                attempts += 1

                outcome = run_liveness_challenge(
                    self._camera,
                    self._detector,
                    self._quality_checker,
                    self._liveness,
                    self._max_frames_per_challenge,
                    self._challenge_deadline_seconds,
                    on_state=on_state,
                    on_challenge=on_challenge,
                    min_face_continuity=self._min_face_continuity,
                )
                if not outcome.liveness_result.passed or outcome.best_frame is None:
                    self._logger.log_event(
                        "enrollment_sample_rejected",
                        reason=outcome.liveness_result.reason,
                        attempt=attempts,
                    )
                    continue

                assert outcome.best_face is not None
                embedding = self._embedder.embed(outcome.best_frame.image, outcome.best_face)

                if samples:
                    running_centroid = _centroid(samples)
                    distance = 1.0 - cosine_similarity(embedding, running_centroid)
                    if distance > self._config.max_outlier_cosine_distance:
                        self._logger.log_event(
                            "enrollment_sample_rejected_outlier",
                            attempt=attempts,
                            outlier_distance_bucket=_bucket(distance),
                        )
                        continue

                if self._config.retain_raw_frames and self._raw_frame_debug_dir is not None:
                    self._logger.log_event(
                        "enrollment_raw_frame_retained_DEV_ONLY",
                        level=logging.WARNING,
                        sample_index=len(samples) + 1,
                    )
                    self._raw_frame_debug_dir.mkdir(parents=True, exist_ok=True)
                    out_path = self._raw_frame_debug_dir / f"{user_id}_{len(samples)}.jpg"
                    cv2.imwrite(str(out_path), outcome.best_frame.image)

                samples.append(embedding)
                self._logger.log_event("enrollment_sample_accepted", sample_index=len(samples))

        centroid = _centroid(samples)
        stored = self._template_store.save(user_id, centroid, tuple(samples))
        self._logger.log_event(
            "enrollment_completed", num_samples=len(samples), template_id=stored.template_id
        )
        return EnrollmentResult(
            user_id=user_id, num_samples_used=len(samples), template_id=stored.template_id
        )


def _centroid(samples: list[Embedding]) -> Embedding:
    stacked = np.stack([s.vector for s in samples])
    mean = stacked.mean(axis=0)
    norm = float(np.linalg.norm(mean))
    if norm < 1e-6:
        raise EnrollmentFailedError("degenerate centroid (near-zero norm) computed from samples")
    return Embedding(vector=(mean / norm).astype(np.float32))


def _bucket(distance: float) -> str:
    """Coarse bucket for logging - never log the raw float next to identity
    (see docs/RESEARCH.md section 14)."""
    if distance < 0.3:
        return "low"
    if distance < 0.6:
        return "medium"
    return "high"
