"""Authentication orchestration - the fail-closed heart of the system.

The contract: every exit from ``authenticate()`` is either an explicit
``AuthResult`` (GRANTED or DENIED) or a ``RateLimitedError`` raised *before*
any attempt is made. There is no code path where an unexpected exception
propagates as a crash that a caller could mistake for "no decision, so
allow" - every stage failure inside the pipeline is caught here and
converted into DENIED plus a rate-limiter failure record. See
docs/THREAT_MODEL.md "fail-closed behavior" and docs/RESEARCH.md section 9.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from faceauth.capture_utils import run_liveness_challenge
from faceauth.exceptions import (
    CameraError,
    ModelError,
    TemplateCorruptedError,
    TemplateNotFoundError,
)
from faceauth.interfaces.camera import CameraProvider
from faceauth.interfaces.detector import FaceDetector
from faceauth.interfaces.embedding import FaceEmbeddingModel
from faceauth.interfaces.liveness import LivenessProvider
from faceauth.interfaces.policy import AuthenticationPolicy
from faceauth.interfaces.quality import FaceQualityChecker
from faceauth.interfaces.rate_limiter import RateLimiter
from faceauth.interfaces.similarity import SimilarityEngine
from faceauth.interfaces.template_store import TemplateStore
from faceauth.logging_utils import SecurityLogger
from faceauth.pipeline_types import AuthDecision, AuthResult, ChallengeKind, DemoState


def _similarity_bucket(similarity: float) -> str:
    """Coarse bucket for logging - never log a raw similarity score next to
    identity (docs/RESEARCH.md section 14)."""
    if similarity < 0.0:
        return "very_low"
    if similarity < 0.363:
        return "low"
    if similarity < 0.6:
        return "medium"
    return "high"


class AuthenticationService:
    def __init__(
        self,
        camera: CameraProvider,
        detector: FaceDetector,
        quality_checker: FaceQualityChecker,
        liveness: LivenessProvider,
        embedder: FaceEmbeddingModel,
        template_store: TemplateStore,
        similarity_engine: SimilarityEngine,
        policy: AuthenticationPolicy,
        rate_limiter: RateLimiter,
        logger: SecurityLogger,
        max_frames_per_challenge: int,
        challenge_deadline_seconds: float,
        require_liveness: bool = True,
        min_face_continuity: float = 0.5,
    ) -> None:
        self._camera = camera
        self._detector = detector
        self._quality_checker = quality_checker
        self._liveness = liveness
        self._embedder = embedder
        self._template_store = template_store
        self._similarity_engine = similarity_engine
        self._policy = policy
        self._rate_limiter = rate_limiter
        self._logger = logger
        self._max_frames_per_challenge = max_frames_per_challenge
        self._challenge_deadline_seconds = challenge_deadline_seconds
        self._require_liveness = require_liveness
        self._min_face_continuity = min_face_continuity

    def authenticate(
        self,
        user_id: str,
        on_state: Callable[[DemoState], None] | None = None,
        on_challenge: Callable[[ChallengeKind], None] | None = None,
    ) -> AuthResult:
        """``on_state`` is an optional UI progress callback (see demo_ui.py).
        It only ever reports states derived from the real decision made
        below - it cannot influence GRANTED/DENIED."""
        def deny(reason: str, event: str, exc: BaseException | None = None, **fields: object) -> AuthResult:
            self._rate_limiter.record_failure()
            if exc is not None:
                self._logger.exception_event(event, exc, **fields)  # type: ignore[arg-type]
            else:
                self._logger.log_event(event, **fields)  # type: ignore[arg-type]
            if on_state is not None:
                on_state(DemoState.ACCESS_DENIED)
            return AuthResult(decision=AuthDecision.DENIED, reason=reason, user_id=user_id)

        # Raises RateLimitedError; deliberately not caught here - a blocked
        # attempt was never made, so it must not also count as a failure.
        self._rate_limiter.check_allowed()

        try:
            with self._camera:
                if on_state is not None:
                    on_state(DemoState.CAMERA_READY)
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

                if self._require_liveness and not outcome.liveness_result.passed:
                    return deny(
                        f"liveness_failed:{outcome.liveness_result.reason}",
                        "authentication_denied_liveness_failed",
                        liveness_reason=outcome.liveness_result.reason,
                    )

                if outcome.best_frame is None or outcome.best_face is None:
                    return deny("no_face_detected", "authentication_denied_no_face")

                if on_state is not None:
                    on_state(DemoState.VERIFYING_IDENTITY)
                embedding = self._embedder.embed(outcome.best_frame.image, outcome.best_face)

                try:
                    template = self._template_store.load(user_id)
                except TemplateNotFoundError:
                    return deny("unknown_user", "authentication_denied_unknown_user")
                except TemplateCorruptedError as exc:
                    return deny(
                        "security_critical_failure",
                        "authentication_denied_corrupted_template",
                        exc=exc,
                    )

                similarity = self._similarity_engine.compare(embedding, template)
                result = self._policy.decide(similarity, user_id)
        except (CameraError, ModelError) as exc:
            return deny("security_critical_failure", "authentication_denied_security_critical_failure", exc=exc)
        except Exception as exc:  # fail-closed: never let an unknown error look like a grant
            return deny("unexpected_error", "authentication_denied_unexpected_error", exc=exc)

        if result.decision is AuthDecision.GRANTED:
            self._rate_limiter.record_success()
            self._logger.log_event(
                "authentication_granted",
                similarity_bucket=_similarity_bucket(result.similarity or 0.0),
            )
            if on_state is not None:
                on_state(DemoState.ACCESS_GRANTED)
        else:
            self._rate_limiter.record_failure()
            self._logger.log_event(
                "authentication_denied_similarity",
                level=logging.INFO,
                similarity_bucket=_similarity_bucket(result.similarity or 0.0),
            )
            if on_state is not None:
                on_state(DemoState.ACCESS_DENIED)
        return result
