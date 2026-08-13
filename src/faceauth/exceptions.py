"""Exception hierarchy for the face-authentication pipeline.

Every exception here is caught somewhere on purpose - authentication.py and
enrollment.py convert them into explicit DENY / re-capture outcomes rather
than letting them propagate as crashes. Nothing in this module is caught and
silently discarded; see docs/THREAT_MODEL.md for the fail-closed policy this
hierarchy exists to support.
"""

from __future__ import annotations


class FaceAuthError(Exception):
    """Base class for all errors raised by the face-authentication pipeline."""


class ConfigurationError(FaceAuthError):
    """Configuration failed to load, parse, or validate."""


class CameraError(FaceAuthError):
    """Base class for camera-related failures."""


class CameraUnavailableError(CameraError):
    """The configured camera could not be opened or stopped responding."""


class DetectionError(FaceAuthError):
    """Base class for face-detection outcomes that block the pipeline."""


class NoFaceDetectedError(DetectionError):
    """No face was found in the frame."""


class MultipleFacesDetectedError(DetectionError):
    """More than one face was found where exactly one was required."""


class QualityError(FaceAuthError):
    """The detected face did not pass quality gating."""


class LowQualityFaceError(QualityError):
    def __init__(self, reasons: list[str]) -> None:
        self.reasons = reasons
        super().__init__(f"face quality check failed: {', '.join(reasons)}")


class LivenessError(FaceAuthError):
    """Base class for liveness/anti-spoofing failures."""


class LivenessCheckFailedError(LivenessError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"liveness check failed: {reason}")


class ModelError(FaceAuthError):
    """Base class for model loading/inference failures."""


class ModelInitializationError(ModelError):
    """A required model file failed to load."""


class ModelInferenceError(ModelError):
    """A model produced an unusable or malformed output at inference time."""


class TemplateStoreError(FaceAuthError):
    """Base class for biometric-template storage failures."""


class TemplateNotFoundError(TemplateStoreError):
    """No enrolled template exists for the requested user."""


class TemplateCorruptedError(TemplateStoreError):
    """A stored template could not be decrypted or deserialized safely."""


class RateLimitedError(FaceAuthError):
    """Authentication is temporarily blocked by the rate limiter."""

    def __init__(self, retry_after_seconds: float) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"rate limited; retry after {retry_after_seconds:.1f}s")


class EnrollmentFailedError(FaceAuthError):
    """Enrollment could not collect enough valid samples within the attempt budget."""


class SecurityCriticalFailure(FaceAuthError):
    """A security-critical component failed in an unexpected way.

    Raised deliberately by orchestration code (never by the caller) as the
    single, explicit signal that "something unexpected happened in a
    security-critical stage" - authentication.py treats this identically to
    an explicit DENY, never an implicit ALLOW.
    """
