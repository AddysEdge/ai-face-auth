"""Wires concrete implementations together from an AppConfig.

This is the single place that knows which concrete class backs each
interface - everything else in the package (enrollment, authentication,
CLI, demo UI) depends only on the interfaces in faceauth/interfaces/. To
swap a backend (different embedding model, TPM-backed storage, etc.), add a
branch here rather than changing calling code.
"""

from __future__ import annotations

from faceauth.authentication import AuthenticationService
from faceauth.camera.opencv_camera import OpenCvCameraProvider
from faceauth.config import AppConfig
from faceauth.detection.yunet_detector import YuNetFaceDetector
from faceauth.embedding.sface_embedding import SFaceEmbeddingModel
from faceauth.enrollment import EnrollmentService
from faceauth.interfaces.camera import CameraProvider
from faceauth.interfaces.detector import FaceDetector
from faceauth.interfaces.embedding import FaceEmbeddingModel
from faceauth.interfaces.liveness import LivenessProvider
from faceauth.interfaces.policy import AuthenticationPolicy
from faceauth.interfaces.quality import FaceQualityChecker
from faceauth.interfaces.rate_limiter import RateLimiter
from faceauth.interfaces.similarity import SimilarityEngine
from faceauth.interfaces.template_store import TemplateStore
from faceauth.liveness.challenge_response import MediaPipeChallengeResponseLiveness
from faceauth.liveness.composite import CompositeLivenessProvider
from faceauth.liveness.passive_onnx import PassiveOnnxSpoofLiveness
from faceauth.logging_utils import SecurityLogger, build_security_logger
from faceauth.policy.threshold_policy import ThresholdAuthenticationPolicy
from faceauth.quality.heuristic_quality import HeuristicFaceQualityChecker
from faceauth.rate_limiting.cooldown_rate_limiter import CooldownRateLimiter
from faceauth.rate_limiting.persistent_cooldown_rate_limiter import PersistentCooldownRateLimiter
from faceauth.similarity.cosine_similarity import CentroidCosineSimilarityEngine
from faceauth.storage.dpapi_template_store import DpapiTemplateStore
from faceauth.storage.file_template_store import FileTemplateStore


def build_logger(config: AppConfig) -> SecurityLogger:
    return build_security_logger("faceauth", config.logging.log_dir, config.logging.level)


def build_camera(config: AppConfig) -> CameraProvider:
    return OpenCvCameraProvider(
        device_index=config.camera.device_index,
        width=config.camera.width,
        height=config.camera.height,
    )


def build_detector(config: AppConfig) -> FaceDetector:
    return YuNetFaceDetector(
        model_path=config.detection.model_path,
        score_threshold=config.detection.score_threshold,
        nms_threshold=config.detection.nms_threshold,
        top_k=config.detection.top_k,
    )


def build_quality_checker(config: AppConfig) -> FaceQualityChecker:
    q = config.quality
    return HeuristicFaceQualityChecker(
        min_face_area_ratio=q.min_face_area_ratio,
        max_face_area_ratio=q.max_face_area_ratio,
        min_sharpness=q.min_sharpness,
        min_brightness=q.min_brightness,
        max_brightness=q.max_brightness,
    )


def build_embedder(config: AppConfig) -> FaceEmbeddingModel:
    return SFaceEmbeddingModel(model_path=config.embedding.model_path)


def build_liveness(config: AppConfig) -> LivenessProvider:
    active = MediaPipeChallengeResponseLiveness(
        model_asset_path=config.liveness.landmarker_model_path,
        blink_score_high=config.liveness.blink_score_high,
        blink_score_low=config.liveness.blink_score_low,
        head_turn_min_swing=config.liveness.head_turn_min_swing,
        enabled_challenges=tuple(config.liveness.enabled_challenges),
    )
    if not config.liveness.passive_backend_enabled:
        return active
    assert config.liveness.passive_model_path is not None
    passive = PassiveOnnxSpoofLiveness(model_path=config.liveness.passive_model_path)
    return CompositeLivenessProvider([active, passive])


def build_similarity_engine(config: AppConfig) -> SimilarityEngine:
    return CentroidCosineSimilarityEngine()


def build_policy(config: AppConfig) -> AuthenticationPolicy:
    return ThresholdAuthenticationPolicy(threshold=config.policy.similarity_threshold)


def build_rate_limiter(config: AppConfig) -> RateLimiter:
    r = config.rate_limit
    if r.persistent:
        return PersistentCooldownRateLimiter(
            state_path=r.state_path,
            max_consecutive_failures=r.max_consecutive_failures,
            base_cooldown_seconds=r.base_cooldown_seconds,
            backoff_multiplier=r.backoff_multiplier,
            max_cooldown_seconds=r.max_cooldown_seconds,
            failure_reset_after_seconds=r.failure_reset_after_seconds,
        )
    return CooldownRateLimiter(
        max_consecutive_failures=r.max_consecutive_failures,
        base_cooldown_seconds=r.base_cooldown_seconds,
        backoff_multiplier=r.backoff_multiplier,
        max_cooldown_seconds=r.max_cooldown_seconds,
        failure_reset_after_seconds=r.failure_reset_after_seconds,
    )


def build_template_store(config: AppConfig, logger: SecurityLogger) -> TemplateStore:
    if config.storage.backend == "dpapi":
        return DpapiTemplateStore(data_dir=config.storage.data_dir)
    return FileTemplateStore(
        data_dir=config.storage.data_dir, key_path=config.storage.dev_key_path, logger=logger
    )


def build_enrollment_service(config: AppConfig) -> EnrollmentService:
    logger = build_logger(config)
    return EnrollmentService(
        camera=build_camera(config),
        detector=build_detector(config),
        quality_checker=build_quality_checker(config),
        liveness=build_liveness(config),
        embedder=build_embedder(config),
        template_store=build_template_store(config, logger),
        config=config.enrollment,
        logger=logger,
        max_frames_per_challenge=config.liveness.max_frames_per_challenge,
        challenge_deadline_seconds=config.liveness.challenge_timeout_seconds,
        min_face_continuity=config.liveness.min_face_continuity,
    )


def build_authentication_service(config: AppConfig) -> AuthenticationService:
    logger = build_logger(config)
    return AuthenticationService(
        camera=build_camera(config),
        detector=build_detector(config),
        quality_checker=build_quality_checker(config),
        liveness=build_liveness(config),
        embedder=build_embedder(config),
        template_store=build_template_store(config, logger),
        similarity_engine=build_similarity_engine(config),
        policy=build_policy(config),
        rate_limiter=build_rate_limiter(config),
        logger=logger,
        max_frames_per_challenge=config.liveness.max_frames_per_challenge,
        challenge_deadline_seconds=config.liveness.challenge_timeout_seconds,
        require_liveness=config.policy.require_liveness,
        min_face_continuity=config.liveness.min_face_continuity,
    )
