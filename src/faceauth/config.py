"""Application configuration.

All tunables live here, validated by pydantic, with defaults chosen from
docs/RESEARCH.md (e.g. the 0.363 cosine-similarity threshold is OpenCV's own
published operating point for the SFace checkpoint this repo ships, not a
guess - see RESEARCH.md section 10). Nothing here is a secret; do not put
credentials in this file or its on-disk representation.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, model_validator

from faceauth.exceptions import ConfigurationError
from faceauth.pipeline_types import ChallengeKind

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODELS_DIR = REPO_ROOT / "models"
DEFAULT_DATA_DIR = REPO_ROOT / "data"


class CameraConfig(BaseModel):
    device_index: int = 0
    width: int = Field(default=640, gt=0)
    height: int = Field(default=480, gt=0)


class DetectionConfig(BaseModel):
    model_path: Path = DEFAULT_MODELS_DIR / "yunet_2023mar.onnx"
    score_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    nms_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    top_k: int = Field(default=50, gt=0)


class QualityConfig(BaseModel):
    min_face_area_ratio: float = Field(default=0.03, ge=0.0, le=1.0)
    max_face_area_ratio: float = Field(default=0.95, ge=0.0, le=1.0)
    min_sharpness: float = Field(default=40.0, ge=0.0)
    min_brightness: float = Field(default=40.0, ge=0.0, le=255.0)
    max_brightness: float = Field(default=220.0, ge=0.0, le=255.0)

    @model_validator(mode="after")
    def _check_ranges(self) -> QualityConfig:
        if self.min_face_area_ratio >= self.max_face_area_ratio:
            raise ValueError("min_face_area_ratio must be < max_face_area_ratio")
        if self.min_brightness >= self.max_brightness:
            raise ValueError("min_brightness must be < max_brightness")
        return self


class EmbeddingConfig(BaseModel):
    model_path: Path = DEFAULT_MODELS_DIR / "sface_2021dec.onnx"
    embedding_dim: int = 128


class LivenessConfig(BaseModel):
    landmarker_model_path: Path = DEFAULT_MODELS_DIR / "face_landmarker.task"
    challenge_timeout_seconds: float = Field(
        default=5.0,
        gt=0.0,
        description=(
            "The authoritative wall-clock window a human has to complete the "
            "active challenge (blink/head-turn) - see capture_utils.run_liveness_challenge. "
            "5s gives time to read which challenge is active and react; a real "
            "live-hardware test found the previous frame-count-only bound "
            "silently produced only ~1.0s on fast hardware."
        ),
    )
    max_frames_per_challenge: int = Field(
        default=300,
        gt=0,
        description="Safety cap only (runaway-loop backstop) - deadline_seconds is the real bound.",
    )
    # blink/head-turn defaults below are calibrated from real measured
    # values (scripts/calibrate_liveness.py against a live webcam - see
    # docs/RESEARCH.md), not guessed. An earlier version used an indirect
    # "degrees"/"drop ratio" abstraction converted via an approximate
    # formula; that was replaced after live testing showed the approximate
    # conversion was off by >3x for head-turn (see challenge_response.py).
    blink_score_high: float = Field(
        default=0.40,
        ge=0.0,
        le=1.0,
        description="Blink blendshape score must rise to at least this to count as 'closed'.",
    )
    blink_score_low: float = Field(
        default=0.20,
        ge=0.0,
        le=1.0,
        description=(
            "Blink blendshape score must also dip to at most this, proving "
            "transience. Raised from an initial 0.15 to 0.20 after live "
            "testing showed real open-eye baseline commonly sits 0.20-0.30 "
            "and rarely dips as low as 0.15, making the original value an "
            "unreliable bottleneck for legitimate users. This does not "
            "weaken spoof resistance - that is governed entirely by "
            "blink_score_high, which a live-tested static photo never "
            "approached (peaked at 0.382 vs the 0.40 threshold)."
        ),
    )
    head_turn_min_swing: float = Field(
        default=0.045,
        gt=0.0,
        description=(
            "Minimum required swing (max-min) of the signed nose/eye-midpoint "
            "ratio within the challenge window, in the requested direction. "
            "Real peak observed during live calibration was ~0.09."
        ),
    )
    enabled_challenges: list[ChallengeKind] = Field(
        default=[ChallengeKind.BLINK],
        min_length=1,
        description=(
            "Which challenge kinds may be randomly issued. Defaults to "
            "BLINK-only: a live spoof test found head-turn detection can be "
            "spuriously triggered by a genuinely stationary photo (real "
            "camera/environmental jitter alone reached the swing "
            "threshold), while blink stayed safely bounded in the same "
            "trial. TURN_HEAD_LEFT/RIGHT remain implemented and can be "
            "re-enabled here once hardened further - see "
            "docs/THREAT_MODEL.md section 2."
        ),
    )

    min_face_continuity: float = Field(
        default=0.5,
        gt=0.0,
        le=1.0,
        description=(
            "Minimum fraction of captured frames that must have exactly one "
            "detected face during the challenge window, or the attempt is "
            "rejected regardless of the liveness signal itself. Added after "
            "a live spoof test showed physically waving a photo/phone "
            "around causes repeated detection dropouts a live human doesn't "
            "produce - see capture_utils.run_liveness_challenge."
        ),
    )

    @model_validator(mode="after")
    def _check_blink_thresholds(self) -> LivenessConfig:
        if self.blink_score_low >= self.blink_score_high:
            raise ValueError("blink_score_low must be < blink_score_high")
        return self
    passive_backend_enabled: bool = False
    passive_model_path: Path | None = None

    @model_validator(mode="after")
    def _check_passive_backend(self) -> LivenessConfig:
        if self.passive_backend_enabled and self.passive_model_path is None:
            raise ValueError("passive_backend_enabled requires passive_model_path")
        return self


class PolicyConfig(BaseModel):
    # 0.363 is OpenCV's own documented cosine-similarity operating point for
    # this exact SFace checkpoint (docs.opencv.org tutorial_dnn_face) - a
    # model default, not a guess, recalibratable via faceauth-evaluate.
    similarity_threshold: float = Field(default=0.363, ge=-1.0, le=1.0)
    require_liveness: bool = True


class RateLimitConfig(BaseModel):
    max_consecutive_failures: int = Field(default=5, gt=0)
    base_cooldown_seconds: float = Field(default=30.0, gt=0.0)
    backoff_multiplier: float = Field(default=2.0, gt=1.0)
    max_cooldown_seconds: float = Field(default=900.0, gt=0.0)
    failure_reset_after_seconds: float = Field(default=1800.0, gt=0.0)
    persistent: bool = Field(
        default=True,
        description=(
            "Persist rate-limit state to state_path (surviving process "
            "restarts) rather than only in memory. Default True: a live "
            "test found in-memory-only state provides no real protection "
            "against repeated separate CLI invocations, since each one "
            "starts a fresh process - see docs/THREAT_MODEL.md section 12."
        ),
    )
    state_path: Path = DEFAULT_DATA_DIR / "rate_limit_state.json"


class StorageConfig(BaseModel):
    backend: Literal["dpapi", "file_dev"] = "dpapi"
    data_dir: Path = DEFAULT_DATA_DIR / "templates"
    dev_key_path: Path = DEFAULT_DATA_DIR / ".dev_key"


class EnrollmentConfig(BaseModel):
    num_samples: int = Field(default=5, ge=3, le=20)
    max_outlier_cosine_distance: float = Field(default=0.5, gt=0.0)
    retain_raw_frames: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"
    log_dir: Path = DEFAULT_DATA_DIR / "logs"


class AppConfig(BaseModel):
    camera: CameraConfig = CameraConfig()
    detection: DetectionConfig = DetectionConfig()
    quality: QualityConfig = QualityConfig()
    embedding: EmbeddingConfig = EmbeddingConfig()
    liveness: LivenessConfig = LivenessConfig()
    policy: PolicyConfig = PolicyConfig()
    rate_limit: RateLimitConfig = RateLimitConfig()
    storage: StorageConfig = StorageConfig()
    enrollment: EnrollmentConfig = EnrollmentConfig()
    logging: LoggingConfig = LoggingConfig()


class ConfigSource(ABC):
    """Where an AppConfig is loaded from. Swappable so tests/CLI can inject
    a config without touching disk."""

    @abstractmethod
    def load(self) -> AppConfig: ...


class DefaultConfigSource(ConfigSource):
    """Pure defaults, no file involved."""

    def load(self) -> AppConfig:
        return AppConfig()


class JsonFileConfigSource(ConfigSource):
    """Loads an AppConfig from a JSON file, overlaying onto defaults.

    Raises ConfigurationError (never a raw pydantic/json exception) so
    callers only need to handle one exception type.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> AppConfig:
        if not self._path.exists():
            raise ConfigurationError(f"config file not found: {self._path}")
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"config file is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigurationError("config file must contain a JSON object")
        try:
            return AppConfig.model_validate(raw)
        except ValidationError as exc:
            raise ConfigurationError(f"config validation failed: {exc}") from exc


def load_config(path: Path | None) -> AppConfig:
    source: ConfigSource = DefaultConfigSource() if path is None else JsonFileConfigSource(path)
    return source.load()
