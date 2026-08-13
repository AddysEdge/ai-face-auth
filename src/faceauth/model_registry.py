"""Provenance/license metadata for every model file this repo depends on.

Kept as plain data (no network calls) so it can be imported cheaply from the
CLI and tests to print license info or verify local files are present. The
actual download logic lives in scripts/fetch_models.py - this module is
intentionally passive.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from faceauth.config import DEFAULT_MODELS_DIR


@dataclass(frozen=True)
class ModelEntry:
    filename: str
    source_url: str
    sha256: str
    license_name: str
    commercial_use: bool
    description: str


MODEL_REGISTRY: tuple[ModelEntry, ...] = (
    ModelEntry(
        filename="yunet_2023mar.onnx",
        source_url=(
            "https://github.com/opencv/opencv_zoo/raw/main/models/"
            "face_detection_yunet/face_detection_yunet_2023mar.onnx"
        ),
        sha256="8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
        license_name="MIT",
        commercial_use=True,
        description="YuNet face detector (5-point landmarks), OpenCV Zoo.",
    ),
    ModelEntry(
        filename="sface_2021dec.onnx",
        source_url=(
            "https://github.com/opencv/opencv_zoo/raw/main/models/"
            "face_recognition_sface/face_recognition_sface_2021dec.onnx"
        ),
        sha256="0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79",
        license_name="Apache-2.0",
        commercial_use=True,
        description="SFace 128-d face embedding model, OpenCV Zoo.",
    ),
    ModelEntry(
        filename="face_landmarker.task",
        source_url=(
            "https://storage.googleapis.com/mediapipe-models/face_landmarker/"
            "face_landmarker/float16/1/face_landmarker.task"
        ),
        sha256="64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff",
        license_name="Apache-2.0",
        commercial_use=True,
        description="MediaPipe Face Landmarker bundle (landmarks + blendshapes).",
    ),
)


def missing_models(models_dir: Path = DEFAULT_MODELS_DIR) -> list[str]:
    return [entry.filename for entry in MODEL_REGISTRY if not (models_dir / entry.filename).exists()]
