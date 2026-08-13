"""SFace face embedding, run through ONNX Runtime directly.

Alignment uses OpenCV's ``FaceRecognizerSF.alignCrop`` (a deterministic
geometric warp calibrated by the model's own authors against this exact
checkpoint - see docs/RESEARCH.md section 4 for why we don't reimplement
that warp ourselves). The actual embedding *inference* - the
security-relevant step - runs through ``onnxruntime.InferenceSession``
directly, not through OpenCV's DNN module, satisfying the "runs on ONNX
Runtime, swappable later" architecture requirement.

The RGB-channel-order, unscaled-[0,255], NCHW preprocessing below was
empirically verified against OpenCV's own ``FaceRecognizerSF.feature()``
reference output (cosine similarity 0.9999998 on a synthetic probe) rather
than assumed - see the verification transcript referenced in RESEARCH.md.
"""

from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

from faceauth.exceptions import ModelInferenceError, ModelInitializationError
from faceauth.interfaces.embedding import FaceEmbeddingModel
from faceauth.pipeline_types import Embedding, FaceBox

_ALIGNED_SIZE = 112
_EMBEDDING_DIM = 128


def _face_box_to_yunet_row(face: FaceBox) -> np.ndarray:
    """Reconstruct the 1x15 detection row format alignCrop expects."""
    flat_landmarks = [coord for point in face.landmarks for coord in point]
    row = [face.x, face.y, face.width, face.height, *flat_landmarks, face.confidence]
    return np.array([row], dtype=np.float32)


class SFaceEmbeddingModel(FaceEmbeddingModel):
    def __init__(self, model_path: Path) -> None:
        if not Path(model_path).exists():
            raise ModelInitializationError(f"SFace model file not found: {model_path}")
        try:
            # Used only for its calibrated alignCrop() geometric warp - no
            # inference is performed through this object. (Not in opencv-python's
            # bundled stubs, but verified working at runtime - see RESEARCH.md.)
            self._aligner = cv2.FaceRecognizerSF_create(str(model_path), "")  # type: ignore[attr-defined]
            so = ort.SessionOptions()
            so.log_severity_level = 3
            self._session = ort.InferenceSession(
                str(model_path), sess_options=so, providers=["CPUExecutionProvider"]
            )
        except (cv2.error, Exception) as exc:  # onnxruntime raises plain Exception subclasses
            raise ModelInitializationError(f"failed to load SFace model: {exc}") from exc
        self._input_name = self._session.get_inputs()[0].name

    @property
    def embedding_dim(self) -> int:
        return _EMBEDDING_DIM

    def embed(self, image: np.ndarray, face: FaceBox) -> Embedding:
        if image is None or image.size == 0:
            raise ModelInferenceError("cannot embed an empty image")
        try:
            row = _face_box_to_yunet_row(face)
            aligned = self._aligner.alignCrop(image, row)
        except cv2.error as exc:
            raise ModelInferenceError(f"face alignment failed: {exc}") from exc
        if aligned.shape[:2] != (_ALIGNED_SIZE, _ALIGNED_SIZE):
            raise ModelInferenceError(f"unexpected aligned crop shape: {aligned.shape}")

        blob = aligned[:, :, ::-1].transpose(2, 0, 1)[None].astype(np.float32).copy()
        try:
            raw = self._session.run(None, {self._input_name: blob})[0]
        except Exception as exc:
            raise ModelInferenceError(f"SFace ONNX Runtime inference failed: {exc}") from exc

        vector = raw.reshape(-1).astype(np.float32)
        if vector.shape[0] != _EMBEDDING_DIM:
            raise ModelInferenceError(
                f"unexpected embedding dimension: {vector.shape[0]}, expected {_EMBEDDING_DIM}"
            )
        norm = float(np.linalg.norm(vector))
        if norm < 1e-6:
            raise ModelInferenceError("degenerate (near-zero-norm) embedding produced")
        return Embedding(vector=vector / norm)
