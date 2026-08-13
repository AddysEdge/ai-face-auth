from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np

from faceauth.exceptions import ModelInferenceError, ModelInitializationError
from faceauth.interfaces.detector import FaceDetector
from faceauth.pipeline_types import FaceBox

# cv2.FaceDetectorYN.detect() returns one row per face:
#   [x, y, w, h, re_x, re_y, le_x, le_y, nose_x, nose_y, rmc_x, rmc_y, lmc_x, lmc_y, score]
# i.e. box(4) + 5 landmark points(10) + score(1) = 15 columns. Landmark order
# is right-eye, left-eye, nose-tip, right-mouth-corner, left-mouth-corner -
# this is OpenCV's own reference decode (see docs/RESEARCH.md section 2 for
# why we use this wrapper instead of a hand-rolled raw-ONNX decode).
_EXPECTED_COLUMNS = 15


class YuNetFaceDetector(FaceDetector):
    def __init__(
        self,
        model_path: Path,
        score_threshold: float = 0.7,
        nms_threshold: float = 0.3,
        top_k: int = 50,
    ) -> None:
        if not Path(model_path).exists():
            raise ModelInitializationError(f"YuNet model file not found: {model_path}")
        try:
            # opencv-python's bundled type stubs don't declare this factory
            # (it exists and works at runtime - verified directly against
            # the downloaded model; see docs/RESEARCH.md section 2).
            self._detector = cv2.FaceDetectorYN_create(  # type: ignore[attr-defined]
                str(model_path),
                "",
                (320, 320),
                score_threshold,
                nms_threshold,
                top_k,
            )
        except cv2.error as exc:
            raise ModelInitializationError(f"failed to load YuNet model: {exc}") from exc

    def detect(self, image: np.ndarray) -> list[FaceBox]:
        if image is None or image.size == 0:
            raise ModelInferenceError("cannot run detection on an empty image")
        height, width = image.shape[:2]
        self._detector.setInputSize((width, height))
        try:
            _, faces = self._detector.detect(image)
        except cv2.error as exc:
            raise ModelInferenceError(f"YuNet inference failed: {exc}") from exc
        if faces is None:
            return []
        boxes: list[FaceBox] = []
        for row in faces:
            if len(row) != _EXPECTED_COLUMNS:
                raise ModelInferenceError(
                    f"unexpected YuNet output shape: {len(row)} columns, expected {_EXPECTED_COLUMNS}"
                )
            x, y, w, h = (float(v) for v in row[0:4])
            landmarks = tuple(
                (float(row[4 + 2 * i]), float(row[4 + 2 * i + 1])) for i in range(5)
            )
            score = float(row[14])
            boxes.append(
                FaceBox(x=x, y=y, width=w, height=h, confidence=score, landmarks=landmarks)
            )
        boxes.sort(key=lambda b: b.confidence, reverse=True)
        return boxes
