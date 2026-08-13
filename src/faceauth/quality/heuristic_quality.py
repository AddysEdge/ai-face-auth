"""Classic-CV face quality gating: sharpness, brightness, size, framing.

Deliberately dependency-light (OpenCV + numpy only, no extra model) so
quality gating never fails because of an unrelated model's initialization
problem. See docs/RESEARCH.md for why enrollment/authentication both reject
low-quality frames rather than trying to "fix" them.
"""

from __future__ import annotations

import cv2
import numpy as np

from faceauth.interfaces.quality import FaceQualityChecker
from faceauth.pipeline_types import FaceBox, QualityReport


class HeuristicFaceQualityChecker(FaceQualityChecker):
    def __init__(
        self,
        min_face_area_ratio: float = 0.03,
        max_face_area_ratio: float = 0.95,
        min_sharpness: float = 40.0,
        min_brightness: float = 40.0,
        max_brightness: float = 220.0,
    ) -> None:
        self._min_face_area_ratio = min_face_area_ratio
        self._max_face_area_ratio = max_face_area_ratio
        self._min_sharpness = min_sharpness
        self._min_brightness = min_brightness
        self._max_brightness = max_brightness

    def check(self, image: np.ndarray, face: FaceBox) -> QualityReport:
        reasons: list[str] = []
        image_area = float(image.shape[0] * image.shape[1])
        face_ratio = face.area / image_area if image_area > 0 else 0.0

        if face_ratio < self._min_face_area_ratio:
            reasons.append("face_too_small")
        if face_ratio > self._max_face_area_ratio:
            reasons.append("face_too_large")

        x0, y0 = max(int(face.x), 0), max(int(face.y), 0)
        x1 = min(int(face.x + face.width), image.shape[1])
        y1 = min(int(face.y + face.height), image.shape[0])
        if x1 <= x0 or y1 <= y0:
            reasons.append("face_box_out_of_bounds")
            return QualityReport(passed=False, reasons=tuple(reasons), face_area_ratio=face_ratio)

        crop = image[y0:y1, x0:x1]
        gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)

        sharpness = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        if sharpness < self._min_sharpness:
            reasons.append("too_blurry")

        brightness = float(gray.mean())
        if brightness < self._min_brightness:
            reasons.append("too_dark")
        if brightness > self._max_brightness:
            reasons.append("too_bright")

        return QualityReport(
            passed=len(reasons) == 0,
            reasons=tuple(reasons),
            sharpness=sharpness,
            brightness=brightness,
            face_area_ratio=face_ratio,
        )
