from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np

from faceauth.pipeline_types import FaceBox, QualityReport


class FaceQualityChecker(ABC):
    """Judges whether a detected face is good enough to embed/enroll/authenticate with."""

    @abstractmethod
    def check(self, image: np.ndarray, face: FaceBox) -> QualityReport: ...
