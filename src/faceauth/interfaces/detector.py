from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np

from faceauth.pipeline_types import FaceBox


class FaceDetector(ABC):
    """Locates faces (and 5-point landmarks) in a BGR image."""

    @abstractmethod
    def detect(self, image: np.ndarray) -> list[FaceBox]:
        """Return all detected faces, most-confident first. Empty list if none."""
