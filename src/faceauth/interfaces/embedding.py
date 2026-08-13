from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np

from faceauth.pipeline_types import Embedding, FaceBox


class FaceEmbeddingModel(ABC):
    """Turns a detected face into a fixed-size, L2-normalized embedding vector."""

    @property
    @abstractmethod
    def embedding_dim(self) -> int: ...

    @abstractmethod
    def embed(self, image: np.ndarray, face: FaceBox) -> Embedding:
        """Align and embed the given face. Raises ModelInferenceError on failure."""
