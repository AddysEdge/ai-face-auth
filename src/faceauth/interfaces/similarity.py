from __future__ import annotations

from abc import ABC, abstractmethod

from faceauth.pipeline_types import Embedding, StoredTemplate


class SimilarityEngine(ABC):
    """Scores how similar a freshly captured embedding is to a stored template.

    Returns a float where *higher means more similar*, in whatever scale the
    implementation defines (cosine similarity's natural [-1, 1] range for the
    default engine) - AuthenticationPolicy is configured with a matching
    threshold, so the two are never mixed across implementations silently.
    """

    @abstractmethod
    def compare(self, probe: Embedding, template: StoredTemplate) -> float: ...
