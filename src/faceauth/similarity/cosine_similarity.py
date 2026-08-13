"""Cosine-similarity engine, with an optional max-over-enrollment-samples strategy.

Both operands are already L2-normalized (enforced by ``Embedding``'s own
constructor - see pipeline_types.py), so cosine similarity reduces to a
plain dot product. See docs/RESEARCH.md section 10 for why cosine similarity
(rather than raw Euclidean distance) is the convention for this model family.
"""

from __future__ import annotations

import numpy as np

from faceauth.interfaces.similarity import SimilarityEngine
from faceauth.pipeline_types import Embedding, StoredTemplate


def cosine_similarity(a: Embedding, b: Embedding) -> float:
    return float(np.dot(a.vector, b.vector))


class CentroidCosineSimilarityEngine(SimilarityEngine):
    """Compares only against the stored centroid embedding."""

    def compare(self, probe: Embedding, template: StoredTemplate) -> float:
        return cosine_similarity(probe, template.centroid)


class MaxSampleCosineSimilarityEngine(SimilarityEngine):
    """Compares against every enrollment sample and takes the best match.

    More tolerant of a single unusual enrollment sample than the centroid
    strategy, at the cost of being (slightly) more permissive - documented
    in RESEARCH.md as an alternative, not the default.
    """

    def compare(self, probe: Embedding, template: StoredTemplate) -> float:
        candidates = template.sample_embeddings or (template.centroid,)
        return max(cosine_similarity(probe, sample) for sample in candidates)
