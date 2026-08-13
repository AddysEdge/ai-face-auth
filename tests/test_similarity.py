import time

import pytest

from faceauth.pipeline_types import StoredTemplate
from faceauth.similarity.cosine_similarity import (
    CentroidCosineSimilarityEngine,
    MaxSampleCosineSimilarityEngine,
    cosine_similarity,
)
from tests.conftest import unit_embedding


def test_cosine_similarity_identical_vectors_is_one():
    a = unit_embedding([1.0, 0.0, 0.0])
    b = unit_embedding([1.0, 0.0, 0.0])
    assert cosine_similarity(a, b) == pytest.approx(1.0)


def test_cosine_similarity_orthogonal_vectors_is_zero():
    a = unit_embedding([1.0, 0.0, 0.0])
    b = unit_embedding([0.0, 1.0, 0.0])
    assert cosine_similarity(a, b) == pytest.approx(0.0, abs=1e-6)


def test_cosine_similarity_opposite_vectors_is_negative_one():
    a = unit_embedding([1.0, 0.0, 0.0])
    b = unit_embedding([-1.0, 0.0, 0.0])
    assert cosine_similarity(a, b) == pytest.approx(-1.0)


def _template(centroid_seed, sample_seeds) -> StoredTemplate:
    return StoredTemplate(
        user_id="u",
        template_id="t",
        centroid=unit_embedding(centroid_seed),
        sample_embeddings=tuple(unit_embedding(s) for s in sample_seeds),
        created_at=time.time(),
    )


def test_centroid_engine_compares_only_against_centroid():
    template = _template([1.0, 0.0], [[0.0, 1.0]])  # centroid far from the sample
    probe = unit_embedding([1.0, 0.0])
    engine = CentroidCosineSimilarityEngine()
    assert engine.compare(probe, template) == pytest.approx(1.0)


def test_max_sample_engine_picks_the_best_matching_sample():
    template = _template([0.5, 0.5], [[1.0, 0.0], [0.0, 1.0]])
    probe = unit_embedding([1.0, 0.0])
    engine = MaxSampleCosineSimilarityEngine()
    # Best match is the [1,0] sample (similarity 1.0), not the centroid.
    assert engine.compare(probe, template) == pytest.approx(1.0)


def test_max_sample_engine_falls_back_to_centroid_when_no_samples():
    template = StoredTemplate(
        user_id="u",
        template_id="t",
        centroid=unit_embedding([1.0, 0.0]),
        sample_embeddings=(),
        created_at=time.time(),
    )
    probe = unit_embedding([1.0, 0.0])
    engine = MaxSampleCosineSimilarityEngine()
    assert engine.compare(probe, template) == pytest.approx(1.0)
