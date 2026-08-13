import numpy as np
import pytest

from faceauth.pipeline_types import Embedding


def test_embedding_accepts_normalized_vector():
    vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)
    emb = Embedding(vector=vec)
    assert np.isclose(np.linalg.norm(emb.vector), 1.0)


def test_embedding_rejects_non_normalized_vector():
    vec = np.array([3.0, 4.0, 0.0], dtype=np.float32)  # norm = 5
    with pytest.raises(ValueError, match="L2-normalized"):
        Embedding(vector=vec)


def test_embedding_rejects_non_1d_vector():
    vec = np.ones((2, 2), dtype=np.float32)
    with pytest.raises(ValueError, match="1-D"):
        Embedding(vector=vec)
