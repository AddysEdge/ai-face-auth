import time

import pytest

from faceauth.exceptions import TemplateCorruptedError
from faceauth.pipeline_types import StoredTemplate
from faceauth.storage.serialization import deserialize_template, serialize_template
from tests.conftest import unit_embedding


def _template() -> StoredTemplate:
    return StoredTemplate(
        user_id="alice",
        template_id="tid-123",
        centroid=unit_embedding([1.0, 2.0, 3.0]),
        sample_embeddings=(unit_embedding([1.0, 0.0, 0.0]), unit_embedding([0.0, 1.0, 0.0])),
        created_at=time.time(),
    )


def test_round_trip_preserves_all_fields():
    original = _template()
    restored = deserialize_template(serialize_template(original))
    assert restored.user_id == original.user_id
    assert restored.template_id == original.template_id
    assert restored.centroid.vector.tolist() == pytest.approx(original.centroid.vector.tolist())
    assert len(restored.sample_embeddings) == len(original.sample_embeddings)


def test_deserialize_rejects_non_json_bytes():
    with pytest.raises(TemplateCorruptedError):
        deserialize_template(b"not json at all {{{")


def test_deserialize_rejects_missing_fields():
    with pytest.raises(TemplateCorruptedError, match="missing fields"):
        deserialize_template(b'{"user_id": "alice"}')


def test_deserialize_rejects_unsupported_format_version():
    payload = serialize_template(_template())
    import json

    obj = json.loads(payload)
    obj["format_version"] = 999
    with pytest.raises(TemplateCorruptedError, match="format version"):
        deserialize_template(json.dumps(obj).encode("utf-8"))


def test_deserialize_rejects_malformed_vector():
    import json

    obj = json.loads(serialize_template(_template()))
    obj["centroid"] = "not-a-vector"
    with pytest.raises(TemplateCorruptedError):
        deserialize_template(json.dumps(obj).encode("utf-8"))
