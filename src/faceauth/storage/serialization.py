"""Template <-> bytes serialization.

Uses JSON, not pickle - pickle can execute arbitrary code on
deserialization, which is an unacceptable risk for a file whose whole
purpose is to be loaded after being decrypted from disk (goal requirement:
avoid unsafe serialization formats for biometric templates). Embedding
vectors are stored as plain lists of floats; there is no executable content
anywhere in this format.
"""

from __future__ import annotations

import json

import numpy as np

from faceauth.exceptions import TemplateCorruptedError
from faceauth.pipeline_types import Embedding, StoredTemplate

_FORMAT_VERSION = 1


def serialize_template(template: StoredTemplate) -> bytes:
    payload = {
        "format_version": _FORMAT_VERSION,
        "user_id": template.user_id,
        "template_id": template.template_id,
        "created_at": template.created_at,
        "centroid": template.centroid.vector.tolist(),
        "samples": [sample.vector.tolist() for sample in template.sample_embeddings],
    }
    return json.dumps(payload).encode("utf-8")


def deserialize_template(data: bytes) -> StoredTemplate:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TemplateCorruptedError(f"template payload is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise TemplateCorruptedError("template payload must be a JSON object")

    required = {"format_version", "user_id", "template_id", "created_at", "centroid", "samples"}
    missing = required - payload.keys()
    if missing:
        raise TemplateCorruptedError(f"template payload missing fields: {sorted(missing)}")

    if payload["format_version"] != _FORMAT_VERSION:
        raise TemplateCorruptedError(
            f"unsupported template format version: {payload['format_version']}"
        )

    try:
        centroid_vec = np.asarray(payload["centroid"], dtype=np.float32)
        sample_vecs = [np.asarray(s, dtype=np.float32) for s in payload["samples"]]
        centroid = Embedding(vector=centroid_vec)
        samples = tuple(Embedding(vector=v) for v in sample_vecs)
    except (TypeError, ValueError) as exc:
        raise TemplateCorruptedError(f"template payload contains invalid vectors: {exc}") from exc

    return StoredTemplate(
        user_id=str(payload["user_id"]),
        template_id=str(payload["template_id"]),
        centroid=centroid,
        sample_embeddings=samples,
        created_at=float(payload["created_at"]),
    )
