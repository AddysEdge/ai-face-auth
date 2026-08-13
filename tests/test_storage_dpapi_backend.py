"""Real DPAPI round-trip tests against DpapiTemplateStore.

Windows-only (skipped elsewhere) - exercises the actual
win32crypt.CryptProtectData/CryptUnprotectData calls, not a mock, matching
the real-hardware verification already done manually for this backend (see
docs/RESEARCH.md section 11).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from faceauth.exceptions import TemplateCorruptedError, TemplateNotFoundError
from tests.conftest import unit_embedding

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")


@pytest.fixture
def store(tmp_path: Path):
    from faceauth.storage.dpapi_template_store import DpapiTemplateStore

    return DpapiTemplateStore(data_dir=tmp_path / "templates")


def test_dpapi_save_then_load_round_trips(store):
    centroid = unit_embedding([1.0, 0.0, 0.0])
    samples = (unit_embedding([1.0, 0.0, 0.0]), unit_embedding([0.9, 0.1, 0.0]))
    saved = store.save("alice", centroid, samples)
    loaded = store.load("alice")
    assert loaded.template_id == saved.template_id
    assert loaded.user_id == "alice"
    assert len(loaded.sample_embeddings) == 2


def test_dpapi_load_missing_user_raises_not_found(store):
    with pytest.raises(TemplateNotFoundError):
        store.load("nobody")


def test_dpapi_encrypted_file_is_not_plaintext_json(store, tmp_path: Path):
    store.save("alice", unit_embedding([1.0, 0.0]), ())
    path = next((tmp_path / "templates").glob("*.dpapi"))
    raw = path.read_bytes()
    assert b"alice" not in raw  # the plaintext user_id must not appear in ciphertext
    assert not raw.startswith(b"{")  # not raw JSON


def test_dpapi_tampered_ciphertext_raises_corrupted(store, tmp_path: Path):
    store.save("alice", unit_embedding([1.0, 0.0]), ())
    path = next((tmp_path / "templates").glob("*.dpapi"))
    tampered = bytearray(path.read_bytes())
    tampered[-1] ^= 0xFF  # flip the last byte
    path.write_bytes(bytes(tampered))
    with pytest.raises(TemplateCorruptedError):
        store.load("alice")


def test_dpapi_list_users_recovers_real_user_ids(store):
    store.save("alice", unit_embedding([1.0, 0.0]), ())
    store.save("bob", unit_embedding([0.0, 1.0]), ())
    assert set(store.list_users()) == {"alice", "bob"}


def test_dpapi_delete_removes_template(store):
    store.save("alice", unit_embedding([1.0, 0.0]), ())
    assert store.exists("alice")
    store.delete("alice")
    assert not store.exists("alice")
