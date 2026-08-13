"""Exercises the dev-fallback FileTemplateStore - platform-independent, so
this is the backend used to cover the TemplateStore contract in CI. The
DPAPI backend is covered separately by a Windows-only integration test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from faceauth.exceptions import TemplateCorruptedError, TemplateNotFoundError
from faceauth.storage.file_template_store import FileTemplateStore
from tests.conftest import unit_embedding


@pytest.fixture
def store(tmp_path: Path) -> FileTemplateStore:
    return FileTemplateStore(data_dir=tmp_path / "templates", key_path=tmp_path / "key")


def test_save_then_load_round_trips(store: FileTemplateStore):
    centroid = unit_embedding([1.0, 0.0, 0.0])
    samples = (unit_embedding([1.0, 0.0, 0.0]), unit_embedding([0.9, 0.1, 0.0]))
    saved = store.save("alice", centroid, samples)
    loaded = store.load("alice")
    assert loaded.user_id == "alice"
    assert loaded.template_id == saved.template_id
    assert len(loaded.sample_embeddings) == 2


def test_load_missing_user_raises_template_not_found(store: FileTemplateStore):
    with pytest.raises(TemplateNotFoundError):
        store.load("nobody")


def test_exists_reflects_save_and_delete(store: FileTemplateStore):
    assert not store.exists("alice")
    store.save("alice", unit_embedding([1.0, 0.0]), ())
    assert store.exists("alice")
    store.delete("alice")
    assert not store.exists("alice")


def test_delete_is_safe_when_nothing_enrolled(store: FileTemplateStore):
    store.delete("nobody")  # must not raise


def test_list_users_returns_all_enrolled(store: FileTemplateStore):
    store.save("alice", unit_embedding([1.0, 0.0]), ())
    store.save("bob", unit_embedding([0.0, 1.0]), ())
    assert set(store.list_users()) == {"alice", "bob"}


def test_save_overwrites_existing_template_for_same_user(store: FileTemplateStore):
    store.save("alice", unit_embedding([1.0, 0.0]), ())
    second = store.save("alice", unit_embedding([0.0, 1.0]), ())
    loaded = store.load("alice")
    assert loaded.template_id == second.template_id
    assert len(store.list_users()) == 1


def test_corrupted_ciphertext_raises_template_corrupted(store: FileTemplateStore, tmp_path: Path):
    store.save("alice", unit_embedding([1.0, 0.0]), ())
    # Corrupt the on-disk file directly - simulates disk corruption/tampering.
    path = next((tmp_path / "templates").glob("*.devfile"))
    path.write_bytes(b"not a valid fernet token")
    with pytest.raises(TemplateCorruptedError):
        store.load("alice")


def test_wrong_key_cannot_decrypt_another_stores_data(tmp_path: Path):
    store_a = FileTemplateStore(data_dir=tmp_path / "templates", key_path=tmp_path / "key_a")
    store_a.save("alice", unit_embedding([1.0, 0.0]), ())

    store_b = FileTemplateStore(data_dir=tmp_path / "templates", key_path=tmp_path / "key_b")
    with pytest.raises(TemplateCorruptedError):
        store_b.load("alice")


def test_user_id_with_unusual_characters_is_handled_safely(store: FileTemplateStore):
    weird_id = "../../etc/passwd; drop table users;"
    store.save(weird_id, unit_embedding([1.0, 0.0]), ())
    loaded = store.load(weird_id)
    assert loaded.user_id == weird_id
