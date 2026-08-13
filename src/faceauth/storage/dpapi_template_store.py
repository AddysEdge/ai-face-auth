"""Windows DPAPI-backed template storage.

Encryption is real ``CryptProtectData``/``CryptUnprotectData`` via
``pywin32``'s ``win32crypt`` binding (verified against a live round-trip
during development - see docs/RESEARCH.md section 11), user scope by
default: only the same Windows user account, on the same machine, can
decrypt a template written here. That guarantee - not "we obfuscated the
file" - is what this store relies on.

Filenames are a SHA-256 hash of the user_id, not the user_id itself, so
arbitrary user_id strings can never cause a path-traversal or
invalid-filename issue; the real user_id lives inside the encrypted
payload and is recovered by decrypting.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from pathlib import Path

from faceauth.exceptions import TemplateCorruptedError, TemplateNotFoundError
from faceauth.interfaces.template_store import TemplateStore
from faceauth.pipeline_types import Embedding, StoredTemplate
from faceauth.storage.serialization import deserialize_template, serialize_template

_ENTROPY = b"faceauth-template-v1"
_SUFFIX = ".dpapi"


def _user_hash(user_id: str) -> str:
    return hashlib.sha256(user_id.encode("utf-8")).hexdigest()


class DpapiTemplateStore(TemplateStore):
    def __init__(self, data_dir: Path) -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        try:
            import win32crypt  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "DpapiTemplateStore requires pywin32 (win32crypt) and a Windows platform"
            ) from exc

    def _path_for(self, user_id: str) -> Path:
        return self._data_dir / f"{_user_hash(user_id)}{_SUFFIX}"

    def save(
        self,
        user_id: str,
        centroid: Embedding,
        sample_embeddings: tuple[Embedding, ...],
    ) -> StoredTemplate:
        import win32crypt

        template = StoredTemplate(
            user_id=user_id,
            template_id=uuid.uuid4().hex,
            centroid=centroid,
            sample_embeddings=sample_embeddings,
            created_at=time.time(),
        )
        plaintext = serialize_template(template)
        ciphertext = win32crypt.CryptProtectData(
            plaintext, "faceauth biometric template", _ENTROPY, None, None, 0
        )
        self._path_for(user_id).write_bytes(ciphertext)
        return template

    def load(self, user_id: str) -> StoredTemplate:
        import pywintypes
        import win32crypt

        path = self._path_for(user_id)
        if not path.exists():
            raise TemplateNotFoundError(f"no template enrolled for user {user_id!r}")
        ciphertext = path.read_bytes()
        try:
            _descr, plaintext = win32crypt.CryptUnprotectData(
                ciphertext, _ENTROPY, None, None, 0
            )
        except pywintypes.error as exc:
            raise TemplateCorruptedError(
                f"failed to decrypt template for user {user_id!r}: {exc}"
            ) from exc
        template = deserialize_template(plaintext)
        if template.user_id != user_id:
            raise TemplateCorruptedError(
                f"decrypted template user_id mismatch: expected {user_id!r}, "
                f"got {template.user_id!r}"
            )
        return template

    def delete(self, user_id: str) -> None:
        path = self._path_for(user_id)
        path.unlink(missing_ok=True)

    def exists(self, user_id: str) -> bool:
        return self._path_for(user_id).exists()

    def list_users(self) -> list[str]:
        users = []
        for path in self._data_dir.glob(f"*{_SUFFIX}"):
            try:
                stem_user_id = self._recover_user_id(path)
            except TemplateCorruptedError:
                continue
            users.append(stem_user_id)
        return users

    def _recover_user_id(self, path: Path) -> str:
        import pywintypes
        import win32crypt

        ciphertext = path.read_bytes()
        try:
            _descr, plaintext = win32crypt.CryptUnprotectData(
                ciphertext, _ENTROPY, None, None, 0
            )
        except pywintypes.error as exc:
            raise TemplateCorruptedError(str(exc)) from exc
        return deserialize_template(plaintext).user_id
