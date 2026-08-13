"""Dev-only fallback template storage for non-Windows / no-DPAPI environments.

NOT SECURE FOR PRODUCTION USE. The encryption key is a plain file on disk
next to the data it protects, protected only by filesystem permissions -
this provides confidentiality against casual inspection but none of DPAPI's
account-binding guarantee. This backend exists solely so the pipeline and
test suite can run on machines without Windows/pywin32. Every construction
logs (or, if no logger is supplied, emits a Python warning) loudly.
"""

from __future__ import annotations

import logging
import time
import uuid
import warnings
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from faceauth.exceptions import TemplateCorruptedError, TemplateNotFoundError
from faceauth.interfaces.template_store import TemplateStore
from faceauth.logging_utils import SecurityLogger
from faceauth.pipeline_types import Embedding, StoredTemplate
from faceauth.storage.serialization import deserialize_template, serialize_template

_SUFFIX = ".devfile"
_DEV_WARNING = (
    "FileTemplateStore is a DEV-ONLY fallback and is NOT secure for production use. "
    "Use DpapiTemplateStore on Windows."
)


class FileTemplateStore(TemplateStore):
    def __init__(
        self,
        data_dir: Path,
        key_path: Path,
        logger: SecurityLogger | None = None,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        if logger is not None:
            logger.log_event("dev_template_store_active", level=logging.WARNING, backend="file_dev")
        else:
            warnings.warn(_DEV_WARNING, RuntimeWarning, stacklevel=2)
        self._fernet = self._load_or_create_key(Path(key_path))

    @staticmethod
    def _load_or_create_key(key_path: Path) -> Fernet:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            key = key_path.read_bytes()
        else:
            key = Fernet.generate_key()
            key_path.write_bytes(key)
        return Fernet(key)

    def _path_for(self, user_id: str) -> Path:
        import hashlib

        digest = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
        return self._data_dir / f"{digest}{_SUFFIX}"

    def save(
        self,
        user_id: str,
        centroid: Embedding,
        sample_embeddings: tuple[Embedding, ...],
    ) -> StoredTemplate:
        template = StoredTemplate(
            user_id=user_id,
            template_id=uuid.uuid4().hex,
            centroid=centroid,
            sample_embeddings=sample_embeddings,
            created_at=time.time(),
        )
        plaintext = serialize_template(template)
        ciphertext = self._fernet.encrypt(plaintext)
        self._path_for(user_id).write_bytes(ciphertext)
        return template

    def load(self, user_id: str) -> StoredTemplate:
        path = self._path_for(user_id)
        if not path.exists():
            raise TemplateNotFoundError(f"no template enrolled for user {user_id!r}")
        ciphertext = path.read_bytes()
        try:
            plaintext = self._fernet.decrypt(ciphertext)
        except InvalidToken as exc:
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
        self._path_for(user_id).unlink(missing_ok=True)

    def exists(self, user_id: str) -> bool:
        return self._path_for(user_id).exists()

    def list_users(self) -> list[str]:
        users = []
        for path in self._data_dir.glob(f"*{_SUFFIX}"):
            try:
                plaintext = self._fernet.decrypt(path.read_bytes())
                users.append(deserialize_template(plaintext).user_id)
            except (InvalidToken, TemplateCorruptedError):
                continue
        return users
