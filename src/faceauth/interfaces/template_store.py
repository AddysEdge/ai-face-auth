from __future__ import annotations

from abc import ABC, abstractmethod

from faceauth.pipeline_types import Embedding, StoredTemplate


class TemplateStore(ABC):
    """Persists and retrieves encrypted biometric templates.

    Implementations own the encryption/decryption of everything they persist
    - a caller never sees ciphertext or a raw file format, only
    ``StoredTemplate``/``Embedding`` objects. See docs/RESEARCH.md section 11
    for why DPAPI is the default backend on Windows.
    """

    @abstractmethod
    def save(
        self,
        user_id: str,
        centroid: Embedding,
        sample_embeddings: tuple[Embedding, ...],
    ) -> StoredTemplate:
        """Encrypt and persist a template, overwriting any existing one for user_id."""

    @abstractmethod
    def load(self, user_id: str) -> StoredTemplate:
        """Raises TemplateNotFoundError / TemplateCorruptedError as appropriate."""

    @abstractmethod
    def delete(self, user_id: str) -> None: ...

    @abstractmethod
    def exists(self, user_id: str) -> bool: ...

    @abstractmethod
    def list_users(self) -> list[str]: ...
