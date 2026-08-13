from __future__ import annotations

from abc import ABC, abstractmethod

from faceauth.pipeline_types import AuthResult


class AuthenticationPolicy(ABC):
    """Final decision point: turns a similarity score into GRANTED/DENIED.

    This is the single place the fail-closed contract is enforced: any
    caller that cannot produce a similarity score (e.g. because an earlier
    stage failed) must not call ``decide`` at all and must instead treat the
    attempt as DENIED directly - see authentication.py.
    """

    @abstractmethod
    def decide(self, similarity: float, user_id: str) -> AuthResult: ...
