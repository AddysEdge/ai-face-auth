"""Combines multiple LivenessProvider backends with AND semantics.

Used to add the optional passive backend (see passive_onnx.py) on top of
the default active challenge-response provider without either provider
knowing about the other. Every sub-provider must pass for the composite to
pass - a single sub-provider refusing is enough to fail closed.
"""

from __future__ import annotations

from faceauth.interfaces.liveness import LivenessProvider
from faceauth.pipeline_types import ChallengeKind, FaceBox, Frame, LivenessResult


class CompositeLivenessProvider(LivenessProvider):
    def __init__(self, providers: list[LivenessProvider]) -> None:
        if not providers:
            raise ValueError("CompositeLivenessProvider requires at least one provider")
        self._providers = providers

    def new_challenge(self) -> ChallengeKind:
        challenges = [p.new_challenge() for p in self._providers]
        return challenges[0]

    def observe(self, frame: Frame, face: FaceBox) -> None:
        for provider in self._providers:
            provider.observe(frame, face)

    def finalize(self) -> LivenessResult:
        results = [p.finalize() for p in self._providers]
        failed_reasons = [r.reason for r in results if not r.passed]
        passed = len(failed_reasons) == 0
        merged_details: dict[str, float] = {}
        for i, r in enumerate(results):
            merged_details.update({f"provider{i}_{k}": v for k, v in r.details.items()})
        return LivenessResult(
            passed=passed,
            reason="all_providers_passed" if passed else ";".join(failed_reasons),
            details=merged_details,
        )
