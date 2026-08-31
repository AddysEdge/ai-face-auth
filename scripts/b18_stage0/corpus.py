"""Cross-session checks that must pass before any aggregate is computed.

Per-session validation cannot see these. Two copies of one session are each
individually valid, yet aggregating them doubles every count while reporting a
single session - which is exactly what an earlier revision did.

The rule this module encodes: **differences that invalidate comparison stop the
analysis; differences the design expects do not.**

Expected to vary — camera, participant, session, date, seed, and the
environmental conditions the protocol deliberately sweeps.

Refused — the same session twice, conflicting thresholds or liveness
configuration, and results produced by different code, different model weights,
or a different dependency set. Aggregating across those compares numbers that
were never comparable. Doing it anyway would need an explicit stratification
design, which is an owner decision, not a default.
"""

from __future__ import annotations

import json
from pathlib import Path


class CorpusError(Exception):
    """The set of manifests cannot be aggregated. Carries every reason."""

    def __init__(self, findings: list[str]):
        self.findings = findings
        super().__init__(f"{len(findings)} corpus finding(s)")


def _canonical(session: dict) -> str:
    return json.dumps(session, sort_keys=True, ensure_ascii=False)


def check_input_paths(paths: list[Path]) -> list[str]:
    """Duplicate inputs would double-count without any per-file check noticing."""
    findings: list[str] = []
    resolved = [p.resolve() for p in paths]
    seen: dict[Path, int] = {}
    for path in resolved:
        seen[path] = seen.get(path, 0) + 1
    for path, count in sorted(seen.items()):
        if count > 1:
            findings.append(f"input path given {count} times: {path}")
    return findings


def check_sessions(sessions: list[dict]) -> list[str]:
    """Every reason this set of sessions cannot be aggregated."""
    findings: list[str] = []
    if not sessions:
        return ["no sessions to analyse"]

    # --- identity ----------------------------------------------------------
    ids: dict[str, int] = {}
    for session in sessions:
        key = session["session_id"]
        ids[key] = ids.get(key, 0) + 1
    for session_id, count in sorted(ids.items()):
        if count > 1:
            findings.append(
                f"session_id {session_id!r} appears {count} times; each session must "
                f"be supplied once or its trials are counted repeatedly"
            )

    canonical: dict[str, int] = {}
    for session in sessions:
        blob = _canonical(session)
        canonical[blob] = canonical.get(blob, 0) + 1
    duplicates = sum(1 for count in canonical.values() if count > 1)
    if duplicates:
        findings.append(
            f"{duplicates} identical session record(s) supplied more than once"
        )

    # --- runtime comparability ---------------------------------------------
    def distinct(extract) -> list:
        values = {json.dumps(extract(s), sort_keys=True) for s in sessions}
        return sorted(values)

    commits = distinct(lambda s: s["provenance"]["faceauth_commit"])
    if len(commits) > 1:
        findings.append(
            f"sessions were produced by {len(commits)} different code commits "
            f"{[json.loads(c) for c in commits]}; aggregating across them compares "
            f"numbers from different software without a stratification design"
        )

    models = distinct(lambda s: s["provenance"]["face_landmarker_sha256"])
    if len(models) > 1:
        findings.append(
            f"sessions used {len(models)} different model digests; the weights that "
            f"produce the scores must be identical across an aggregate"
        )

    deps = distinct(lambda s: s["provenance"]["pinned_dependencies"])
    if len(deps) > 1:
        findings.append(
            f"sessions used {len(deps)} different pinned dependency sets; the runtime "
            f"that produces the scores must be identical across an aggregate"
        )

    configs = distinct(lambda s: s["provenance"]["liveness_config"])
    if len(configs) > 1:
        parsed = [json.loads(c) for c in configs]
        highs = sorted({c.get("blink_score_high") for c in parsed})
        lows = sorted({c.get("blink_score_low") for c in parsed})
        if len(highs) > 1 or len(lows) > 1:
            findings.append(
                f"sessions disagree on the decision thresholds (high={highs}, "
                f"low={lows}); rates computed against different thresholds are not "
                f"comparable and must not be pooled"
            )
        else:
            findings.append(
                f"sessions disagree on the liveness configuration across "
                f"{len(configs)} variants; the decision path must be identical "
                f"across an aggregate"
            )
    return findings


def require_aggregatable(paths: list[Path], sessions: list[dict]) -> None:
    """Raise unless this set of manifests may legitimately be aggregated."""
    findings = check_input_paths(paths) + check_sessions(sessions)
    if findings:
        raise CorpusError(findings)


def thresholds(sessions: list[dict]) -> tuple[float, float]:
    """The single agreed threshold pair. Only safe after ``require_aggregatable``."""
    config = sessions[0]["provenance"]["liveness_config"]
    return float(config["blink_score_high"]), float(config["blink_score_low"])
