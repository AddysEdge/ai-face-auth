"""FAR/FRR/EER evaluation tooling.

Computes standard biometric-verification metrics from similarity scores the
caller already collected and supplies - this module does not collect,
scrape, or ship any face dataset itself; it is a pure function of whatever
genuine/impostor similarity scores are handed to it (see docs/RESEARCH.md
section 16).

Conventions (matching ThresholdAuthenticationPolicy / cosine similarity,
where higher = more similar, decision is GRANT if similarity >= threshold):
  FAR(t) = P(impostor score >= t)   -- false ACCEPTs at threshold t
  FRR(t) = P(genuine score < t)     -- false REJECTs at threshold t
  EER    = the threshold where FAR(t) == FRR(t) (found by scanning all
           distinct observed scores and taking the closest crossing -
           a simple, auditable method appropriate for a small evaluation
           set, not a claim of publication-grade curve fitting).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np


@dataclass(frozen=True)
class RocPoint:
    threshold: float
    far: float
    frr: float
    tar: float


@dataclass(frozen=True)
class EvaluationReport:
    num_genuine: int
    num_impostor: int
    eer: float
    eer_threshold: float
    recommended_threshold: float
    target_far: float
    roc: tuple[RocPoint, ...]


def load_score_file(path: Path) -> tuple[list[float], list[float]]:
    """Loads {"genuine": [floats...], "impostor": [floats...]} from a JSON
    file the caller already produced (e.g. by running authenticate() against
    known-genuine and known-impostor attempts and recording the similarity
    score each time). Raises ValueError on a malformed file."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "genuine" not in raw or "impostor" not in raw:
        raise ValueError('score file must be a JSON object with "genuine" and "impostor" arrays')
    genuine = [float(x) for x in raw["genuine"]]
    impostor = [float(x) for x in raw["impostor"]]
    if not genuine or not impostor:
        raise ValueError("both genuine and impostor score lists must be non-empty")
    return genuine, impostor


def _far_frr_at(genuine: np.ndarray, impostor: np.ndarray, threshold: float) -> tuple[float, float]:
    far = float((impostor >= threshold).mean())
    frr = float((genuine < threshold).mean())
    return far, frr


def _candidate_thresholds(genuine: np.ndarray, impostor: np.ndarray) -> np.ndarray:
    values = np.concatenate([genuine, impostor, np.array([-1.0, 1.0])])
    return np.unique(values)


def compute_eer(genuine: list[float], impostor: list[float]) -> tuple[float, float]:
    g, i = np.asarray(genuine, dtype=np.float64), np.asarray(impostor, dtype=np.float64)
    thresholds = _candidate_thresholds(g, i)
    far = np.array([_far_frr_at(g, i, t)[0] for t in thresholds])
    frr = np.array([_far_frr_at(g, i, t)[1] for t in thresholds])
    idx = int(np.argmin(np.abs(far - frr)))
    eer = float((far[idx] + frr[idx]) / 2.0)
    return eer, float(thresholds[idx])


def recommended_operating_threshold(
    genuine: list[float], impostor: list[float], target_far: float
) -> float:
    g, i = np.asarray(genuine, dtype=np.float64), np.asarray(impostor, dtype=np.float64)
    thresholds = _candidate_thresholds(g, i)
    far = np.array([_far_frr_at(g, i, t)[0] for t in thresholds])
    qualifying = thresholds[far <= target_far]
    if qualifying.size == 0:
        # Target FAR unreachable with this data: fall back to the strictest
        # available threshold and let the report make that visible.
        return float(thresholds[-1])
    return float(qualifying.min())


def build_roc(genuine: list[float], impostor: list[float], num_points: int = 51) -> tuple[RocPoint, ...]:
    g, i = np.asarray(genuine, dtype=np.float64), np.asarray(impostor, dtype=np.float64)
    thresholds = np.linspace(-1.0, 1.0, num_points)
    points = []
    for t in thresholds:
        far, frr = _far_frr_at(g, i, float(t))
        points.append(RocPoint(threshold=float(t), far=far, frr=frr, tar=1.0 - frr))
    return tuple(points)


def evaluate(genuine: list[float], impostor: list[float], target_far: float = 1e-5) -> EvaluationReport:
    eer, eer_threshold = compute_eer(genuine, impostor)
    recommended = recommended_operating_threshold(genuine, impostor, target_far)
    roc = build_roc(genuine, impostor)
    return EvaluationReport(
        num_genuine=len(genuine),
        num_impostor=len(impostor),
        eer=eer,
        eer_threshold=eer_threshold,
        recommended_threshold=recommended,
        target_far=target_far,
        roc=roc,
    )
