"""Tests that the oracle comparison actually enforces its tolerances.

An earlier revision of `scripts/b17_option_a/compare.py` exited on detection
agreement alone, so any magnitude of landmark, blink, blendshape or turn-ratio
error still produced exit 0. These tests breach each limit in turn and require
a nonzero exit, so the harness cannot silently regress to non-enforcing again.

No model weights and no `mediapipe` are needed: the comparison's measurement
and its judgement are separate functions, and only the judgement is under test
here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.b17_option_a import compare  # noqa: E402


def _face_row(case: str, **overrides) -> dict:
    row = {
        "case": case,
        "width": 480,
        "height": 480,
        "oracle_detected": True,
        "replica_detected": True,
        "replica_detector_fired": True,
        "replica_presence_passed": True,
        "presence_score": 0.999,
        "landmark_error": 0.001,
        "landmark_error_px": 0.5,
        "blink_error": 0.005,
        "blendshape_error": 0.01,
        "turn_ratio_error": 0.001,
    }
    row.update(overrides)
    return row


def _no_face_row(case: str, **overrides) -> dict:
    row = {
        "case": case,
        "width": 480,
        "height": 480,
        "oracle_detected": False,
        "replica_detected": False,
        "replica_detector_fired": False,
        "replica_presence_passed": False,
    }
    row.update(overrides)
    return row


def _report(rows: list[dict] | None = None) -> dict:
    rows = rows if rows is not None else [_face_row("alpha"), _no_face_row("omega")]
    relevant = [r for r in rows if r["replica_detector_fired"]]
    return {
        "generated": "2026-08-31T00:00:00+00:00",
        "source_commit": "0" * 40,
        "bundle": {"path": "face_landmarker.task", "sha256": "a" * 64},
        "versions": {"mediapipe": "1.0.1", "ai_edge_litert": "2.2.0",
                     "numpy": "2.5.2", "cv2": "5.0.0"},
        "oracle": "mediapipe==1.0.1",
        "replica": "ai-edge-litert",
        "cases": len(rows),
        "expected_cases": [r["case"] for r in rows],
        "tolerances": dict(compare.TOLERANCES),
        "detection_agreement": sum(
            r["oracle_detected"] == r["replica_detected"] for r in rows
        ),
        "presence_agreement": sum(
            r["replica_presence_passed"] == r["oracle_detected"] for r in relevant
        ),
        "presence_relevant_cases": len(relevant),
        "worst": {},
        "results": rows,
    }


def _run_main(monkeypatch, report, tmp_path: Path) -> int:
    monkeypatch.setattr(compare, "run", lambda _bundle: report)
    monkeypatch.setattr(compare, "_require_bundle", lambda path: path)
    return compare.main(["--bundle", str(tmp_path / "b.task"),
                         "--out", str(tmp_path / "out.json")])


# --------------------------------------------------------------- the baseline


def test_a_clean_report_passes():
    """Without this, every test below could pass for the wrong reason."""
    assert compare.evaluate(_report()) == []


def test_a_clean_report_exits_zero_and_writes_results(monkeypatch, tmp_path):
    assert _run_main(monkeypatch, _report(), tmp_path) == 0
    written = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert written["passed"] is True
    assert written["failures"] == []


# ------------------------------------------------------- each limit breached


@pytest.mark.parametrize(
    "metric",
    ["landmark_error_px", "blink_error", "turn_ratio_error", "blendshape_error"],
)
def test_exceeding_each_tolerance_fails(metric, monkeypatch, tmp_path):
    """One metric over its limit, everything else clean, must fail the run."""
    over = compare.TOLERANCES[metric] * 1.01
    rows = [_face_row("alpha", **{metric: over}), _no_face_row("omega")]
    report = _report(rows)

    failures = compare.evaluate(report)
    assert any(metric in f and "exceeds limit" in f for f in failures), failures
    assert _run_main(monkeypatch, report, tmp_path) != 0


@pytest.mark.parametrize(
    "metric",
    ["landmark_error_px", "blink_error", "turn_ratio_error", "blendshape_error"],
)
def test_sitting_exactly_on_each_tolerance_passes(metric):
    """The limit is inclusive, so a value equal to it is not a breach.

    Pinned so a later change to `>` vs `>=` is a deliberate decision rather
    than an accident.
    """
    rows = [_face_row("alpha", **{metric: compare.TOLERANCES[metric]})]
    assert compare.evaluate(_report(rows)) == []


# ------------------------------------------------------------- disagreements


def test_detection_disagreement_fails(monkeypatch, tmp_path):
    rows = [_face_row("alpha"), _no_face_row("omega", oracle_detected=True)]
    report = _report(rows)
    assert any("detection agreement" in f for f in compare.evaluate(report))
    assert _run_main(monkeypatch, report, tmp_path) != 0


def test_presence_disagreement_fails(monkeypatch, tmp_path):
    """Detector fired, replica let it through, oracle says no face."""
    rows = [
        _face_row("alpha"),
        _no_face_row("gate", replica_detector_fired=True,
                     replica_presence_passed=True, oracle_detected=False),
    ]
    report = _report(rows)
    report["presence_agreement"] = 1  # alpha agrees, gate does not
    assert any("presence agreement" in f for f in compare.evaluate(report))
    assert _run_main(monkeypatch, report, tmp_path) != 0


# ----------------------------------------------------------- malformed input


def test_a_missing_expected_case_fails(monkeypatch, tmp_path):
    report = _report([_face_row("alpha")])
    report["expected_cases"] = ["alpha", "beta"]
    assert any("missing expected case" in f for f in compare.evaluate(report))
    assert _run_main(monkeypatch, report, tmp_path) != 0


def test_a_duplicated_case_fails():
    report = _report([_face_row("alpha"), _face_row("alpha")])
    assert any("duplicate case" in f for f in compare.evaluate(report))


@pytest.mark.parametrize("metric", list(compare.REQUIRED_FACE_METRICS))
def test_a_missing_metric_on_a_detected_case_fails(metric, monkeypatch, tmp_path):
    """A metric that quietly stops being produced must not read as a pass."""
    row = _face_row("alpha")
    del row[metric]
    report = _report([row])
    assert any(f"missing metric {metric}" in f for f in compare.evaluate(report))
    assert _run_main(monkeypatch, report, tmp_path) != 0


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_measurements_fail(bad, monkeypatch, tmp_path):
    report = _report([_face_row("alpha", blink_error=bad)])
    assert any("not a finite number" in f for f in compare.evaluate(report))
    assert _run_main(monkeypatch, report, tmp_path) != 0


def test_a_non_numeric_measurement_fails():
    report = _report([_face_row("alpha", blink_error="0.001")])
    assert any("not a finite number" in f for f in compare.evaluate(report))


def test_an_empty_report_fails():
    assert compare.evaluate({"results": []}) == ["malformed report: no results"]
    assert compare.evaluate({}) == ["malformed report: no results"]


# ------------------------------------------------------------- the contract


def test_the_declared_tolerances_are_no_weaker_than_required():
    """These ceilings are part of the acceptance argument, not tuning knobs.

    Pinned so relaxing one to make a run pass shows up as a deliberate test
    change in review rather than a quiet edit to a constant.
    """
    assert compare.TOLERANCES["landmark_error_px"] <= 1.0
    assert compare.TOLERANCES["blink_error"] <= 0.02
    assert compare.TOLERANCES["turn_ratio_error"] <= 0.0045
    assert compare.TOLERANCES["blendshape_error"] <= 0.05


def test_the_turn_ratio_limit_is_a_tenth_of_the_configured_threshold():
    import inspect

    from faceauth.liveness.challenge_response import LiteRtChallengeResponseLiveness

    signature = inspect.signature(LiteRtChallengeResponseLiveness.__init__)
    configured = signature.parameters["head_turn_min_swing"].default
    assert compare.TOLERANCES["turn_ratio_error"] <= configured * 0.10
