import json
from pathlib import Path

import pytest

from faceauth.evaluate import (
    compute_eer,
    evaluate,
    load_score_file,
    recommended_operating_threshold,
)


def test_perfectly_separated_scores_give_zero_eer():
    genuine = [0.6, 0.7, 0.8, 0.9]
    impostor = [0.0, 0.1, 0.2, 0.3]
    eer, threshold = compute_eer(genuine, impostor)
    assert eer == pytest.approx(0.0)
    assert 0.3 <= threshold <= 0.6


def test_fully_overlapping_scores_give_high_eer():
    genuine = [0.5, 0.5, 0.5, 0.5]
    impostor = [0.5, 0.5, 0.5, 0.5]
    eer, _ = compute_eer(genuine, impostor)
    assert eer > 0.4  # near-total overlap -> EER near 0.5


def test_recommended_threshold_meets_target_far_when_achievable():
    genuine = [0.6, 0.7, 0.8, 0.9]
    impostor = [0.0, 0.1, 0.2, 0.3]
    threshold = recommended_operating_threshold(genuine, impostor, target_far=0.0)
    # No impostor score should be >= threshold.
    assert all(i < threshold for i in impostor)


def test_evaluate_report_has_consistent_counts():
    genuine = [0.6, 0.65, 0.7]
    impostor = [0.1, 0.15, 0.2, 0.25]
    report = evaluate(genuine, impostor, target_far=0.1)
    assert report.num_genuine == 3
    assert report.num_impostor == 4
    assert len(report.roc) > 0
    assert 0.0 <= report.eer <= 1.0


def test_load_score_file_round_trip(tmp_path: Path):
    path = tmp_path / "scores.json"
    path.write_text(json.dumps({"genuine": [0.7, 0.8], "impostor": [0.1, 0.2]}))
    genuine, impostor = load_score_file(path)
    assert genuine == [0.7, 0.8]
    assert impostor == [0.1, 0.2]


def test_load_score_file_rejects_missing_keys(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"genuine": [0.7]}))
    with pytest.raises(ValueError):
        load_score_file(path)


def test_load_score_file_rejects_empty_lists(tmp_path: Path):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"genuine": [], "impostor": [0.1]}))
    with pytest.raises(ValueError):
        load_score_file(path)
