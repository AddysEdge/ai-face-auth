"""Behavioural tests for the strict B18 Stage 0 manifest validator.

These drive the validator with synthetic manifests and assert on what it
*decides*. Every fixture is invented; no participant, camera, recording or
measurement exists behind any of it.

Many tests below are regressions for defects an earlier revision shipped -
each is marked. They exist so those specific holes cannot reopen.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.b18_stage0 import cli  # noqa: E402
from scripts.b18_stage0.schema import (  # noqa: E402
    REQUIRED_DATA_CLASSIFICATION,
    ManifestError,
    require_valid_session,
    validate_session,
)
from scripts.b18_stage0.synthetic import make_trial, session_one, session_two  # noqa: E402


def _rejects(session) -> list[str]:
    findings = validate_session(session)
    assert findings, "expected the validator to reject this manifest"
    return findings


# ------------------------------------------------------------------ baseline


def test_the_synthetic_corpus_is_valid():
    """Without this, every negative test below could pass for the wrong reason."""
    assert validate_session(session_one()) == []
    assert validate_session(session_two()) == []


def test_require_valid_session_returns_the_session_unchanged():
    session = session_one()
    assert require_valid_session(session, "S01.json") is session


# ------------------------------------------- REGRESSION: synthetic-only gate


def test_a_missing_data_classification_is_rejected():
    session = session_one()
    del session["data_classification"]
    assert any("data_classification" in f for f in _rejects(session))


@pytest.mark.parametrize(
    "classification",
    ["real_stage1", "stage2", "production", "", None, "SYNTHETIC_STAGE0", "synthetic"],
)
def test_any_non_synthetic_classification_is_rejected(classification):
    """Stage 0 tooling must not be able to consume real participant data."""
    session = session_one()
    session["data_classification"] = classification
    findings = _rejects(session)
    assert any("data_classification" in f for f in findings)
    assert any("owner-authorized" in f for f in findings)


def test_the_required_classification_is_the_synthetic_one():
    assert REQUIRED_DATA_CLASSIFICATION == "synthetic_stage0"


# ------------------------------------ REGRESSION: whitelist, not a blacklist


@pytest.mark.parametrize(
    "key",
    ["ssn", "participant_contact_info", "nhs_number", "home_address",
     "next_of_kin", "employee_ref", "name", "email", "photo"],
)
def test_any_unknown_session_field_is_rejected(key):
    """A blacklist can be out-guessed; `ssn` slipped past the previous one."""
    session = session_one()
    session[key] = "anything"
    assert any("unknown field" in f and key in f for f in _rejects(session))


def test_an_unknown_field_inside_provenance_is_rejected():
    session = session_one()
    session["provenance"]["operator_home_address"] = "x"
    assert any("unknown field" in f for f in _rejects(session))


def test_an_unknown_field_inside_liveness_config_is_rejected():
    session = session_one()
    session["provenance"]["liveness_config"]["subject_name"] = "x"
    assert any("unknown field" in f for f in _rejects(session))


def test_an_unknown_field_inside_a_trial_is_rejected():
    session = session_one()
    session["trials"][0]["participant_notes_freeform"] = "x"
    assert any("unknown field" in f for f in _rejects(session))


def test_an_unknown_field_inside_a_condition_is_rejected():
    session = session_one()
    session["trials"][0]["condition"]["room_number"] = 3
    assert any("unknown field" in f for f in _rejects(session))


# ------------------------------------------------ REGRESSION: calendar dates


@pytest.mark.parametrize(
    "date", ["2026-99-99", "2026-13-01", "2026-02-30", "2026-00-10",
             "01-01-2026", "2026/01/01", "yesterday", "", "2026-1-1"],
)
def test_an_impossible_or_malformed_date_is_rejected(date):
    session = session_one()
    session["date"] = date
    assert any("date" in f for f in _rejects(session))


def test_an_implausible_year_is_rejected():
    session = session_one()
    session["date"] = "1899-01-01"
    assert any("implausible" in f for f in _rejects(session))


# ------------------------------------- REGRESSION: full config validation


@pytest.mark.parametrize("timeout", ["forever", None, -1.0, 0.0, 10_000.0, True])
def test_an_invalid_challenge_timeout_is_rejected(timeout):
    session = session_one()
    session["provenance"]["liveness_config"]["challenge_timeout_seconds"] = timeout
    assert any("challenge_timeout_seconds" in f for f in _rejects(session))


@pytest.mark.parametrize("frames", [-5, 0, "300", 3.5, None, 10**9])
def test_an_invalid_frame_limit_is_rejected(frames):
    session = session_one()
    session["provenance"]["liveness_config"]["max_frames_per_challenge"] = frames
    assert any("max_frames_per_challenge" in f for f in _rejects(session))


@pytest.mark.parametrize(
    "challenges",
    [["BOGUS"], [], ["BLINK", "TURN_HEAD_LEFT"], "BLINK", None, ["blink"]],
)
def test_only_a_blink_only_configuration_is_accepted(challenges):
    """This analyser models the BLINK decision; anything else needs a different model."""
    session = session_one()
    session["provenance"]["liveness_config"]["enabled_challenges"] = challenges
    assert any("enabled_challenges" in f for f in _rejects(session))


@pytest.mark.parametrize("continuity", [0.0, -0.1, 1.5, "half", None])
def test_an_invalid_continuity_threshold_is_rejected(continuity):
    session = session_one()
    session["provenance"]["liveness_config"]["min_face_continuity"] = continuity
    assert any("min_face_continuity" in f for f in _rejects(session))


def test_a_low_threshold_above_the_high_threshold_is_rejected():
    session = session_one()
    session["provenance"]["liveness_config"]["blink_score_low"] = 0.9
    assert any("never both be satisfied" in f for f in _rejects(session))


@pytest.mark.parametrize("version", ["3", "2.7", "3.12.0.1", "python3.12", ""])
def test_a_malformed_python_version_is_rejected(version):
    session = session_one()
    session["provenance"]["python_version"] = version
    assert any("python_version" in f for f in _rejects(session))


@pytest.mark.parametrize("resolution", ["1280", "1280*720", "big", "x720", ""])
def test_a_malformed_camera_resolution_is_rejected(resolution):
    session = session_one()
    session["provenance"]["camera_resolution"] = resolution
    assert any("camera_resolution" in f for f in _rejects(session))


@pytest.mark.parametrize(
    "deps",
    [{}, {"": "1.0"}, {"pkg": ""}, {"pkg": "latest"}, {"pkg": None},
     {"bad name!": "1.0"}, "ai-edge-litert==2.2.0"],
)
def test_invalid_pinned_dependencies_are_rejected(deps):
    session = session_one()
    session["provenance"]["pinned_dependencies"] = deps
    assert any("pinned_dependencies" in f for f in _rejects(session))


# --------------------------------- REGRESSION: control chars / MD injection


@pytest.mark.parametrize(
    "value",
    ["cam\nlabel", "cam\rlabel", "cam\x00label", "cam\x1blabel",
     "cam | injected | row", "x" * 300],
)
def test_unsafe_report_visible_text_is_rejected(value):
    """These fields reach a Markdown table; newlines and pipes are table syntax."""
    session = session_one()
    session["provenance"]["camera_label"] = value
    assert any("camera_label" in f for f in _rejects(session))


def test_unsafe_operator_role_is_rejected():
    session = session_one()
    session["operator_role"] = "operator\n| evil | row |"
    assert any("operator_role" in f for f in _rejects(session))


def test_unsafe_notes_are_rejected():
    session = session_one()
    session["trials"][0]["notes"] = "note with a | pipe"
    assert any("notes" in f for f in _rejects(session))


def test_empty_notes_are_allowed():
    session = session_one()
    session["trials"][0]["notes"] = ""
    assert validate_session(session) == []


# ----------------------------- REGRESSION: honest empty observation series


def test_a_no_face_trial_may_have_zero_observations():
    """The fixture must not fabricate scores to satisfy the validator."""
    trial = session_one()["trials"][6]
    assert trial["blink_scores"] == []
    assert trial["max_blink_score"] is None
    assert trial["min_blink_score"] is None
    assert trial["frames_with_face"] == 0
    assert validate_session(session_one()) == []


def test_a_valid_trial_may_not_have_zero_observations():
    session = session_one()
    trial = session["trials"][0]
    trial.update(blink_scores=[], max_blink_score=None, min_blink_score=None)
    assert any("empty series is only permitted" in f for f in _rejects(session))


@pytest.mark.parametrize("reason", ["missed_prompt", "operator_error", "ambiguous_ground_truth"])
def test_an_empty_series_is_refused_for_reasons_that_imply_observations(reason):
    session = session_one()
    trial = session["trials"][6]
    trial["exclusion_reason"] = reason
    trial["self_report"] = "blinked"
    assert any("empty series is only permitted" in f for f in _rejects(session))


def test_derived_values_must_be_null_when_there_are_no_observations():
    session = session_one()
    session["trials"][6]["max_blink_score"] = 0.5
    assert any("must be null when there are no observations" in f for f in _rejects(session))


def test_no_face_detected_requires_zero_face_frames():
    session = session_one()
    session["trials"][6]["frames_with_face"] = 3
    session["trials"][6]["face_continuity"] = 3 / 60
    assert any("frames_with_face" in f for f in _rejects(session))


def test_observations_cannot_exceed_frames_with_a_face():
    session = session_one()
    trial = session["trials"][0]
    trial["frames_with_face"] = 2          # but 4 observations recorded
    trial["face_continuity"] = 2 / trial["frames_captured"]
    assert any("observations exceed frames_with_face" in f for f in _rejects(session))


# --------------------------- REGRESSION: ground truth and self-report pairs


@pytest.mark.parametrize("report", ["unsure", "did_not_blink", "n/a"])
def test_a_valid_genuine_blink_trial_requires_a_blinked_self_report(report):
    session = session_one()
    session["trials"][0]["self_report"] = report
    findings = _rejects(session)
    assert any("ambiguous_ground_truth" in f for f in findings)


def test_a_valid_genuine_non_blink_trial_requires_did_not_blink():
    session = session_one()
    session["trials"][3]["self_report"] = "blinked"
    assert any("ambiguous_ground_truth" in f for f in _rejects(session))


def test_a_valid_spoof_trial_requires_the_non_human_self_report():
    session = session_one()
    session["trials"][4]["self_report"] = "blinked"
    assert any("self_report" in f for f in _rejects(session))


def test_a_disagreeing_self_report_must_be_excluded_as_ambiguous():
    """S02 trial 6 is the honest form: unsure, excluded, ambiguous_ground_truth."""
    assert validate_session(session_two()) == []
    session = session_two()
    session["trials"][6]["exclusion_reason"] = "operator_error"
    assert any("ambiguous_ground_truth" in f for f in _rejects(session))


def test_ground_truth_must_agree_with_the_intended_type():
    session = session_one()
    session["trials"][0]["ground_truth"] = "spoof"
    assert any("contradicts intended_type" in f for f in _rejects(session))


# -------------------------------------- REGRESSION: outcome verification


def test_an_outcome_contradicting_its_scores_is_rejected():
    """attempt_outcome is editable; trusting it would let a manifest assert any FAR."""
    session = session_one()
    session["trials"][0].update(
        attempt_outcome="rejected", outcome_reason="no_transient_blink_detected"
    )
    assert any("attempt_outcome" in f for f in _rejects(session))


def test_an_outcome_reason_contradicting_the_outcome_is_rejected():
    session = session_one()
    session["trials"][0]["outcome_reason"] = "face_detection_unstable"
    assert any("outcome_reason" in f for f in _rejects(session))


def test_a_spoof_asserted_as_rejected_despite_crossing_the_threshold_is_rejected():
    """The exact shape that would understate FAR."""
    session = session_two()
    session["trials"][5].update(
        attempt_outcome="rejected", outcome_reason="no_transient_blink_detected"
    )
    assert any("attempt_outcome" in f for f in _rejects(session))


def test_the_continuity_override_is_recomputed():
    """Low continuity must turn a passing decision into face_detection_unstable."""
    session = session_one()
    trial = session["trials"][0]
    trial["frames_captured"] = 60
    trial["frames_with_face"] = 4          # 0.0667 < min_face_continuity 0.5
    trial["face_continuity"] = 4 / 60
    findings = validate_session(session)
    # 4 observations > frames_with_face 4 is fine; the outcome must now flip.
    assert any("face_detection_unstable" in f for f in findings)


def test_an_unknown_outcome_reason_is_rejected():
    session = session_one()
    session["trials"][0]["outcome_reason"] = "looked_fine_to_me"
    assert any("outcome_reason" in f for f in _rejects(session))


def test_an_unknown_label_source_is_rejected():
    session = session_one()
    session["trials"][0]["label_source"] = "vibes"
    assert any("label_source" in f for f in _rejects(session))


# ------------------------------------------- REGRESSION: retry invariants


def test_a_retry_of_a_valid_trial_is_rejected():
    """Retrying a valid trial would count the same cell twice."""
    session = session_one()
    session["trials"][7]["retry_of_trial_index"] = 0
    assert any("only an excluded trial may be retried" in f for f in _rejects(session))


def test_a_retry_under_a_different_condition_is_rejected():
    session = session_one()
    session["trials"][7]["condition"]["lighting"] = "backlit"
    assert any("condition differs" in f for f in _rejects(session))


def test_a_retry_of_a_different_intended_type_is_rejected():
    session = session_one()
    session["trials"][7]["intended_type"] = "G2"
    findings = _rejects(session)
    assert any("intended_type" in f and "differs" in f for f in findings)


def test_a_retry_occurring_before_its_original_is_rejected():
    session = session_one()
    session["trials"][7]["trial_index"] = 3      # original is index 6
    findings = _rejects(session)
    assert any("must occur after" in f for f in findings)


def test_a_retry_pointing_at_a_missing_trial_is_rejected():
    session = session_one()
    session["trials"][7]["retry_of_trial_index"] = 999
    assert any("matches no trial_index" in f for f in _rejects(session))


def test_a_self_referential_retry_is_rejected():
    session = session_one()
    session["trials"][7]["retry_of_trial_index"] = 7
    assert any("retry of itself" in f for f in _rejects(session))


def test_two_retries_of_the_same_trial_are_rejected():
    session = session_one()
    extra = make_trial(
        8, "G1", [0.22, 0.19, 0.55], retry_of_trial_index=6,
        lighting="bright_even", head_pose="frontal", distance_cm=70, eyewear="none",
    )
    session["trials"].append(extra)
    assert any("at most one retry per cell" in f for f in _rejects(session))


def test_duplicate_trial_indices_are_rejected():
    session = session_one()
    session["trials"].append(copy.deepcopy(session["trials"][0]))
    assert any("duplicate trial_index" in f for f in _rejects(session))


# ------------------------------------------------------------- identifiers


@pytest.mark.parametrize("participant", ["Alex", "P0", "p01", "P01X", "", "P-01", "P00001"])
def test_a_non_pseudonymous_participant_id_is_rejected(participant):
    session = session_one()
    session["participant_id"] = participant
    assert any("participant_id" in f for f in _rejects(session))


def test_a_non_pseudonymous_session_id_is_rejected():
    session = session_one()
    session["session_id"] = "Tuesday morning"
    assert any("session_id" in f for f in _rejects(session))


@pytest.mark.parametrize("commit", ["not-hex", "abc", "0" * 39, "0" * 41, "A" * 40])
def test_a_malformed_commit_sha_is_rejected(commit):
    session = session_one()
    session["provenance"]["faceauth_commit"] = commit
    assert any("faceauth_commit" in f for f in _rejects(session))


def test_a_malformed_model_digest_is_rejected():
    session = session_one()
    session["provenance"]["face_landmarker_sha256"] = "deadbeef"
    assert any("face_landmarker_sha256" in f for f in _rejects(session))


# ------------------------------------------------------------ score arrays


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_scores_are_rejected(bad):
    session = session_one()
    session["trials"][0]["blink_scores"] = [0.2, bad]
    assert any("non-finite" in f for f in _rejects(session))


@pytest.mark.parametrize("bad", [-0.01, 1.01, 5.0])
def test_out_of_range_scores_are_rejected(bad):
    session = session_one()
    session["trials"][0]["blink_scores"] = [0.2, bad]
    assert any("0..1" in f for f in _rejects(session))


def test_a_boolean_is_not_accepted_as_a_score():
    session = session_one()
    session["trials"][0]["blink_scores"] = [0.2, True]
    assert any("non-finite or non-numeric" in f for f in _rejects(session))


def test_a_mismatched_derived_max_is_rejected():
    session = session_one()
    session["trials"][0]["max_blink_score"] = 0.99
    assert any("max_blink_score" in f for f in _rejects(session))


def test_a_mismatched_face_continuity_is_rejected():
    session = session_one()
    session["trials"][0]["face_continuity"] = 0.1
    assert any("face_continuity" in f for f in _rejects(session))


def test_turn_ratios_must_be_present_even_when_null():
    session = session_one()
    del session["trials"][0]["turn_ratios"]
    assert any("turn_ratios" in f for f in _rejects(session))


def test_a_malformed_turn_ratio_series_is_rejected():
    session = session_one()
    session["trials"][0]["turn_ratios"] = [0.1, float("nan")]
    assert any("turn_ratios" in f for f in _rejects(session))


# ------------------------------------------------------- reporting behaviour


def test_all_findings_are_reported_not_just_the_first():
    session = session_one()
    session["participant_id"] = "Alex"
    session["date"] = "nope"
    session["trials"][0]["intended_type"] = "ZZ"
    assert len(validate_session(session)) >= 3


def test_findings_name_the_failing_path():
    session = session_one()
    session["trials"][2]["intended_type"] = "ZZ"
    assert any("trials[2].intended_type" in f for f in validate_session(session))


def test_require_valid_session_raises_with_every_finding_prefixed():
    session = session_one()
    session["participant_id"] = "Alex"
    with pytest.raises(ManifestError) as excinfo:
        require_valid_session(session, "S01.json")
    assert all(f.startswith("S01.json:") for f in excinfo.value.findings)


# --------------------------------------------------------------------- CLI


def _write(tmp_path: Path, name: str, session) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(session), encoding="utf-8")
    return path


def test_cli_validate_accepts_the_synthetic_corpus(tmp_path, capsys):
    paths = [_write(tmp_path, "a.json", session_one()),
             _write(tmp_path, "b.json", session_two())]
    assert cli.main(["validate", *[str(p) for p in paths]]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "VALID" in out and "synthetic" in out
    assert "cannot prove that free-text fields are" in out


def test_cli_validate_rejects_an_invalid_manifest_with_exit_one(tmp_path, capsys):
    session = session_one()
    session["participant_id"] = "Alex"
    assert cli.main(["validate", str(_write(tmp_path, "a.json", session))]) == cli.EXIT_INVALID
    err = capsys.readouterr().err
    assert "INVALID" in err and "participant_id" in err
    assert "No manifest was partially accepted" in err


def test_cli_returns_usage_exit_two_for_a_missing_file(tmp_path, capsys):
    assert cli.main(["validate", str(tmp_path / "absent.json")]) == cli.EXIT_USAGE
    assert "no such file" in capsys.readouterr().err


def test_cli_returns_usage_exit_two_for_malformed_json(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{ this is not json", encoding="utf-8")
    assert cli.main(["validate", str(path)]) == cli.EXIT_USAGE
    assert "not valid JSON" in capsys.readouterr().err


# ------------------------------------------- REGRESSION: JSON-level attacks


def test_duplicate_json_object_keys_are_rejected(tmp_path, capsys):
    """json keeps the last duplicate, silently discarding the first."""
    path = tmp_path / "dupe.json"
    path.write_text('{"participant_id": "P01", "participant_id": "P02"}', encoding="utf-8")
    assert cli.main(["validate", str(path)]) == cli.EXIT_USAGE
    assert "duplicate object key" in capsys.readouterr().err


def test_duplicate_keys_nested_in_a_trial_are_rejected(tmp_path, capsys):
    path = tmp_path / "dupe2.json"
    path.write_text('{"trials": [{"trial_index": 1, "trial_index": 2}]}', encoding="utf-8")
    assert cli.main(["validate", str(path)]) == cli.EXIT_USAGE
    assert "duplicate object key" in capsys.readouterr().err


def test_invalid_utf8_is_rejected_with_exit_two(tmp_path, capsys):
    path = tmp_path / "bad_encoding.json"
    path.write_bytes(b'{"session_id": "S01", "x": "\xff\xfe invalid"}')
    assert cli.main(["validate", str(path)]) == cli.EXIT_USAGE
    assert "not valid UTF-8" in capsys.readouterr().err


def test_usage_failure_is_distinct_from_validation_failure(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    invalid = _write(tmp_path, "invalid.json", {"session_id": "S01"})
    assert cli.main(["validate", str(broken)]) == cli.EXIT_USAGE
    assert cli.main(["validate", str(invalid)]) == cli.EXIT_INVALID
