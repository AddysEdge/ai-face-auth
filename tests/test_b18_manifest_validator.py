"""Behavioural tests for the B18 Stage 0 manifest validator.

These drive the validator with synthetic manifests and assert on what it
*decides*, not on how it is written. Every fixture is invented; no participant,
camera, recording or measurement exists behind any of it.
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
    ManifestError,
    require_valid_session,
    validate_session,
)
from scripts.b18_stage0.synthetic import make_trial, session_one, session_two  # noqa: E402


def _findings_text(session) -> str:
    return " | ".join(validate_session(session))


# ------------------------------------------------------------------- baseline


def test_the_synthetic_corpus_is_valid():
    """Without this, every negative test below could pass for the wrong reason."""
    assert validate_session(session_one()) == []
    assert validate_session(session_two()) == []


def test_require_valid_session_returns_the_session_unchanged():
    session = session_one()
    assert require_valid_session(session, "S01.json") is session


# ---------------------------------------------------------------- structure


def test_a_non_object_top_level_is_rejected():
    assert validate_session([1, 2, 3])
    assert validate_session("not a session")


@pytest.mark.parametrize(
    "key",
    ["session_id", "participant_id", "date", "operator_role",
     "randomisation_seed", "provenance", "trials"],
)
def test_each_required_session_field_is_required(key):
    session = session_one()
    del session[key]
    assert any(key in f for f in validate_session(session))


@pytest.mark.parametrize("key", ["trial_index", "intended_type", "blink_scores",
                                 "attempt_outcome", "valid", "exclusion_reason"])
def test_each_required_trial_field_is_required(key):
    session = session_one()
    del session["trials"][0][key]
    assert any(key in f for f in validate_session(session))


def test_empty_trials_list_is_rejected():
    session = session_one()
    session["trials"] = []
    assert any("non-empty" in f for f in validate_session(session))


# --------------------------------------------------------------- identifiers


@pytest.mark.parametrize(
    "participant", ["Alex", "P0", "p01", "P01X", "", "P-01", "participant-1"]
)
def test_a_non_pseudonymous_participant_id_is_rejected(participant):
    """A real name must not pass as an identifier."""
    session = session_one()
    session["participant_id"] = participant
    assert any("participant_id" in f for f in validate_session(session))


def test_a_non_pseudonymous_session_id_is_rejected():
    session = session_one()
    session["session_id"] = "Tuesday morning"
    assert any("session_id" in f for f in validate_session(session))


@pytest.mark.parametrize("date", ["01-01-2026", "2026/01/01", "yesterday", ""])
def test_a_malformed_date_is_rejected(date):
    session = session_one()
    session["date"] = date
    assert any("date" in f for f in validate_session(session))


# ------------------------------------------------------- prohibited fields


@pytest.mark.parametrize("key", ["name", "email", "user_id", "dob", "serial",
                                 "photo", "image", "video", "file_path", "signature"])
def test_a_prohibited_field_at_the_top_level_is_rejected(key):
    session = session_one()
    session[key] = "anything"
    assert any("prohibited field" in f and key in f for f in validate_session(session))


def test_a_prohibited_field_nested_inside_a_trial_is_rejected():
    """The scan must reach every depth, not just the top level."""
    session = session_one()
    session["trials"][0]["condition"]["photo"] = "x"
    assert any("prohibited field" in f for f in validate_session(session))


def test_a_prohibited_field_deeply_nested_is_rejected():
    session = session_one()
    session["provenance"]["pinned_dependencies"] = {"ok": "1.0"}
    session["provenance"]["liveness_config"]["email"] = "x"
    assert any("prohibited field" in f for f in validate_session(session))


def test_a_prohibited_key_is_caught_regardless_of_case_or_spacing():
    session = session_one()
    session["trials"][0][" Email "] = "x"
    assert any("prohibited field" in f for f in validate_session(session))


# ------------------------------------------------------------- score arrays


def test_an_empty_score_array_is_rejected():
    session = session_one()
    session["trials"][0]["blink_scores"] = []
    assert any("non-empty" in f for f in validate_session(session))


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_scores_are_rejected(bad):
    session = session_one()
    session["trials"][0]["blink_scores"] = [0.2, bad]
    session["trials"][0]["max_blink_score"] = 0.2
    session["trials"][0]["min_blink_score"] = 0.2
    assert any("non-finite" in f for f in validate_session(session))


@pytest.mark.parametrize("bad", [-0.01, 1.01, 5.0])
def test_out_of_range_scores_are_rejected(bad):
    session = session_one()
    trial = session["trials"][0]
    trial["blink_scores"] = [0.2, bad]
    trial["max_blink_score"] = max(trial["blink_scores"])
    trial["min_blink_score"] = min(trial["blink_scores"])
    assert any("0..1" in f for f in validate_session(session))


def test_a_non_numeric_score_is_rejected():
    session = session_one()
    session["trials"][0]["blink_scores"] = [0.2, "0.5"]
    assert any("non-finite or non-numeric" in f for f in validate_session(session))


def test_a_boolean_is_not_accepted_as_a_score():
    """bool subclasses int; a flag is not a measurement."""
    session = session_one()
    session["trials"][0]["blink_scores"] = [0.2, True]
    assert any("non-finite or non-numeric" in f for f in validate_session(session))


# ------------------------------------------------------- derived quantities


def test_a_mismatched_max_blink_score_is_rejected():
    session = session_one()
    session["trials"][0]["max_blink_score"] = 0.99
    findings = validate_session(session)
    assert any("max_blink_score" in f and "0.99" in f for f in findings)


def test_a_mismatched_min_blink_score_is_rejected():
    session = session_one()
    session["trials"][0]["min_blink_score"] = 0.01
    assert any("min_blink_score" in f for f in validate_session(session))


def test_a_mismatched_face_continuity_is_rejected():
    session = session_one()
    session["trials"][0]["face_continuity"] = 0.1
    assert any("face_continuity" in f for f in validate_session(session))


def test_frames_with_face_cannot_exceed_frames_captured():
    session = session_one()
    trial = session["trials"][0]
    trial["frames_with_face"] = trial["frames_captured"] + 1
    assert any("exceeds frames_captured" in f for f in validate_session(session))


def test_zero_frames_captured_is_rejected_rather_than_dividing_by_zero():
    session = session_one()
    trial = session["trials"][0]
    trial["frames_captured"] = 0
    trial["frames_with_face"] = 0
    findings = validate_session(session)
    assert any("frames_captured" in f for f in findings)


# ------------------------------------------------------------------- enums


@pytest.mark.parametrize("field,bad", [
    ("intended_type", "G9"),
    ("attempt_outcome", "maybe"),
    ("ground_truth", "probably"),
    ("self_report", "shrug"),
    ("exclusion_reason", "because"),
])
def test_invalid_enum_values_are_rejected(field, bad):
    session = session_one()
    trial = session["trials"][0]
    trial[field] = bad
    if field == "exclusion_reason":
        trial["valid"] = False
    assert any(field in f for f in validate_session(session))


@pytest.mark.parametrize("field,bad", [
    ("lighting", "candlelight"), ("head_pose", "upside_down"), ("eyewear", "monocle"),
])
def test_invalid_condition_values_are_rejected(field, bad):
    session = session_one()
    session["trials"][0]["condition"][field] = bad
    assert any(field in f for f in validate_session(session))


@pytest.mark.parametrize("distance", [0, 5, 1000, -70])
def test_out_of_range_distance_is_rejected(distance):
    session = session_one()
    session["trials"][0]["condition"]["distance_cm"] = distance
    assert any("distance_cm" in f for f in validate_session(session))


# ------------------------------------------------- validity / exclusion pair


def test_valid_true_with_an_exclusion_reason_is_contradictory():
    session = session_one()
    trial = session["trials"][0]
    trial["valid"] = True
    trial["exclusion_reason"] = "operator_error"
    assert any("valid is true but exclusion_reason" in f for f in validate_session(session))


def test_valid_false_without_a_reason_is_rejected():
    session = session_one()
    trial = session["trials"][0]
    trial["valid"] = False
    trial["exclusion_reason"] = None
    assert any("must say why" in f for f in validate_session(session))


def test_ground_truth_must_agree_with_the_intended_type():
    session = session_one()
    session["trials"][0]["ground_truth"] = "spoof"
    assert any("contradicts intended_type" in f for f in validate_session(session))


# ------------------------------------------------------------------ retries


def test_a_retry_pointing_at_a_missing_trial_is_rejected():
    session = session_one()
    session["trials"][-1]["retry_of_trial_index"] = 999
    assert any("does not match any trial_index" in f for f in validate_session(session))


def test_a_self_referential_retry_is_rejected():
    session = session_one()
    trial = session["trials"][-1]
    trial["retry_of_trial_index"] = trial["trial_index"]
    assert any("retry of itself" in f for f in validate_session(session))


def test_a_retry_chain_is_rejected_because_one_retry_per_cell_is_the_limit():
    session = session_one()
    session["trials"].append(
        make_trial(8, "G1", [0.22, 0.55], "accepted", retry_of_trial_index=7)
    )
    assert any("itself a retry" in f for f in validate_session(session))


def test_two_retries_of_the_same_trial_are_rejected():
    session = session_one()
    session["trials"].append(
        make_trial(9, "G1", [0.22, 0.55], "accepted", retry_of_trial_index=6)
    )
    assert any("at most one retry per cell" in f for f in validate_session(session))


def test_a_retry_cycle_is_detected():
    """Two trials naming each other must not loop the validator."""
    session = session_one()
    session["trials"][6]["retry_of_trial_index"] = 7
    findings = validate_session(session)
    assert any("cycle" in f or "itself a retry" in f for f in findings)


def test_duplicate_trial_indices_are_rejected():
    session = session_one()
    duplicate = copy.deepcopy(session["trials"][0])
    session["trials"].append(duplicate)
    assert any("duplicate trial_index" in f for f in validate_session(session))


# --------------------------------------------------------------- provenance


@pytest.mark.parametrize("key", ["faceauth_commit", "python_version",
                                 "face_landmarker_sha256", "liveness_config",
                                 "camera_label", "camera_resolution", "os_build",
                                 "pinned_dependencies"])
def test_incomplete_provenance_is_rejected(key):
    session = session_one()
    del session["provenance"][key]
    assert any(key in f for f in validate_session(session))


@pytest.mark.parametrize("key", ["blink_score_high", "blink_score_low",
                                 "enabled_challenges", "min_face_continuity"])
def test_missing_threshold_configuration_is_rejected(key):
    """Thresholds must be explicit; the analysis reads them rather than assuming."""
    session = session_one()
    del session["provenance"]["liveness_config"][key]
    assert any(key in f for f in validate_session(session))


def test_a_low_threshold_above_the_high_threshold_is_rejected():
    session = session_one()
    session["provenance"]["liveness_config"]["blink_score_low"] = 0.9
    assert any("cannot both be satisfied" in f for f in validate_session(session))


@pytest.mark.parametrize("commit", ["not-hex", "abc", "0" * 39, "0" * 41])
def test_a_malformed_commit_sha_is_rejected(commit):
    session = session_one()
    session["provenance"]["faceauth_commit"] = commit
    assert any("faceauth_commit" in f for f in validate_session(session))


def test_a_malformed_model_digest_is_rejected():
    session = session_one()
    session["provenance"]["face_landmarker_sha256"] = "deadbeef"
    assert any("face_landmarker_sha256" in f for f in validate_session(session))


# ------------------------------------------------------- reporting behaviour


def test_all_findings_are_reported_not_just_the_first():
    """A caller fixing one problem at a time is a slow, error-prone loop."""
    session = session_one()
    session["participant_id"] = "Alex"
    session["date"] = "nope"
    session["trials"][0]["intended_type"] = "ZZ"
    assert len(validate_session(session)) >= 3


def test_require_valid_session_raises_with_every_finding():
    session = session_one()
    session["participant_id"] = "Alex"
    with pytest.raises(ManifestError) as excinfo:
        require_valid_session(session, "S01.json")
    assert excinfo.value.findings
    assert all(f.startswith("S01.json:") for f in excinfo.value.findings)


def test_findings_name_the_failing_path():
    session = session_one()
    session["trials"][2]["intended_type"] = "ZZ"
    assert any("trials[2].intended_type" in f for f in validate_session(session))


# --------------------------------------------------------------------- CLI


def _write(tmp_path: Path, name: str, session) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(session), encoding="utf-8")
    return path


def test_cli_validate_accepts_the_synthetic_corpus(tmp_path, capsys):
    paths = [_write(tmp_path, "S01.json", session_one()),
             _write(tmp_path, "S02.json", session_two())]
    assert cli.main(["validate", *[str(p) for p in paths]]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "VALID" in out
    assert "cannot prove that free-text fields are" in out


def test_cli_validate_rejects_an_invalid_manifest_with_exit_one(tmp_path, capsys):
    session = session_one()
    session["participant_id"] = "Alex"
    path = _write(tmp_path, "S01.json", session)
    assert cli.main(["validate", str(path)]) == cli.EXIT_INVALID
    err = capsys.readouterr().err
    assert "INVALID" in err
    assert "participant_id" in err
    assert "No manifest was partially accepted" in err


def test_cli_returns_usage_exit_two_for_a_missing_file(tmp_path, capsys):
    assert cli.main(["validate", str(tmp_path / "absent.json")]) == cli.EXIT_USAGE
    assert "no such file" in capsys.readouterr().err


def test_cli_returns_usage_exit_two_for_malformed_json(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{ this is not json", encoding="utf-8")
    assert cli.main(["validate", str(path)]) == cli.EXIT_USAGE
    assert "not valid JSON" in capsys.readouterr().err


def test_usage_failure_is_distinct_from_validation_failure(tmp_path):
    """Exit 2 means 'could not look'; exit 1 means 'looked, and it is wrong'."""
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    invalid = _write(tmp_path, "invalid.json", {"session_id": "S01"})
    assert cli.main(["validate", str(broken)]) == cli.EXIT_USAGE
    assert cli.main(["validate", str(invalid)]) == cli.EXIT_INVALID


def test_cli_refuses_an_output_path_whose_directory_does_not_exist(tmp_path, capsys):
    path = _write(tmp_path, "S01.json", session_one())
    missing = tmp_path / "no_such_dir" / "out.json"
    assert cli.main(["analyse", str(path), "--out", str(missing)]) == cli.EXIT_USAGE
    assert "does not exist" in capsys.readouterr().err


def test_cli_refuses_a_directory_as_an_output_path(tmp_path, capsys):
    path = _write(tmp_path, "S01.json", session_one())
    assert cli.main(["analyse", str(path), "--out", str(tmp_path)]) == cli.EXIT_USAGE
    assert "is a directory" in capsys.readouterr().err


def test_no_partial_output_is_left_when_validation_fails(tmp_path):
    """A half-written report looks like evidence. There must not be one."""
    session = session_one()
    session["participant_id"] = "Alex"
    path = _write(tmp_path, "S01.json", session)
    out = tmp_path / "results.json"
    report = tmp_path / "report.md"
    assert cli.main(["analyse", str(path), "--out", str(out), "--report", str(report)]) == cli.EXIT_INVALID
    assert not out.exists()
    assert not report.exists()
    assert not list(tmp_path.glob("*.partial"))
