"""Behavioural tests for the B18 Stage 0 aggregate analysis and corpus checks.

Expected values are computed independently in the test - by hand, or from a
closed form - rather than by calling the code under test. Pinning a metric to
its own output would prove only self-consistency.

All fixtures are synthetic. No participant, camera, recording or measurement
exists behind any of it.
"""

from __future__ import annotations

import copy
import json
import math
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.b18_stage0.analyze import (  # noqa: E402
    analyse,
    md_escape,
    render_markdown,
    wilson_interval,
    zero_event_upper_bound,
)
from scripts.b18_stage0.corpus import CorpusError, check_input_paths, check_sessions  # noqa: E402
from scripts.b18_stage0.synthetic import corpus, make_trial, session_one, session_two  # noqa: E402


@pytest.fixture
def result():
    return analyse(corpus())


# ------------------------------------------------------------- the estimators


def test_wilson_interval_matches_an_independent_computation():
    successes, trials, z = 2, 20, 1.959963984540054
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    low, high = wilson_interval(successes, trials)
    assert low == pytest.approx(centre - margin, abs=1e-12)
    assert high == pytest.approx(centre + margin, abs=1e-12)


def test_wilson_interval_stays_inside_zero_to_one():
    for successes, trials in ((0, 3), (3, 3), (1, 200), (199, 200)):
        low, high = wilson_interval(successes, trials)
        assert 0.0 <= low <= high <= 1.0


def test_wilson_interval_is_none_without_a_denominator():
    assert wilson_interval(0, 0) is None


def test_zero_event_upper_bound_matches_the_exact_form():
    for n in (10, 30, 100, 300):
        assert zero_event_upper_bound(n) == pytest.approx(1 - 0.05 ** (1 / n), abs=1e-12)


def test_zero_event_upper_bound_is_near_the_rule_of_three():
    for n in (30, 100, 300):
        assert zero_event_upper_bound(n) == pytest.approx(3 / n, rel=0.05)


# --------------------------------- REGRESSION: cross-session comparability


def test_the_same_session_supplied_twice_is_refused():
    """Previously this doubled every trial while reporting one session."""
    with pytest.raises(CorpusError) as excinfo:
        analyse([session_one(), copy.deepcopy(session_one())])
    assert any("appears 2 times" in f for f in excinfo.value.findings)


def test_duplicate_input_paths_are_refused(tmp_path):
    path = tmp_path / "a.json"
    assert any("given 2 times" in f for f in check_input_paths([path, path]))


def test_conflicting_thresholds_stop_the_analysis():
    """Previously this proceeded on the first threshold with only a note."""
    sessions = corpus()
    sessions[1]["provenance"]["liveness_config"]["blink_score_high"] = 0.5
    with pytest.raises(CorpusError) as excinfo:
        analyse(sessions)
    assert any("disagree on the decision thresholds" in f for f in excinfo.value.findings)


def test_conflicting_liveness_configuration_stops_the_analysis():
    sessions = corpus()
    sessions[1]["provenance"]["liveness_config"]["min_face_continuity"] = 0.9
    with pytest.raises(CorpusError) as excinfo:
        analyse(sessions)
    assert any("liveness configuration" in f for f in excinfo.value.findings)


def test_different_code_commits_stop_the_analysis():
    sessions = corpus()
    sessions[1]["provenance"]["faceauth_commit"] = "a" * 40
    with pytest.raises(CorpusError) as excinfo:
        analyse(sessions)
    assert any("different code commits" in f for f in excinfo.value.findings)


def test_different_model_digests_stop_the_analysis():
    sessions = corpus()
    sessions[1]["provenance"]["face_landmarker_sha256"] = "b" * 64
    with pytest.raises(CorpusError) as excinfo:
        analyse(sessions)
    assert any("model digests" in f for f in excinfo.value.findings)


def test_different_dependency_sets_stop_the_analysis():
    sessions = corpus()
    sessions[1]["provenance"]["pinned_dependencies"] = {"ai-edge-litert": "2.3.0"}
    with pytest.raises(CorpusError) as excinfo:
        analyse(sessions)
    assert any("dependency sets" in f for f in excinfo.value.findings)


def test_differing_cameras_and_participants_are_allowed():
    """The design expects these to vary; only comparability-breakers stop it."""
    assert check_sessions(corpus()) == []


def test_an_empty_corpus_is_refused():
    with pytest.raises(CorpusError):
        analyse([])


# ------------------------------------------------------------------- counts


def test_counts_are_exact(result):
    """Hand-counted: 8 + 7 trials, 2 excluded."""
    counts = result["counts"]
    assert counts["participants"] == 2
    assert counts["participant_ids"] == ["P01", "P02"]
    assert counts["sessions"] == 2
    assert counts["cameras"] == 2
    assert counts["trials_attempted"] == 15
    assert counts["trials_valid"] == 13
    assert counts["trials_excluded"] == 2


def test_attempted_equals_valid_plus_excluded(result):
    counts = result["counts"]
    assert counts["trials_attempted"] == counts["trials_valid"] + counts["trials_excluded"]


def test_exclusions_are_grouped_by_reason(result):
    assert result["exclusions_by_reason"] == {
        "ambiguous_ground_truth": 1,
        "no_face_detected": 1,
    }


def test_excluded_trials_enter_no_numerator_or_denominator():
    baseline = analyse(corpus())
    sessions = corpus()
    sessions[0]["trials"].append(
        make_trial(20, "S1", [], frames_captured=30, frames_with_face=0,
                   valid=False, exclusion_reason="no_face_detected")
    )
    modified = analyse(sessions)
    assert modified["counts"]["trials_attempted"] == baseline["counts"]["trials_attempted"] + 1
    assert modified["counts"]["trials_excluded"] == baseline["counts"]["trials_excluded"] + 1
    assert modified["counts"]["trials_valid"] == baseline["counts"]["trials_valid"]
    assert modified["still_image_margin"] == baseline["still_image_margin"]


# -------------------------------------------------------------------- rates


def test_frr_counts_only_rejected_genuine_blink_trials(result):
    """Valid G* trials: S01 #0,#1,#2,#7 and S02 #0,#1 = 6; exactly #2 rejected."""
    frr = result["aggregate"]["frr_genuine_blink"]
    assert frr["numerator"] == 1
    assert frr["denominator"] == 6
    assert frr["rate"] == pytest.approx(1 / 6, abs=1e-6)


def test_genuine_non_blink_rejections_are_not_counted_as_frr(result):
    correct = result["aggregate"]["correct_rejection_genuine_non_blink"]
    assert correct["numerator"] == 3
    assert correct["denominator"] == 3
    assert result["aggregate"]["frr_genuine_blink"]["denominator"] == 6


def test_far_is_reported_separately_for_every_spoof_type(result):
    by_type = result["aggregate"]["far_by_attack_type"]
    assert set(by_type) == {"S1", "S2", "S3", "S4", "S5"}
    assert by_type["S1"]["numerator"] == 0 and by_type["S1"]["denominator"] == 2
    assert by_type["S2"]["numerator"] == 0 and by_type["S2"]["denominator"] == 1
    assert by_type["S4"]["numerator"] == 1 and by_type["S4"]["denominator"] == 1


# -------------------------------- REGRESSION: no pooled FAR anywhere


def test_no_pooled_far_appears_in_the_aggregate(result):
    """Pooling S1-S3 with S4 manufactures a number describing no real attack."""
    assert result["aggregate"]["far_pooled_across_attack_types"] is None
    assert "S1-S3" in result["aggregate"]["why_no_pooled_far"]


def test_no_pooled_far_appears_per_participant_or_per_camera(result):
    for entry in result["per_participant"] + result["per_camera"]:
        assert "far_all_spoof_types" not in entry
        assert set(entry["far_by_attack_type"]) == {"S1", "S2", "S3", "S4", "S5"}


def test_the_report_contains_no_pooled_far_figure(result):
    report = render_markdown(result)
    assert "No pooled FAR is reported" in report
    assert "all spoof types pooled" not in report


# ----------------------- REGRESSION: S1-S3 margin separated from S4 replay


def test_the_primary_margin_covers_still_images_only(result):
    """S4 replay peaked at 0.66; including it produced a nonsense -0.26 margin."""
    margin = result["still_image_margin"]
    assert margin["observed_max"] == pytest.approx(0.382)
    assert margin["margin_to_high"] == pytest.approx(0.40 - 0.382)
    assert margin["trials"] == 3           # S1 x2 + S2 x1
    assert "S1-S3" in margin["scope"]


def test_video_replay_is_reported_independently(result):
    replay = result["video_replay"]
    assert replay["scope"] == "S4"
    assert replay["trials"] == 1
    assert replay["far"]["numerator"] == 1
    assert replay["max_blink_distribution"]["max"] == pytest.approx(0.66)
    assert "KNOWN UNMITIGATED GAP" in replay["note"]


def test_replay_scores_never_enter_the_still_image_distribution(result):
    still = result["still_image_margin"]["max_blink_distribution"]
    assert still["max"] == pytest.approx(0.382)
    assert still["n"] == 3


# -------------------------- REGRESSION: near miss is BELOW the threshold


def test_a_value_above_the_threshold_is_not_a_near_miss(result):
    """0.66 is 0.26 ABOVE 0.40 and was previously counted as 'within 0.05'."""
    assert result["still_image_margin"]["near_misses_within_0_05_below_high"] == 1
    by_type = {e["type"]: e for e in result["per_attack_type"]}
    assert by_type["S4"]["margin"]["near_misses_within_0_05_below_high"] == 0
    assert by_type["S4"]["margin"]["threshold_crossings_at_or_above_high"] == 1


def test_a_crossing_is_reported_as_a_crossing_not_a_near_miss(result):
    by_type = {e["type"]: e for e in result["per_attack_type"]}
    assert by_type["S1"]["margin"]["threshold_crossings_at_or_above_high"] == 0
    assert by_type["S1"]["margin"]["near_misses_within_0_05_below_high"] == 1


def test_the_near_miss_definition_is_stated_in_the_result(result):
    assert "0 <= high - max" in result["still_image_margin"]["near_miss_definition"]


# ----------------------------------------------- rate context and honesty


def test_every_rate_carries_counts_participants_and_exclusions(result):
    def check(entry):
        for key in ("numerator", "denominator", "participants",
                    "excluded_trials_in_scope", "basis"):
            assert key in entry, key
        assert entry["basis"] == "descriptive, trial-level"
        assert entry["not_a_population_rate"] is True

    check(result["aggregate"]["frr_genuine_blink"])
    check(result["aggregate"]["correct_rejection_genuine_non_blink"])
    for rate in result["aggregate"]["far_by_attack_type"].values():
        check(rate)
    for entry in result["per_participant"]:
        check(entry["frr"])
        for rate in entry["far_by_attack_type"].values():
            check(rate)


def test_zero_event_groups_report_an_upper_bound_rather_than_zero(result):
    s1 = result["aggregate"]["far_by_attack_type"]["S1"]
    assert s1["numerator"] == 0
    assert s1["zero_event_upper_bound_95"] == pytest.approx(1 - 0.05 ** (1 / 2), abs=1e-6)


def test_a_zero_denominator_group_reports_no_rate(result):
    for absent in ("S3", "S5"):
        entry = result["aggregate"]["far_by_attack_type"][absent]
        assert entry["denominator"] == 0
        assert entry["rate"] is None
        assert entry["wilson_95"] is None


def test_per_participant_results_are_present_and_ordered(result):
    assert [e["participant_id"] for e in result["per_participant"]] == ["P01", "P02"]


def test_per_participant_rates_are_computed_within_the_participant(result):
    by_id = {e["participant_id"]: e for e in result["per_participant"]}
    assert by_id["P01"]["frr"]["numerator"] == 1 and by_id["P01"]["frr"]["denominator"] == 4
    assert by_id["P02"]["frr"]["numerator"] == 0 and by_id["P02"]["frr"]["denominator"] == 2


def test_results_are_split_by_camera(result):
    cameras = [e["camera_label"] for e in result["per_camera"]]
    assert cameras == sorted(cameras) and len(cameras) == 2
    assert sum(e["valid_trials"] for e in result["per_camera"]) == result["counts"]["trials_valid"]


# --------------------------------------- boundaries, compared exactly


def test_both_inclusive_boundaries_are_reported_as_exercised(result):
    crossing = result["threshold_crossing"]
    assert crossing["both_boundaries_exercised"] is True
    assert crossing["trials_at_high_boundary"] == 1     # the [0.20, 0.40] trial
    assert crossing["trials_at_low_boundary"] == 2      # that trial and S02 #1
    assert "inclusive" in crossing["comparison"]
    # This assertion was previously `boundary_tolerance > 0`. The tolerance it
    # asserted was the defect: it made the analysis accept values the shipping
    # code rejects. The report now states the opposite, and the near-boundary
    # tolerance that remains is a label only.
    assert crossing["decision_comparison"] == (
        "exact; no tolerance is applied to any decision"
    )
    assert crossing["near_boundary_label_tolerance"] > 0


def test_a_trial_just_inside_the_boundaries_does_not_count_as_reaching_them():
    session = session_one()
    session["trials"] = [make_trial(0, "G1", [0.201, 0.399])]
    crossing = analyse([session])["threshold_crossing"]
    assert crossing["trials_reaching_high"] == 0
    assert crossing["trials_reaching_low"] == 0
    assert crossing["both_boundaries_exercised"] is False


def test_boundary_comparison_survives_a_json_round_trip():
    """An exact == would be brittle after serialisation; a tolerance is used."""
    session = session_one()
    session["trials"] = [make_trial(0, "G1", [0.20, 0.40])]
    round_tripped = json.loads(json.dumps(session))
    crossing = analyse([round_tripped])["threshold_crossing"]
    assert crossing["trials_at_high_boundary"] == 1
    assert crossing["trials_at_low_boundary"] == 1


# ------------------------------------------------------------ distributions


def test_condition_coverage_counts_every_factor(result):
    coverage = result["condition_coverage"]
    assert set(coverage) == {"lighting", "head_pose", "distance_cm", "eyewear", "camera_label"}
    for factor in ("lighting", "head_pose", "distance_cm", "eyewear"):
        assert sum(coverage[factor].values()) == result["counts"]["trials_valid"]


def test_provenance_is_reported_per_session_with_classification(result):
    assert [e["session_id"] for e in result["provenance"]] == ["S01", "S02"]
    for entry in result["provenance"]:
        assert entry["data_classification"] == "synthetic_stage0"
        assert entry["liveness_config"]["blink_score_high"] == 0.40


def test_a_session_of_only_excluded_trials_does_not_divide_by_zero():
    session = session_one()
    session["trials"] = [
        make_trial(0, "G1", [], frames_captured=30, frames_with_face=0,
                   valid=False, exclusion_reason="no_face_detected")
    ]
    outcome = analyse([session])
    assert outcome["counts"]["trials_valid"] == 0
    assert outcome["aggregate"]["frr_genuine_blink"]["rate"] is None
    assert outcome["still_image_margin"]["observed_max"] is None


# ------------------------------------------------------- honesty guarantees


def test_the_result_never_marks_b18_cleared(result):
    assert result["clears_b18"] is False
    assert result["authorizes_capture"] is False
    assert result["b18_status"] == "OPEN"


def test_no_input_can_make_the_analysis_claim_b18_is_cleared():
    sessions = corpus()
    for session in sessions:
        for trial in session["trials"]:
            if trial["intended_type"].startswith("S") and trial["blink_scores"]:
                trial.update(
                    blink_scores=[0.10, 0.12], max_blink_score=0.12, min_blink_score=0.10,
                    attempt_outcome="rejected", outcome_reason="no_transient_blink_detected",
                )
    outcome = analyse(sessions)
    assert outcome["clears_b18"] is False
    serialised = json.dumps(outcome).lower()
    assert "b18 cleared" not in serialised
    assert '"clears_b18": true' not in serialised


def test_the_result_carries_the_stage0_banner_and_clustering_warning(result):
    assert "SYNTHETIC STAGE 0 EVIDENCE ONLY" in result["banner"]
    assert "B18 REMAINS OPEN" in result["banner"]
    assert "cannot authorize Stage 1" in result["banner"]
    assert "UNDERSTATE uncertainty" in result["statistical_basis"]
    assert result["data_classification"] == "synthetic_stage0"


# ------------------------------- REGRESSION: Markdown injection defence


def test_md_escape_escapes_pipes():
    assert md_escape("a|b") == "a\\|b"


def test_md_escape_removes_newlines():
    escaped = md_escape("line1\nline2")
    assert "\n" not in escaped and "\r" not in escaped


def test_md_escape_strips_control_characters():
    assert "\x00" not in md_escape("a\x00b")
    assert "\x1b" not in md_escape("a\x1bb")


def test_the_report_survives_a_pipe_in_a_value_at_render_time(result):
    """Validation rejects pipes; escaping is the second layer if that relaxes."""
    tampered = json.loads(json.dumps(result))
    tampered["provenance"][0]["camera_label"] = "evil | injected"
    assert "evil \\| injected" in render_markdown(tampered)


# ----------------------------------------------------------------- report


def test_the_markdown_report_leads_with_the_banner(result):
    report = render_markdown(result)
    assert any("SYNTHETIC STAGE 0 EVIDENCE ONLY" in line for line in report.splitlines()[:6])
    assert "B18 status: **OPEN**" in report
    assert "Clears B18: **False**" in report


def test_the_markdown_report_puts_participants_before_the_aggregate(result):
    report = render_markdown(result)
    assert report.index("Per-participant results (primary)") < report.index("## Aggregate")


def test_the_aggregate_report_contains_no_participant_level_score_series(result):
    report = render_markdown(result)
    for session in corpus():
        for trial in session["trials"]:
            if trial["blink_scores"]:
                assert str(trial["blink_scores"]) not in report
    assert "blink_scores" not in report


def test_the_report_separates_still_image_from_replay(result):
    report = render_markdown(result)
    assert "Still-image spoof margin (S1-S3)" in report
    assert "Video replay (S4) - reported separately" in report
    assert report.index("Still-image spoof margin") < report.index("Video replay (S4)")


# ------------------------------------------------------------- determinism


def test_analysis_output_is_byte_identical_across_runs():
    first = json.dumps(analyse(corpus()), indent=1, sort_keys=True, ensure_ascii=False)
    second = json.dumps(analyse(corpus()), indent=1, sort_keys=True, ensure_ascii=False)
    assert first == second


def test_the_report_is_byte_identical_across_runs():
    assert render_markdown(analyse(corpus())) == render_markdown(analyse(corpus()))


def test_output_does_not_depend_on_input_session_order():
    forward = analyse([session_one(), session_two()])
    reversed_order = analyse([session_two(), session_one()])
    assert json.dumps(forward, sort_keys=True) == json.dumps(reversed_order, sort_keys=True)


def test_the_result_contains_no_timestamp():
    serialised = json.dumps(analyse(corpus())).lower()
    for token in ("generated", "timestamp", "utcnow"):
        assert token not in serialised
