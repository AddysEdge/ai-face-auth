"""Behavioural tests for the B18 Stage 0 aggregate analysis.

Expected values are computed independently in the test - by hand, or with a
separate implementation - rather than by calling the code under test. Pinning a
metric to its own output would only prove it is consistent, not correct.

All fixtures are synthetic. No participant, camera, recording or measurement
exists behind any of it.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.b18_stage0 import cli  # noqa: E402
from scripts.b18_stage0.analyze import (  # noqa: E402
    analyse,
    render_markdown,
    wilson_interval,
    zero_event_upper_bound,
)
from scripts.b18_stage0.synthetic import corpus, make_trial, session_one, session_two  # noqa: E402


@pytest.fixture
def result():
    return analyse(corpus())


# ------------------------------------------------------------- the estimators


def test_wilson_interval_matches_an_independent_computation():
    """Recomputed from the closed form, not from the implementation."""
    successes, trials, z = 2, 20, 1.959963984540054
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator

    low, high = wilson_interval(successes, trials)
    assert low == pytest.approx(centre - margin, abs=1e-12)
    assert high == pytest.approx(centre + margin, abs=1e-12)


def test_wilson_interval_stays_inside_zero_to_one():
    """The reason for preferring Wilson over the normal approximation."""
    for successes, trials in ((0, 3), (3, 3), (1, 200), (199, 200)):
        low, high = wilson_interval(successes, trials)
        assert 0.0 <= low <= high <= 1.0


def test_wilson_interval_is_none_without_a_denominator():
    assert wilson_interval(0, 0) is None


def test_zero_event_upper_bound_matches_the_exact_form():
    for n in (10, 30, 100, 300):
        assert zero_event_upper_bound(n) == pytest.approx(1 - 0.05 ** (1 / n), abs=1e-12)


def test_zero_event_upper_bound_is_near_the_rule_of_three():
    """Sanity: the exact bound should sit close to 3/n, not wildly off."""
    for n in (30, 100, 300):
        assert zero_event_upper_bound(n) == pytest.approx(3 / n, rel=0.05)


def test_zero_event_upper_bound_is_none_without_a_denominator():
    assert zero_event_upper_bound(0) is None


# ------------------------------------------------------------------- counts


def test_counts_are_exact(result):
    """Hand-counted from the synthetic corpus: 8 + 7 trials, 2 excluded."""
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
    """Add an excluded trial that would change every rate if it counted."""
    baseline = analyse(corpus())
    sessions = corpus()
    sessions[0]["trials"].append(
        make_trial(
            20, "S1", [0.9, 0.1], "accepted",
            valid=False, exclusion_reason="software_error",
        )
    )
    modified = analyse(sessions)

    assert modified["counts"]["trials_attempted"] == baseline["counts"]["trials_attempted"] + 1
    assert modified["counts"]["trials_excluded"] == baseline["counts"]["trials_excluded"] + 1
    assert modified["counts"]["trials_valid"] == baseline["counts"]["trials_valid"]
    # An accepted spoof at 0.9 would be conspicuous if it leaked into the rates.
    assert modified["aggregate"]["far_all_spoof_types_pooled"] == \
        baseline["aggregate"]["far_all_spoof_types_pooled"]
    assert modified["spoof_margin"] == baseline["spoof_margin"]


# -------------------------------------------------------------------- rates


def test_frr_counts_only_rejected_genuine_blink_trials(result):
    """By hand: valid G* trials are S01 #0,#1,#2,#7 and S02 #0,#1 = 6.
    Exactly one (#2) was rejected."""
    frr = result["aggregate"]["frr_genuine_blink"]
    assert frr["numerator"] == 1
    assert frr["denominator"] == 6
    assert frr["rate"] == pytest.approx(1 / 6, abs=1e-6)


def test_genuine_non_blink_rejections_are_not_counted_as_frr(result):
    """Rejecting someone who did not blink is the control working."""
    correct = result["aggregate"]["correct_rejection_genuine_non_blink"]
    assert correct["numerator"] == 3   # N1, N2, N3 all rejected
    assert correct["denominator"] == 3
    assert result["aggregate"]["frr_genuine_blink"]["denominator"] == 6


def test_far_is_reported_separately_for_every_spoof_type(result):
    by_type = {entry["type"]: entry for entry in result["per_attack_type"]}
    assert set(by_type) == {"S1", "S2", "S3", "S4", "S5"}

    assert by_type["S1"]["far"]["numerator"] == 0
    assert by_type["S1"]["far"]["denominator"] == 2
    assert by_type["S2"]["far"]["numerator"] == 0
    assert by_type["S2"]["far"]["denominator"] == 1
    # S4 replay is the known gap and is accepted in the synthetic corpus.
    assert by_type["S4"]["far"]["numerator"] == 1
    assert by_type["S4"]["far"]["denominator"] == 1
    assert by_type["S4"]["far"]["rate"] == 1.0


def test_a_spoof_type_with_no_trials_reports_a_zero_denominator_not_a_rate(result):
    by_type = {entry["type"]: entry for entry in result["per_attack_type"]}
    for absent in ("S3", "S5"):
        assert by_type[absent]["far"]["denominator"] == 0
        assert by_type[absent]["far"]["rate"] is None
        assert by_type[absent]["far"]["wilson_95"] is None
        assert by_type[absent]["max_blink"]["n"] == 0


def test_every_rate_carries_its_numerator_and_denominator(result):
    def check(entry):
        assert "numerator" in entry and "denominator" in entry
        assert entry["basis"] == "descriptive, trial-level"

    check(result["aggregate"]["frr_genuine_blink"])
    check(result["aggregate"]["far_all_spoof_types_pooled"])
    check(result["aggregate"]["correct_rejection_genuine_non_blink"])
    for entry in result["per_participant"]:
        check(entry["frr"])
        check(entry["far_all_spoof_types"])
    for entry in result["per_attack_type"]:
        check(entry["far"])


def test_zero_event_groups_report_an_upper_bound_rather_than_zero(result):
    by_type = {entry["type"]: entry for entry in result["per_attack_type"]}
    s1 = by_type["S1"]["far"]
    assert s1["numerator"] == 0
    assert s1["zero_event_upper_bound_95"] == pytest.approx(1 - 0.05 ** (1 / 2), abs=1e-6)


def test_a_group_with_events_has_no_zero_event_bound(result):
    by_type = {entry["type"]: entry for entry in result["per_attack_type"]}
    assert by_type["S4"]["far"]["zero_event_upper_bound_95"] is None


# --------------------------------------------------- per-participant primacy


def test_per_participant_results_are_present_and_ordered(result):
    ids = [entry["participant_id"] for entry in result["per_participant"]]
    assert ids == ["P01", "P02"]


def test_per_participant_rates_are_computed_within_the_participant(result):
    by_id = {e["participant_id"]: e for e in result["per_participant"]}
    # P01: 4 valid G* trials, exactly one rejected (#2).
    assert by_id["P01"]["frr"]["numerator"] == 1
    assert by_id["P01"]["frr"]["denominator"] == 4
    # P02: 2 valid G* trials, none rejected.
    assert by_id["P02"]["frr"]["numerator"] == 0
    assert by_id["P02"]["frr"]["denominator"] == 2


def test_results_are_split_by_camera(result):
    cameras = [entry["camera_label"] for entry in result["per_camera"]]
    assert cameras == sorted(cameras)
    assert len(cameras) == 2
    by_camera = {e["camera_label"]: e for e in result["per_camera"]}
    assert sum(e["valid_trials"] for e in by_camera.values()) == result["counts"]["trials_valid"]


# ------------------------------------------------------------ spoof margin


def test_spoof_margin_uses_the_observed_maximum(result):
    """Synthetic spoof maxima: 0.382, 0.24, 0.33, 0.66 -> max 0.66."""
    margin = result["spoof_margin"]
    assert margin["high_threshold"] == 0.40
    assert margin["observed_max_over_all_spoofs"] == pytest.approx(0.66)
    assert margin["margin_to_high"] == pytest.approx(0.40 - 0.66)


def test_spoof_trials_within_five_hundredths_of_the_threshold_are_counted(result):
    """0.382 and 0.66 are both >= 0.35; 0.24 and 0.33 are not."""
    assert result["spoof_margin"]["within_0_05_of_high"] == 2


def test_per_attack_margin_is_computed_against_that_attack_only(result):
    by_type = {entry["type"]: entry for entry in result["per_attack_type"]}
    assert by_type["S1"]["margin_to_high"] == pytest.approx(0.40 - 0.382)
    assert by_type["S1"]["within_0_05_of_high"] == 1


# -------------------------------------------------- threshold crossing edges


def test_both_inclusive_boundaries_are_reported_as_exercised(result):
    crossing = result["threshold_crossing"]
    assert crossing["both_boundaries_exercised"] is True
    # Exactly at 0.40: only S01 trial 1, [0.20, 0.40].
    assert crossing["trials_exactly_at_high"] == 1
    # Exactly at 0.20: S01 trial 1 [0.20, 0.40] and S02 trial 1 [0.28, 0.20, 0.49].
    assert crossing["trials_exactly_at_low"] == 2
    assert "inclusive" in crossing["comparison"]


def test_a_trial_exactly_on_both_boundaries_counts_as_reaching_them():
    """0.40 and 0.20 exactly must count: the shipping comparison is >= and <=."""
    session = session_one()
    session["trials"] = [make_trial(0, "G1", [0.20, 0.40], "accepted")]
    crossing = analyse([session])["threshold_crossing"]
    assert crossing["trials_reaching_high"] == 1
    assert crossing["trials_reaching_low"] == 1
    assert crossing["trials_exactly_at_high"] == 1
    assert crossing["trials_exactly_at_low"] == 1


def test_a_trial_just_inside_the_boundaries_does_not_count_as_reaching_them():
    session = session_one()
    session["trials"] = [make_trial(0, "G1", [0.201, 0.399], "rejected")]
    crossing = analyse([session])["threshold_crossing"]
    assert crossing["trials_reaching_high"] == 0
    assert crossing["trials_reaching_low"] == 0
    assert crossing["both_boundaries_exercised"] is False


# ------------------------------------------------------- distributions etc.


def test_distributions_report_count_min_median_max(result):
    spoof = result["distributions"]["spoof_max"]
    assert spoof["n"] == 4
    assert spoof["min"] == pytest.approx(0.24)
    assert spoof["max"] == pytest.approx(0.66)
    # median of [0.24, 0.33, 0.382, 0.66] = (0.33 + 0.382) / 2
    assert spoof["median"] == pytest.approx((0.33 + 0.382) / 2, abs=1e-6)


def test_condition_coverage_counts_every_factor(result):
    coverage = result["condition_coverage"]
    assert set(coverage) == {"lighting", "head_pose", "distance_cm", "eyewear", "camera_label"}
    for factor in ("lighting", "head_pose", "distance_cm", "eyewear"):
        assert sum(coverage[factor].values()) == result["counts"]["trials_valid"]


def test_provenance_is_reported_per_session(result):
    sessions = [entry["session_id"] for entry in result["provenance"]]
    assert sessions == ["S01", "S02"]
    for entry in result["provenance"]:
        assert entry["liveness_config"]["blink_score_high"] == 0.40
        assert entry["randomisation_seed"]


def test_disagreeing_thresholds_produce_a_prominent_note():
    sessions = corpus()
    sessions[1]["provenance"]["liveness_config"]["blink_score_high"] = 0.5
    note = analyse(sessions)["notes"]
    assert note and any("disagree on thresholds" in n for n in note)


def test_empty_input_is_refused_rather_than_producing_empty_rates():
    with pytest.raises(ValueError, match="no sessions"):
        analyse([])


def test_a_session_with_only_excluded_trials_does_not_divide_by_zero():
    session = session_one()
    session["trials"] = [
        make_trial(0, "G1", [0.2, 0.3], "rejected",
                   valid=False, exclusion_reason="operator_error")
    ]
    outcome = analyse([session])
    assert outcome["counts"]["trials_valid"] == 0
    assert outcome["aggregate"]["frr_genuine_blink"]["rate"] is None
    assert outcome["spoof_margin"]["observed_max_over_all_spoofs"] is None


# ------------------------------------------------------- honesty guarantees


def test_the_result_never_marks_b18_cleared(result):
    assert result["clears_b18"] is False
    assert result["authorizes_capture"] is False
    assert result["b18_status"] == "OPEN"


def test_no_input_can_make_the_analysis_claim_b18_is_cleared():
    """Even a perfect synthetic run must not produce a clearance."""
    sessions = corpus()
    for session in sessions:
        for trial in session["trials"]:
            trial["valid"] = True
            trial["exclusion_reason"] = None
            if trial["intended_type"].startswith("S"):
                trial["attempt_outcome"] = "rejected"
            elif trial["intended_type"].startswith("G"):
                trial["attempt_outcome"] = "accepted"
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
    assert "not population bounds" in result["statistical_basis"]


def test_the_pooled_far_carries_its_caveat_in_the_same_object(result):
    assert "S4" in result["aggregate"]["pooling_caveat"]


# ----------------------------------------------------------------- report


def test_the_markdown_report_leads_with_the_banner(result):
    report = render_markdown(result)
    head = report.splitlines()[:6]
    assert any("SYNTHETIC STAGE 0 EVIDENCE ONLY" in line for line in head)
    assert "B18 status: **OPEN**" in report
    assert "Clears B18: **False**" in report


def test_the_markdown_report_repeats_the_banner_at_the_end(result):
    report = render_markdown(result)
    assert "SYNTHETIC STAGE 0 EVIDENCE ONLY" in report.splitlines()[-6:][0] or         any("SYNTHETIC STAGE 0 EVIDENCE ONLY" in line for line in report.splitlines()[-8:])


def test_the_markdown_report_puts_participants_before_the_aggregate(result):
    report = render_markdown(result)
    assert report.index("Per-participant results (primary)") < report.index("## Aggregate")


def test_the_aggregate_report_contains_no_participant_level_score_series(result):
    """Plan §11.3: only aggregate, non-identifying results may be published."""
    report = render_markdown(result)
    for session in corpus():
        for trial in session["trials"]:
            series = ", ".join(str(s) for s in trial["blink_scores"])
            assert series not in report
            assert str(trial["blink_scores"]) not in report
    assert "blink_scores" not in report
    assert "outcome_reason" not in report


def test_the_report_states_the_participant_count_is_the_sample_size(result):
    assert "not the trial count, is the sample size" in render_markdown(result)


def test_the_report_never_prints_a_bare_zero_percent_for_a_zero_event_group(result):
    report = render_markdown(result)
    assert "one-sided 95% upper bound" in report


def test_a_zero_denominator_group_renders_as_not_applicable(result):
    assert "n/a (0 trials)" in render_markdown(result)


# ------------------------------------------------------------- determinism


def test_analysis_output_is_byte_identical_across_runs():
    """Plan §13 requires the analysis be reproducible from the manifest."""
    first = json.dumps(analyse(corpus()), indent=1, sort_keys=True, ensure_ascii=False)
    second = json.dumps(analyse(corpus()), indent=1, sort_keys=True, ensure_ascii=False)
    assert first == second


def test_the_report_is_byte_identical_across_runs():
    assert render_markdown(analyse(corpus())) == render_markdown(analyse(corpus()))


def test_output_does_not_depend_on_input_session_order():
    """Sorted iteration, so a caller's argument order cannot change the numbers."""
    forward = analyse([session_one(), session_two()])
    reversed_order = analyse([session_two(), session_one()])
    assert json.dumps(forward, sort_keys=True) == json.dumps(reversed_order, sort_keys=True)


def test_the_result_contains_no_timestamp():
    """A timestamp would silently break byte-identical reproduction."""
    serialised = json.dumps(analyse(corpus())).lower()
    for token in ("generated", "timestamp", "\"date\":", "utcnow", "2026-"):
        assert token not in serialised


def test_cli_writes_byte_identical_files_on_repeated_runs(tmp_path):
    manifests = []
    for name, session in (("S01.json", session_one()), ("S02.json", session_two())):
        path = tmp_path / name
        path.write_text(json.dumps(session), encoding="utf-8")
        manifests.append(str(path))

    outputs = []
    for run in ("a", "b"):
        out = tmp_path / f"results_{run}.json"
        report = tmp_path / f"report_{run}.md"
        assert cli.main(["analyse", *manifests, "--out", str(out), "--report", str(report)]) == 0
        outputs.append((out.read_bytes(), report.read_bytes()))

    assert outputs[0][0] == outputs[1][0], "results JSON differed between runs"
    assert outputs[0][1] == outputs[1][1], "Markdown report differed between runs"


def test_cli_analyse_prints_the_report_when_no_output_path_is_given(tmp_path, capsys):
    path = tmp_path / "S01.json"
    path.write_text(json.dumps(session_one()), encoding="utf-8")
    assert cli.main(["analyse", str(path)]) == 0
    assert "SYNTHETIC STAGE 0 EVIDENCE ONLY" in capsys.readouterr().out


def test_cli_leaves_no_partial_file_behind_on_success(tmp_path):
    path = tmp_path / "S01.json"
    path.write_text(json.dumps(session_one()), encoding="utf-8")
    out = tmp_path / "results.json"
    assert cli.main(["analyse", str(path), "--out", str(out)]) == 0
    assert out.exists()
    assert not list(tmp_path.glob("*.partial"))


# --------------------------------------------------------------- no network


def test_stage0_tooling_opens_no_socket(tmp_path, monkeypatch):
    """B17 made the runtime network-silent; Stage 0 tooling must be too.

    Rather than trusting inspection, every socket constructor and connect is
    replaced with something that raises, and the whole pipeline is then run.
    """
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("Stage 0 tooling attempted network access")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)

    manifest = tmp_path / "S01.json"
    manifest.write_text(json.dumps(session_one()), encoding="utf-8")
    out = tmp_path / "results.json"
    report = tmp_path / "report.md"

    assert cli.main(["validate", str(manifest)]) == 0
    assert cli.main(["analyse", str(manifest), "--out", str(out), "--report", str(report)]) == 0
    assert out.exists() and report.exists()

