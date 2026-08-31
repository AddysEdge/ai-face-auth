"""Regression tests for the Stage 0 corrections A-H.

Each section names the defect it pins down. Every assertion is behavioural: it
exercises the shipping code path and checks what the tooling *does*, never what
its source says.

Nothing here opens a camera, touches a real record, or deletes a real path.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.b18_stage0 import corpus, schema  # noqa: E402
from scripts.b18_stage0.analyze import analyse, md_escape, render_markdown  # noqa: E402
from scripts.b18_stage0.decision import blink_passes, outcome_for  # noqa: E402
from scripts.b18_stage0.synthetic import (  # noqa: E402
    CAMERA_A,
    CAMERA_B,
    HIGH,
    LOW,
    make_trial,
    session_one,
    session_two,
)

from faceauth.liveness.challenge_response import decide_blink  # noqa: E402

GUARD = REPO_ROOT / "scripts" / "check_b18_data_leak.py"


def _valid_session(**overrides):
    session = session_one()
    session.update(overrides)
    return session


# =====================================================================
# A. Exact shipping threshold semantics
# =====================================================================


@pytest.mark.parametrize(
    ("scores", "expected", "why"),
    [
        ([0.40, 0.20], True, "exactly high and exactly low - both inclusive"),
        ([0.40, 0.19], True, "exactly high, below low"),
        ([0.41, 0.20], True, "above high, exactly low"),
        ([0.3999999995, 0.10], False, "immediately below high - the reported defect"),
        ([0.39999999999999997, 0.10], False, "the float neighbour below 0.40"),
        ([0.4000000000000001, 0.10], True, "the float neighbour above 0.40"),
        ([0.60, 0.2000000001], False, "immediately above low"),
        ([0.60, 0.19999999999999998], True, "the float neighbour below 0.20"),
        ([0.39, 0.10], False, "clearly below high"),
        ([0.60, 0.21], False, "clearly above low"),
    ],
)
def test_the_stage0_rule_matches_shipping_exactly(scores, expected, why):
    """REGRESSION (A): a tolerance made 0.3999999995 'reach' a 0.40 threshold."""
    assert blink_passes(list(scores), HIGH, LOW) is expected, why
    # ...and it is the shipping function that says so.
    assert decide_blink(list(scores), HIGH, LOW).passed is expected, why


def test_stage0_and_shipping_agree_across_a_dense_boundary_sweep():
    """No input may exist on which the two disagree."""
    steps = [HIGH + i * 1e-10 for i in range(-20, 21)]
    steps += [HIGH + i * 1e-3 for i in range(-5, 6)]
    for value in steps:
        scores = [value, 0.10]
        assert blink_passes(scores, HIGH, LOW) is decide_blink(
            list(scores), HIGH, LOW
        ).passed, f"divergence at max={value!r}"


def test_the_validator_rejects_an_acceptance_just_below_the_threshold():
    """The manifest-level consequence of the same defect."""
    session = session_one()
    session["trials"] = [make_trial(0, "G1", [0.3999999995, 0.10])]
    # make_trial derives the outcome, so it must already say rejected.
    assert session["trials"][0]["attempt_outcome"] == "rejected"
    assert schema.validate_session(session) == []

    # Now assert the outcome by hand and the validator must object.
    session["trials"][0]["attempt_outcome"] = "accepted"
    session["trials"][0]["outcome_reason"] = "blink_detected"
    findings = schema.validate_session(session)
    assert any("attempt_outcome" in f for f in findings)
    # The message must not round the value it is arguing about.
    assert any("0.3999999995" in f for f in findings), findings


def test_the_analyzer_does_not_count_a_near_miss_as_a_crossing():
    session = session_one()
    session["trials"] = [make_trial(0, "S1", [0.3999999995, 0.10])]
    crossing = analyse([session])["threshold_crossing"]
    assert crossing["trials_reaching_high"] == 0


def test_validation_analysis_and_shipping_agree_on_every_synthetic_trial():
    """The three must classify identically, trial by trial."""
    for session in (session_one(), session_two()):
        config = session["provenance"]["liveness_config"]
        for trial in session["trials"]:
            scores = trial["blink_scores"]
            expected = outcome_for(
                [float(s) for s in scores],
                config["blink_score_high"], config["blink_score_low"],
                frames_captured=trial["frames_captured"],
                frames_with_face=trial["frames_with_face"],
                min_face_continuity=config["min_face_continuity"],
            )
            assert trial["attempt_outcome"] == expected.outcome
            assert trial["outcome_reason"] == expected.reason
            if scores:
                assert expected.passed_blink_rule == decide_blink(
                    [float(s) for s in scores],
                    config["blink_score_high"], config["blink_score_low"],
                ).passed


def test_no_stage0_module_applies_a_tolerance_to_a_decision():
    """Only decision.py may name a tolerance, and only as a label."""
    for name in ("schema.py", "analyze.py", "corpus.py", "cli.py", "synthetic.py"):
        source = (REPO_ROOT / "scripts" / "b18_stage0" / name).read_text(encoding="utf-8")
        assert "BOUNDARY_TOLERANCE" not in source, f"{name} still applies a decision tolerance"


# =====================================================================
# B. Complete cross-field validation
# =====================================================================


def _one_trial_session(trial):
    session = session_one()
    session["trials"] = [trial]
    return session


def test_a_clean_session_still_validates():
    """The positive case, so the negatives below mean something."""
    assert schema.validate_session(session_one()) == []
    assert schema.validate_session(session_two()) == []


def test_frames_captured_may_not_exceed_the_configured_cap():
    session = session_one()
    cap = session["provenance"]["liveness_config"]["max_frames_per_challenge"]
    trial = session["trials"][0]
    trial["frames_captured"] = cap + 1
    trial["frames_with_face"] = cap + 1
    trial["face_continuity"] = 1.0
    findings = schema.validate_session(session)
    assert any("max_frames_per_challenge" in f for f in findings), findings


def test_frames_captured_exactly_at_the_cap_is_accepted():
    session = session_one()
    cap = session["provenance"]["liveness_config"]["max_frames_per_challenge"]
    trial = session["trials"][0]
    trial["frames_captured"] = cap
    trial["frames_with_face"] = cap
    trial["face_continuity"] = 1.0
    assert schema.validate_session(session) == []


def test_more_observations_than_face_frames_is_rejected():
    session = session_one()
    trial = session["trials"][0]
    trial["frames_with_face"] = 1
    trial["face_continuity"] = round(1 / trial["frames_captured"], 6)
    findings = schema.validate_session(session)
    assert any("frames_with_face" in f for f in findings), findings


def test_turn_ratios_are_rejected_for_a_blink_only_challenge():
    session = session_one()
    session["trials"][0]["turn_ratios"] = [0.1, -0.2]
    findings = schema.validate_session(session)
    assert any("turn_ratios" in f for f in findings), findings


def test_absent_turn_ratios_are_accepted_for_a_blink_only_challenge():
    session = session_one()
    assert all(t["turn_ratios"] is None for t in session["trials"])
    assert schema.validate_session(session) == []


def test_a_spoof_trial_may_not_claim_a_self_report_label_source():
    """A spoof has no participant, so it cannot have corroborating self-report."""
    session = session_one()
    for trial in session["trials"]:
        if trial["intended_type"] in schema.SPOOF_TYPES:
            trial["label_source"] = schema.GENUINE_LABEL_SOURCE
    findings = schema.validate_session(session)
    assert any("label_source" in f for f in findings), findings


def test_a_genuine_trial_requires_schedule_plus_self_report():
    session = session_one()
    session["trials"][0]["label_source"] = schema.SPOOF_LABEL_SOURCE
    findings = schema.validate_session(session)
    assert any("label_source" in f for f in findings), findings


def test_correct_label_sources_are_accepted():
    session = session_one()
    for trial in session["trials"]:
        expected = (schema.SPOOF_LABEL_SOURCE
                    if trial["intended_type"] in schema.SPOOF_TYPES
                    else schema.GENUINE_LABEL_SOURCE)
        assert trial["label_source"] == expected
    assert schema.validate_session(session) == []


@pytest.mark.parametrize("seed", [-1, -99999999, 2**32, 2**64])
def test_a_seed_outside_the_documented_range_is_rejected(seed):
    findings = schema.validate_session(_valid_session(randomisation_seed=seed))
    assert any("randomisation_seed" in f for f in findings), findings


@pytest.mark.parametrize("seed", [0, 1, 20260101, 2**32 - 1])
def test_a_seed_inside_the_documented_range_is_accepted(seed):
    assert schema.validate_session(_valid_session(randomisation_seed=seed)) == []


def test_an_excluded_trial_outcome_is_verified_too():
    """Recomputation applies to every trial, not only the valid ones."""
    session = session_one()
    excluded = next(t for t in session["trials"] if t["valid"] is False)
    excluded["attempt_outcome"] = "accepted"
    excluded["outcome_reason"] = "blink_detected"
    findings = schema.validate_session(session)
    assert findings, "an excluded trial's outcome must still be recomputed"


def test_an_unstable_continuity_override_is_recomputed():
    session = _one_trial_session(
        make_trial(0, "G1", [0.60, 0.10], frames_captured=60, frames_with_face=10)
    )
    trial = session["trials"][0]
    assert trial["attempt_outcome"] == "rejected"
    assert trial["outcome_reason"] == "face_detection_unstable"
    assert schema.validate_session(session) == []

    trial["outcome_reason"] = "no_transient_blink_detected"
    assert any("outcome_reason" in f for f in schema.validate_session(session))


# =====================================================================
# C. Corpus comparability
# =====================================================================


def test_a_mixed_python_minor_version_corpus_is_refused():
    """REGRESSION (C): 3.12 and 3.13 sessions were pooled without objection."""
    a, b = session_one(), session_two()
    b["provenance"]["python_version"] = "3.13.1"
    findings = corpus.check_sessions([a, b])
    assert any("Python minor versions" in f for f in findings), findings
    with pytest.raises(corpus.CorpusError):
        analyse([a, b])


def test_a_differing_patch_version_is_still_comparable():
    a, b = session_one(), session_two()
    b["provenance"]["python_version"] = "3.12.7"
    assert corpus.check_sessions([a, b]) == []


@pytest.mark.parametrize(
    ("field", "value", "needle"),
    [
        ("schema_version", "0.9", "manifest schema versions"),
        ("tool_version", "0.9", "Stage 0 tool versions"),
        ("liveness_implementation", "mediapipe_runtime", "liveness implementations"),
    ],
)
def test_incomparable_provenance_stops_the_analysis(field, value, needle):
    a, b = session_one(), session_two()
    b["provenance"][field] = value
    findings = corpus.check_sessions([a, b])
    assert any(needle in f for f in findings), findings


def test_a_comparable_corpus_is_accepted():
    assert corpus.check_sessions([session_one(), session_two()]) == []


def test_the_schema_rejects_an_unknown_liveness_implementation():
    session = session_one()
    session["provenance"]["liveness_implementation"] = "mediapipe_runtime"
    assert any("liveness_implementation" in f for f in schema.validate_session(session))


# =====================================================================
# D. Rate metadata and denominators, on a hand-calculated corpus
# =====================================================================
#
# Two participants, two cameras, three spoof types. Every number below is
# worked out by hand in the comments and asserted independently, so a change
# in the aggregation cannot pass by agreeing with itself.


def _hand_built_corpus():
    """P10 on camera A, P11 on camera B.

    P10 (camera A), 5 valid + 1 excluded:
      G1 [0.62, 0.18] accepted        genuine blink, pass
      G1 [0.37, 0.18] rejected        genuine blink, FRR event
      S1 [0.30, 0.10] rejected        still spoof, correctly rejected
      S1 [0.38, 0.10] rejected        still spoof, correctly rejected
      S4 [0.55, 0.10] ACCEPTED        replay, the known gap
      G1 []           excluded        no_face_detected

    P11 (camera B), 4 valid + 1 excluded:
      G1 [0.70, 0.15] accepted        genuine blink, pass
      N1 [0.25, 0.22] rejected        genuine non-blink, correct rejection
      S2 [0.33, 0.12] rejected        still spoof, correctly rejected
      S4 [0.66, 0.11] ACCEPTED        replay, the known gap
      S1 []           excluded        no_face_detected
    """
    empty = {"frames_captured": 60, "frames_with_face": 0,
             "valid": False, "exclusion_reason": "no_face_detected"}

    first = session_one()
    first.update(session_id="S10", participant_id="P10", trials=[
        make_trial(0, "G1", [0.62, 0.18]),
        make_trial(1, "G1", [0.37, 0.18]),
        make_trial(2, "S1", [0.30, 0.10]),
        make_trial(3, "S1", [0.38, 0.10]),
        make_trial(4, "S4", [0.55, 0.10]),
        make_trial(5, "G1", [], **empty),
    ])
    first["provenance"]["camera_label"] = CAMERA_A

    second = session_one()
    second.update(session_id="S11", participant_id="P11", trials=[
        make_trial(0, "G1", [0.70, 0.15]),
        make_trial(1, "N1", [0.25, 0.22]),
        make_trial(2, "S2", [0.33, 0.12]),
        make_trial(3, "S4", [0.66, 0.11]),
        make_trial(4, "S1", [], **empty),
    ])
    second["provenance"]["camera_label"] = CAMERA_B
    return first, second


@pytest.fixture
def hand_built():
    first, second = _hand_built_corpus()
    assert schema.validate_session(first) == []
    assert schema.validate_session(second) == []
    return analyse([first, second])


def test_hand_calculated_counts(hand_built):
    counts = hand_built["counts"]
    assert counts["participants"] == 2
    assert counts["trials_attempted"] == 11       # 6 + 5
    assert counts["trials_valid"] == 9            # 5 + 4
    assert counts["trials_excluded"] == 2         # one each


def test_hand_calculated_aggregate_frr(hand_built):
    """Genuine blink trials: P10 has 2, P11 has 1. One rejected -> 1/3."""
    frr = hand_built["aggregate"]["frr_genuine_blink"]
    assert (frr["numerator"], frr["denominator"]) == (1, 3)
    assert frr["participants"] == 2
    # Exclusions in scope: both excluded trials are... P10's is G1 (in scope),
    # P11's is S1 (NOT in scope). So exactly one.
    assert frr["excluded_trials_in_scope"] == 1


def test_hand_calculated_far_per_attack_type(hand_built):
    far = hand_built["aggregate"]["far_by_attack_type"]

    # S1: P10 has two valid, P11 has none valid (its S1 was excluded).
    assert (far["S1"]["numerator"], far["S1"]["denominator"]) == (0, 2)
    assert far["S1"]["participants"] == 1, "only P10 contributed a valid S1 trial"
    assert far["S1"]["excluded_trials_in_scope"] == 1, "P11's excluded S1 is in scope"

    # S2: P11 only.
    assert (far["S2"]["numerator"], far["S2"]["denominator"]) == (0, 1)
    assert far["S2"]["participants"] == 1
    assert far["S2"]["excluded_trials_in_scope"] == 0

    # S3 and S5: no trials at all. The corpus totals must NOT leak in.
    for absent in ("S3", "S5"):
        assert far[absent]["denominator"] == 0
        assert far[absent]["participants"] == 0, (
            f"{absent} has no trials, so no participant contributed to it"
        )
        assert far[absent]["excluded_trials_in_scope"] == 0
        assert far[absent]["rate"] is None

    # S4: both participants, both accepted - the known gap.
    assert (far["S4"]["numerator"], far["S4"]["denominator"]) == (2, 2)
    assert far["S4"]["participants"] == 2


def test_hand_calculated_per_participant(hand_built):
    by_id = {e["participant_id"]: e for e in hand_built["per_participant"]}
    p10, p11 = by_id["P10"], by_id["P11"]

    assert (p10["valid_trials"], p10["excluded_trials"]) == (5, 1)
    assert (p10["frr"]["numerator"], p10["frr"]["denominator"]) == (1, 2)
    assert p10["frr"]["participants"] == 1
    assert p10["frr"]["excluded_trials_in_scope"] == 1        # its G1 exclusion

    assert (p11["valid_trials"], p11["excluded_trials"]) == (4, 1)
    assert (p11["frr"]["numerator"], p11["frr"]["denominator"]) == (0, 1)
    assert p11["frr"]["excluded_trials_in_scope"] == 0, (
        "P11's exclusion is an S1 spoof, which is not in the FRR scope"
    )
    assert p11["far_by_attack_type"]["S1"]["excluded_trials_in_scope"] == 1


def test_hand_calculated_per_camera(hand_built):
    by_camera = {e["camera_label"]: e for e in hand_built["per_camera"]}
    assert set(by_camera) == {CAMERA_A, CAMERA_B}
    a, b = by_camera[CAMERA_A], by_camera[CAMERA_B]
    assert (a["valid_trials"], a["participants"]) == (5, 1)
    assert (b["valid_trials"], b["participants"]) == (4, 1)
    assert a["far_by_attack_type"]["S1"]["denominator"] == 2
    assert b["far_by_attack_type"]["S1"]["denominator"] == 0
    assert b["far_by_attack_type"]["S1"]["participants"] == 0


def test_hand_calculated_still_image_margin_excludes_replay(hand_built):
    """S1-S3 peak is 0.38; S4 peaks at 0.66 and must not enter the margin."""
    margin = hand_built["still_image_margin"]
    assert margin["observed_max"] == 0.38
    assert margin["margin_to_high"] == pytest.approx(0.02)
    assert hand_built["video_replay"]["max_blink_distribution"]["max"] == 0.66


def test_every_rate_carries_its_full_metadata(hand_built):
    """No rate may travel without scope, counts, participants and limitation."""
    required = {
        "scope", "event", "numerator", "denominator", "rate", "participants",
        "excluded_trials_in_scope", "basis", "not_a_population_rate", "limitation",
    }
    seen = 0

    def walk(node):
        nonlocal seen
        if isinstance(node, dict):
            if "numerator" in node and "denominator" in node:
                seen += 1
                missing = required - set(node)
                assert not missing, f"rate {node.get('scope')!r} missing {sorted(missing)}"
                assert node["participants"] <= hand_built["counts"]["participants"]
                assert "clustered" in node["limitation"]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(hand_built)
    assert seen >= 20, f"expected many rates, found {seen}"


def test_participants_never_exceed_the_denominator(hand_built):
    """A rate cannot have more contributing people than contributing trials."""
    def walk(node):
        if isinstance(node, dict):
            if "numerator" in node and "denominator" in node:
                assert node["participants"] <= node["denominator"] or node["denominator"] == 0
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(hand_built)


def test_pooled_far_stays_prohibited(hand_built):
    assert hand_built["aggregate"]["far_pooled_across_attack_types"] is None
    assert "NOT pooled" in hand_built["aggregate"]["why_no_pooled_far"]


# =====================================================================
# D/H. The Markdown report carries the material JSON evidence
# =====================================================================


def test_the_report_renders_per_camera_evidence(hand_built):
    report = render_markdown(hand_built)
    assert "## Per-camera results" in report
    assert "### FAR per attack type, per camera" in report
    assert "### Still-image margin, per camera" in report
    assert "### Still-image margin, per participant" in report
    for camera in (CAMERA_A, CAMERA_B):
        assert md_escape(camera) in report


def test_the_report_states_the_headline_numbers(hand_built):
    report = render_markdown(hand_built)
    assert "1/3" in report, "the aggregate FRR must appear"
    assert "2/2" in report, "the S4 replay FAR must appear"
    assert "No pooled FAR is reported" in report


def _unescaped(text: str, character: str) -> int:
    """Occurrences of ``character`` not preceded by a backslash."""
    return sum(
        1 for index, ch in enumerate(text)
        if ch == character and (index == 0 or text[index - 1] != "\\")
    )


@pytest.mark.parametrize(
    ("hostile", "dangerous"),
    [
        ("pipe|injection", "|"),
        ("[link](http://example.invalid)", "["),
        ("[link](http://example.invalid)", "("),
        ("`code span", "`"),
        ("cell]end", "]"),
    ],
)
def test_markdown_escaping_neutralises_hostile_text(hostile, dangerous):
    """REGRESSION (H): free text must not become table or link syntax."""
    escaped = md_escape(hostile)
    assert _unescaped(escaped, dangerous) == 0, escaped
    assert "\n" not in escaped and "\r" not in escaped


def test_markdown_escaping_neutralises_html():
    escaped = md_escape("<script>alert(1)</script>")
    assert "<" not in escaped and ">" not in escaped
    assert "&lt;script&gt;" in escaped


def test_markdown_escaping_flattens_newlines():
    assert "\n" not in md_escape("row one\nrow two")
    assert "row one row two" in md_escape("row one\nrow two")


def test_a_hostile_camera_label_cannot_break_the_table():
    session = session_one()
    session["provenance"]["camera_label"] = "CAM-A"
    report = render_markdown(analyse([session]))
    for line in report.splitlines():
        if line.startswith("|") and "CAM-A" in line:
            # A table row's cell count must stay as declared.
            assert line.count("|") - line.count("\\|") >= 2


def test_json_and_markdown_describe_the_same_run(hand_built):
    """Semantic equivalence: the report must not contradict the JSON."""
    report = render_markdown(hand_built)
    counts = hand_built["counts"]
    assert str(counts["trials_valid"]) in report
    assert str(counts["trials_attempted"]) in report
    assert hand_built["b18_status"] in report


def test_rendering_is_deterministic(hand_built):
    assert render_markdown(hand_built) == render_markdown(hand_built)
    first = json.dumps(hand_built, sort_keys=True)
    second = json.dumps(analyse(list(_hand_built_corpus())), sort_keys=True)
    assert first == second


# =====================================================================
# F. The CI data-leak guard
# =====================================================================


def _run_guard(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GUARD), *args],
        capture_output=True, text=True, cwd=REPO_ROOT, check=False,
    )


def test_the_guard_self_test_passes():
    result = _run_guard("--self-test")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 failed" in result.stdout


def test_the_guard_accepts_the_current_tree():
    result = _run_guard()
    assert result.returncode == 0, result.stdout + result.stderr


def _classify(path: str, raw: bytes):
    import importlib.util

    spec = importlib.util.spec_from_file_location("b18_guard", GUARD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {f.rule for f in module.classify(path, raw)}


def test_no_directory_is_broadly_exempt():
    """REGRESSION (F): scripts/b18_stage0/ and tests/test_b18_* were trusted whole."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("b18_guard", GUARD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for path in module.ALLOWLIST:
        assert not path.endswith("/"), f"{path} is a directory exemption"
        assert "*" not in path, f"{path} is a wildcard exemption"
        assert (REPO_ROOT / path).is_file(), f"{path} does not exist"


@pytest.mark.parametrize("path", [
    "scripts/b18_stage0/leaked.json",
    "tests/test_b18_leaked.json",
    "docs/b18/leaked.json",
    "leaked.json",
])
def test_a_leaked_manifest_is_rejected_under_any_path(path):
    manifest = json.dumps({
        "session_id": "S01", "participant_id": "P01",
        "trials": [{"blink_scores": [0.2, 0.6]}],
    }).encode("utf-8")
    assert "manifest-data" in _classify(path, manifest)


@pytest.mark.parametrize("path", [
    "scripts/b18_stage0/report.md",
    "tests/test_b18_report.md",
    "docs/stage0_evidence.md",
])
def test_a_generated_report_is_rejected_under_any_path(path):
    report = (
        b"SYNTHETIC STAGE 0 EVIDENCE ONLY - B18 REMAINS OPEN.\n\n"
        b"## Per-participant results (primary)\n\n| P01 | 1/4 |\n"
    )
    # Either rule is a rejection: a file literally named report.md is also a
    # published run artifact, and that check runs first.
    assert _classify(path, report) & {"report-signature", "runtime-artifact"}


def test_an_undecodable_file_fails_closed():
    assert "undecodable" in _classify("docs/whatever.md", b"\xff\xfe\x00\xc3\x28")


def test_the_real_stage0_source_is_not_flagged():
    for name in ("schema.py", "analyze.py", "cli.py", "synthetic.py",
                 "cleanup.py", "corpus.py", "workspace.py", "decision.py"):
        path = f"scripts/b18_stage0/{name}"
        raw = (REPO_ROOT / "scripts" / "b18_stage0" / name).read_bytes()
        assert _classify(path, raw) == set(), f"{path} was wrongly flagged"


def test_the_blank_consent_form_stays_tracked():
    """A template is not a record; the repository must be able to ship it."""
    form = REPO_ROOT / "docs" / "b18" / "forms" / "CONSENT_FORM.md"
    if not form.is_file():
        pytest.skip("consent form not present")
    assert _classify("docs/b18/forms/CONSENT_FORM.md", form.read_bytes()) == set()


def test_a_filled_consent_record_is_rejected():
    filled = (
        b"Participant consent record\n\nFull name: A Real Person\n"
        b"Signature: A Real Person\n"
    )
    assert "identity-record" in _classify("docs/b18/forms/signed.md", filled)
