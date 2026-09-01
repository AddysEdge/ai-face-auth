"""Strict validation of B18 Stage 0 session manifests.

The normative schema is ``docs/b18/forms/TRIAL_MANIFEST_SCHEMA.md``; this module
enforces it, and enforces it *strictly*.

Two stances worth stating up front, because an earlier revision of this file got
both wrong:

**Whitelist, not blacklist.** Every object has an exact allowed key set and an
unknown key is a hard failure. A blacklist of identifying field names is a
guess about what a leak will be called - ``ssn`` and
``participant_contact_info`` both sailed past the previous blacklist. A
whitelist cannot be out-guessed.

**Synthetic-only.** A manifest must declare
``"data_classification": "synthetic_stage0"``. Anything else is refused. Stage 0
tooling must not be able to consume a real participant manifest and emit a
report calling the data synthetic. Handling Stage 1 or Stage 2 manifests
requires a separate, owner-authorized, reviewed change - not a flag on this one.

Nothing here reads a camera or a network. It validates a JSON document.
"""

from __future__ import annotations

import datetime as _datetime
import math
import re
from typing import Any

from scripts.b18_stage0.decision import outcome_for

# --------------------------------------------------------------- vocabularies

GENUINE_BLINK_TYPES = ("G1", "G2", "G3")
GENUINE_NON_BLINK_TYPES = ("N1", "N2", "N3")
STILL_SPOOF_TYPES = ("S1", "S2", "S3")   # printed photo / still display
REPLAY_SPOOF_TYPES = ("S4",)             # video replay - the known gap
OTHER_SPOOF_TYPES = ("S5",)
SPOOF_TYPES = STILL_SPOOF_TYPES + REPLAY_SPOOF_TYPES + OTHER_SPOOF_TYPES
TRIAL_TYPES = GENUINE_BLINK_TYPES + GENUINE_NON_BLINK_TYPES + SPOOF_TYPES

LIGHTING = ("bright_even", "dim", "side_light", "backlit")
HEAD_POSE = ("frontal", "yaw_left_15", "yaw_right_15", "pitch_up_10", "pitch_down_10")
EYEWEAR = ("none", "clear_glasses", "tinted")

ATTEMPT_OUTCOMES = ("accepted", "rejected")
GROUND_TRUTHS = ("blink", "no_blink", "spoof")
SELF_REPORTS = ("blinked", "did_not_blink", "unsure", "n/a")
LABEL_SOURCES = ("schedule+self_report", "schedule_only")

# A genuine trial's label rests on what the participant was asked to do *and*
# what they reported doing; a spoof trial has no participant to self-report, so
# its label rests on the schedule alone. Using "schedule+self_report" on a spoof
# claims corroborating evidence that cannot exist.
GENUINE_LABEL_SOURCE = "schedule+self_report"
SPOOF_LABEL_SOURCE = "schedule_only"

#: The liveness implementations whose scores this schema describes.
LIVENESS_IMPLEMENTATIONS = ("litert_landmarker",)

EXCLUSION_REASONS = (
    "no_face_detected",
    "missed_prompt",
    "operator_error",
    "software_error",
    "ambiguous_ground_truth",
)

# Only these excluded reasons may honestly carry zero observations. A trial the
# detector never saw a face in has nothing to record; fabricating a score series
# to satisfy a validator would be inventing data.
EMPTY_OBSERVATION_REASONS = ("no_face_detected", "software_error")

# The four reasons the shipping BLINK path can produce - see
# challenge_response.decide_blink, finalize, and capture_utils.
OUTCOME_REASONS = (
    "blink_detected",
    "no_transient_blink_detected",
    "no_face_observed_during_challenge",
    "face_detection_unstable",
)

# The classification this tool - and only this tool - will process.
REQUIRED_DATA_CLASSIFICATION = "synthetic_stage0"

# capture_utils.run_liveness_challenge's default. The continuity override only
# applies once at least this many frames were captured.
MIN_FRAMES_FOR_CONTINUITY_CHECK = 5

# ------------------------------------------------------------- exact key sets

SESSION_KEYS = frozenset({
    "session_id", "participant_id", "date", "operator_role", "randomisation_seed",
    "data_classification", "provenance", "trials",
})
PROVENANCE_KEYS = frozenset({
    "faceauth_commit", "python_version", "pinned_dependencies",
    "face_landmarker_sha256", "liveness_config", "camera_label",
    "camera_resolution", "os_build", "liveness_implementation",
    "schema_version", "tool_version",
})
CONFIG_KEYS = frozenset({
    "blink_score_high", "blink_score_low", "enabled_challenges",
    "challenge_timeout_seconds", "max_frames_per_challenge", "min_face_continuity",
})
TRIAL_KEYS = frozenset({
    "trial_index", "intended_type", "condition", "blink_scores", "turn_ratios",
    "max_blink_score", "min_blink_score", "frames_captured", "frames_with_face",
    "face_continuity", "attempt_outcome", "outcome_reason", "ground_truth",
    "self_report", "label_source", "valid", "exclusion_reason",
    "retry_of_trial_index", "notes",
})
CONDITION_KEYS = frozenset({"lighting", "head_pose", "distance_cm", "eyewear"})

# ------------------------------------------------------------------- patterns

PARTICIPANT_ID_RE = re.compile(r"^P\d{2,4}$")
SESSION_ID_RE = re.compile(r"^S\d{2,4}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PYTHON_VERSION_RE = re.compile(r"^3\.\d{1,2}(\.\d{1,3})?$")
RESOLUTION_RE = re.compile(r"^\d{2,5}x\d{2,5}$")
DEP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DEP_VERSION_RE = re.compile(r"^[0-9][A-Za-z0-9.\-+]{0,31}$")

# Report-visible free text: printable, single line, no control characters, and
# no Markdown table delimiters. Rendering escapes as well - this is defence in
# depth, not a substitute for it.
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# ---------------------------------------------------------------------- bounds

SCORE_MIN, SCORE_MAX = 0.0, 1.0
DISTANCE_MIN_CM, DISTANCE_MAX_CM = 10, 500
MAX_FRAMES_ABSOLUTE = 100_000
TIMEOUT_MIN_S, TIMEOUT_MAX_S = 0.1, 600.0
TEXT_MAX_LEN = 200
NOTES_MAX_LEN = 500

# Derived fields (max/min/continuity) are restatements of the score series, so a
# small mismatch there is a transcription question, not a decision. These
# tolerances never touch the accept/reject rule - that is decision.outcome_for,
# which is exact and delegates to the shipping function.
DERIVED_TOLERANCE = 1e-6
CONTINUITY_TOLERANCE = 1e-3

# The valid range for a recorded PRNG seed. Python's random.seed accepts any
# int, but the protocol records a 32-bit unsigned value so a run is repeatable
# from the manifest alone.
SEED_MIN, SEED_MAX = 0, 2**32 - 1

#: Schema and tool versions this validator understands. A corpus may not mix
#: versions (see corpus.check_sessions).
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "1.0"


class ManifestError(Exception):
    """A manifest failed validation. Carries every finding, not just the first."""

    def __init__(self, findings: list[str]):
        self.findings = findings
        super().__init__(f"{len(findings)} validation finding(s)")


# ------------------------------------------------------------------- helpers


def _is_finite_number(value: Any) -> bool:
    """bool subclasses int in Python; a flag is not a measurement."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_keys(node: Any, allowed: frozenset[str], path: str, findings: list[str]) -> bool:
    """Exact key set. Unknown keys fail; a whitelist cannot be out-guessed."""
    if not isinstance(node, dict):
        findings.append(f"{path}: must be an object")
        return False
    unknown = sorted(set(node) - allowed)
    if unknown:
        findings.append(
            f"{path}: unknown field(s) {unknown} - this schema is a whitelist, and "
            f"an unrecognised field may carry identifying data"
        )
    missing = sorted(allowed - set(node))
    if missing:
        findings.append(f"{path}: required field(s) missing {missing}")
    return not unknown and not missing


def _check_text(value: Any, path: str, findings: list[str], *, max_len: int = TEXT_MAX_LEN,
                allow_empty: bool = False) -> None:
    """Report-visible text: printable, single-line, bounded, no table delimiters."""
    if not isinstance(value, str):
        findings.append(f"{path}: must be a string")
        return
    if not allow_empty and not value.strip():
        findings.append(f"{path}: must be a non-empty string")
        return
    if len(value) > max_len:
        findings.append(f"{path}: exceeds {max_len} characters")
    if CONTROL_CHARS_RE.search(value):
        findings.append(f"{path}: contains control characters")
    if "\n" in value or "\r" in value:
        findings.append(f"{path}: must be a single line")
    if "|" in value:
        findings.append(f"{path}: must not contain '|', which delimits Markdown tables")


# -------------------------------------------------------------- provenance


def _validate_liveness_config(config: Any, findings: list[str]) -> None:
    path = "provenance.liveness_config"
    if not _check_keys(config, CONFIG_KEYS, path, findings) and not isinstance(config, dict):
        return

    high, low = config.get("blink_score_high"), config.get("blink_score_low")
    for key, value in (("blink_score_high", high), ("blink_score_low", low)):
        if not _is_finite_number(value):
            findings.append(f"{path}.{key}: must be a finite number")
        elif not SCORE_MIN <= float(value) <= SCORE_MAX:
            findings.append(f"{path}.{key}: {value} is outside the 0..1 score range")
    if _is_finite_number(high) and _is_finite_number(low) and float(low) > float(high):
        findings.append(
            f"{path}: blink_score_low ({low}) exceeds blink_score_high ({high}); "
            f"the pair can never both be satisfied"
        )

    continuity = config.get("min_face_continuity")
    if not _is_finite_number(continuity) or not 0.0 < float(continuity) <= 1.0:
        findings.append(f"{path}.min_face_continuity: must be a number in (0, 1]")

    timeout = config.get("challenge_timeout_seconds")
    if not _is_finite_number(timeout):
        findings.append(f"{path}.challenge_timeout_seconds: must be a finite number")
    elif not TIMEOUT_MIN_S <= float(timeout) <= TIMEOUT_MAX_S:
        findings.append(
            f"{path}.challenge_timeout_seconds: {timeout} is outside "
            f"{TIMEOUT_MIN_S}..{TIMEOUT_MAX_S} seconds"
        )

    frames = config.get("max_frames_per_challenge")
    if not _is_int(frames):
        findings.append(f"{path}.max_frames_per_challenge: must be an integer")
    elif not 1 <= frames <= MAX_FRAMES_ABSOLUTE:
        findings.append(
            f"{path}.max_frames_per_challenge: {frames} is outside 1..{MAX_FRAMES_ABSOLUTE}"
        )

    # This analyser models the BLINK decision only. A manifest recorded with any
    # other challenge enabled would need different outcome verification, so it
    # is refused rather than analysed under the wrong model.
    challenges = config.get("enabled_challenges")
    if challenges != ["BLINK"]:
        findings.append(
            f"{path}.enabled_challenges: must be exactly ['BLINK'] for this "
            f"analyser, got {challenges!r}"
        )


def _validate_provenance(provenance: Any, findings: list[str]) -> None:
    path = "provenance"
    if not _check_keys(provenance, PROVENANCE_KEYS, path, findings) and not isinstance(provenance, dict):
        return

    commit = provenance.get("faceauth_commit")
    if not (isinstance(commit, str) and COMMIT_RE.match(commit)):
        findings.append(f"{path}.faceauth_commit: must be a 40-character lowercase hex SHA")

    digest = provenance.get("face_landmarker_sha256")
    if not (isinstance(digest, str) and SHA256_RE.match(digest)):
        findings.append(f"{path}.face_landmarker_sha256: must be a 64-character lowercase hex SHA-256")

    version = provenance.get("python_version")
    if not (isinstance(version, str) and PYTHON_VERSION_RE.match(version)):
        findings.append(f"{path}.python_version: must look like '3.12' or '3.12.0'")

    resolution = provenance.get("camera_resolution")
    if not (isinstance(resolution, str) and RESOLUTION_RE.match(resolution)):
        findings.append(f"{path}.camera_resolution: must look like '1280x720'")

    _check_text(provenance.get("camera_label"), f"{path}.camera_label", findings)
    _check_text(provenance.get("os_build"), f"{path}.os_build", findings)

    deps = provenance.get("pinned_dependencies")
    if not isinstance(deps, dict) or not deps:
        findings.append(f"{path}.pinned_dependencies: must be a non-empty name->version map")
    else:
        for name, pinned in sorted(deps.items()):
            if not (isinstance(name, str) and DEP_NAME_RE.match(name)):
                findings.append(f"{path}.pinned_dependencies: {name!r} is not a valid package name")
            if not (isinstance(pinned, str) and DEP_VERSION_RE.match(pinned)):
                findings.append(
                    f"{path}.pinned_dependencies[{name!r}]: {pinned!r} is not an exact pinned version"
                )

    implementation = provenance.get("liveness_implementation")
    if implementation not in LIVENESS_IMPLEMENTATIONS:
        findings.append(
            f"{path}.liveness_implementation: {implementation!r} is not one of "
            f"{list(LIVENESS_IMPLEMENTATIONS)}; scores from a different liveness "
            f"implementation are not comparable with these"
        )

    for key, expected in (("schema_version", SCHEMA_VERSION), ("tool_version", TOOL_VERSION)):
        stated = provenance.get(key)
        if stated != expected:
            findings.append(
                f"{path}.{key}: this tool reads {expected!r}, got {stated!r}; a manifest "
                f"written against a different {key} may mean different things by the "
                f"same field names"
            )

    _validate_liveness_config(provenance.get("liveness_config"), findings)


# ------------------------------------------------------------------ trials


def _validate_condition(condition: Any, path: str, findings: list[str]) -> None:
    if not _check_keys(condition, CONDITION_KEYS, path, findings) and not isinstance(condition, dict):
        return
    for key, allowed in (("lighting", LIGHTING), ("head_pose", HEAD_POSE), ("eyewear", EYEWEAR)):
        if condition.get(key) not in allowed:
            findings.append(f"{path}.{key}: {condition.get(key)!r} is not one of {list(allowed)}")
    distance = condition.get("distance_cm")
    if not _is_int(distance):
        findings.append(f"{path}.distance_cm: must be an integer")
    elif not DISTANCE_MIN_CM <= distance <= DISTANCE_MAX_CM:
        findings.append(
            f"{path}.distance_cm: {distance} is outside {DISTANCE_MIN_CM}..{DISTANCE_MAX_CM} cm"
        )


def _expected_self_report(intended_type: str) -> str:
    if intended_type in GENUINE_BLINK_TYPES:
        return "blinked"
    if intended_type in GENUINE_NON_BLINK_TYPES:
        return "did_not_blink"
    return "n/a"


def _verify_outcome(trial: dict, config: dict, path: str, findings: list[str]) -> None:
    """Recompute the attempt outcome from the manifest and shipping behaviour.

    ``attempt_outcome`` is an editable field. Trusting it would let a manifest
    assert any FAR or FRR the author wanted, so every fact recomputable from the
    record is recomputed and cross-checked.
    """
    scores = trial.get("blink_scores")
    high, low = config.get("blink_score_high"), config.get("blink_score_low")
    min_continuity = config.get("min_face_continuity")
    captured, with_face = trial.get("frames_captured"), trial.get("frames_with_face")
    outcome, reason = trial.get("attempt_outcome"), trial.get("outcome_reason")

    if not (
        isinstance(scores, list)
        and all(_is_finite_number(s) for s in scores)
        and _is_finite_number(high) and _is_finite_number(low)
        and _is_finite_number(min_continuity)
        and _is_int(captured) and _is_int(with_face) and captured > 0
    ):
        return  # a prior finding already covers the malformed input

    if not scores:
        if outcome != "rejected" or reason != "no_face_observed_during_challenge":
            findings.append(
                f"{path}: an empty observation series can only produce "
                f"rejected/'no_face_observed_during_challenge', got "
                f"{outcome!r}/{reason!r}"
            )
        return

    values = [float(s) for s in scores]
    continuity = with_face / captured
    # The shipping rule, via the shipping function. No tolerance, no local copy.
    expected = outcome_for(
        values, float(high), float(low),
        frames_captured=captured,
        frames_with_face=with_face,
        min_face_continuity=float(min_continuity),
        min_frames_for_continuity_check=MIN_FRAMES_FOR_CONTINUITY_CHECK,
    )
    expected_outcome, expected_reason = expected.outcome, expected.reason

    if outcome != expected_outcome:
        findings.append(
            # repr, not a rounded format: a value like 0.3999999995 must not be
            # printed as "0.400000" in the very message explaining that it does
            # not reach 0.40.
            f"{path}.attempt_outcome: recorded {outcome!r} but max={max(values)!r}, "
            f"min={min(values)!r} against high={high!r}/low={low!r} with continuity "
            f"{continuity!r} implies {expected_outcome!r}"
        )
    if reason != expected_reason:
        findings.append(
            f"{path}.outcome_reason: recorded {reason!r} but the recomputed decision "
            f"implies {expected_reason!r}"
        )


def _validate_trial(trial: Any, index: int, config: dict, findings: list[str]) -> None:
    path = f"trials[{index}]"
    if not _check_keys(trial, TRIAL_KEYS, path, findings) and not isinstance(trial, dict):
        return

    if not _is_int(trial.get("trial_index")) or trial.get("trial_index") < 0:
        findings.append(f"{path}.trial_index: must be a non-negative integer")

    intended = trial.get("intended_type")
    if intended not in TRIAL_TYPES:
        findings.append(f"{path}.intended_type: {intended!r} is not one of {list(TRIAL_TYPES)}")

    _validate_condition(trial.get("condition"), f"{path}.condition", findings)

    valid = trial.get("valid")
    reason = trial.get("exclusion_reason")
    if not isinstance(valid, bool):
        findings.append(f"{path}.valid: must be a boolean")
    elif valid and reason is not None:
        findings.append(f"{path}: valid is true but exclusion_reason is {reason!r}")
    elif not valid and reason is None:
        findings.append(f"{path}: valid is false but exclusion_reason is null")
    if reason is not None and reason not in EXCLUSION_REASONS:
        findings.append(f"{path}.exclusion_reason: {reason!r} is not one of {list(EXCLUSION_REASONS)}")

    # --- observation series -------------------------------------------------
    scores = trial.get("blink_scores")
    scores_ok = False
    if not isinstance(scores, list):
        findings.append(f"{path}.blink_scores: must be an array")
    elif not all(_is_finite_number(s) for s in scores):
        findings.append(f"{path}.blink_scores: contains a non-finite or non-numeric value")
    elif not all(SCORE_MIN <= float(s) <= SCORE_MAX for s in scores):
        findings.append(f"{path}.blink_scores: a value is outside the 0..1 score range")
    elif not scores:
        # Zero observations is honest only for the reasons that mean "nothing
        # was ever measured". Everything else must carry its series.
        if valid is not False or reason not in EMPTY_OBSERVATION_REASONS:
            findings.append(
                f"{path}.blink_scores: an empty series is only permitted for an "
                f"excluded trial with reason in {list(EMPTY_OBSERVATION_REASONS)}, "
                f"not valid={valid!r} reason={reason!r}"
            )
        else:
            scores_ok = True
    else:
        scores_ok = True

    # --- derived values, recomputed not trusted -----------------------------
    if scores_ok and scores:
        values = [float(s) for s in scores]
        for key, expected in (("max_blink_score", max(values)), ("min_blink_score", min(values))):
            stated = trial.get(key)
            if not _is_finite_number(stated):
                findings.append(f"{path}.{key}: must be a finite number")
            elif abs(float(stated) - expected) > DERIVED_TOLERANCE:
                findings.append(f"{path}.{key}: stated {stated} but the series gives {expected:.6f}")
    elif scores_ok and not scores:
        for key in ("max_blink_score", "min_blink_score"):
            if trial.get(key) is not None:
                findings.append(f"{path}.{key}: must be null when there are no observations")

    turn_ratios = trial.get("turn_ratios")
    if turn_ratios is not None:
        if not isinstance(turn_ratios, list) or not turn_ratios:
            findings.append(f"{path}.turn_ratios: must be null or a non-empty array")
        elif not all(_is_finite_number(t) for t in turn_ratios):
            findings.append(f"{path}.turn_ratios: contains a non-finite or non-numeric value")

    # --- frames -------------------------------------------------------------
    captured, with_face = trial.get("frames_captured"), trial.get("frames_with_face")
    frames_ok = True
    for key, value in (("frames_captured", captured), ("frames_with_face", with_face)):
        if not _is_int(value) or value < 0:
            findings.append(f"{path}.{key}: must be a non-negative integer")
            frames_ok = False
        elif value > MAX_FRAMES_ABSOLUTE:
            findings.append(f"{path}.{key}: {value} exceeds the sanity bound {MAX_FRAMES_ABSOLUTE}")
            frames_ok = False

    if frames_ok:
        if captured == 0:
            findings.append(f"{path}.frames_captured: must be greater than zero")
        else:
            if with_face > captured:
                findings.append(
                    f"{path}.frames_with_face: {with_face} exceeds frames_captured {captured}"
                )
            expected_continuity = with_face / captured
            stated = trial.get("face_continuity")
            if not _is_finite_number(stated):
                findings.append(f"{path}.face_continuity: must be a finite number")
            elif abs(float(stated) - expected_continuity) > CONTINUITY_TOLERANCE:
                findings.append(
                    f"{path}.face_continuity: stated {stated} but {with_face}/{captured} "
                    f"gives {expected_continuity:.6f}"
                )
            # observe() records at most one score per frame that had a face.
            if isinstance(scores, list) and len(scores) > with_face:
                findings.append(
                    f"{path}: {len(scores)} observations exceed frames_with_face "
                    f"{with_face}; the pipeline records at most one score per "
                    f"frame in which a face was detected"
                )
            if reason == "no_face_detected" and with_face != 0:
                findings.append(
                    f"{path}: exclusion_reason 'no_face_detected' but frames_with_face "
                    f"is {with_face}, not 0"
                )
            # The capture loop cannot exceed its own configured frame budget.
            cap = config.get("max_frames_per_challenge") if isinstance(config, dict) else None
            if _is_int(cap) and captured > cap:
                findings.append(
                    f"{path}.frames_captured: {captured} exceeds the configured "
                    f"max_frames_per_challenge {cap}; the capture loop stops at the cap, "
                    f"so this record could not have been produced by the shipping path"
                )

    # --- enums and text -----------------------------------------------------
    if trial.get("attempt_outcome") not in ATTEMPT_OUTCOMES:
        findings.append(f"{path}.attempt_outcome: {trial.get('attempt_outcome')!r} is not one of {list(ATTEMPT_OUTCOMES)}")
    if trial.get("outcome_reason") not in OUTCOME_REASONS:
        findings.append(
            f"{path}.outcome_reason: {trial.get('outcome_reason')!r} is not one of "
            f"{list(OUTCOME_REASONS)} - the shipping BLINK path produces no other reason"
        )
    if trial.get("ground_truth") not in GROUND_TRUTHS:
        findings.append(f"{path}.ground_truth: {trial.get('ground_truth')!r} is not one of {list(GROUND_TRUTHS)}")
    if trial.get("self_report") not in SELF_REPORTS:
        findings.append(f"{path}.self_report: {trial.get('self_report')!r} is not one of {list(SELF_REPORTS)}")
    if trial.get("label_source") not in LABEL_SOURCES:
        findings.append(f"{path}.label_source: {trial.get('label_source')!r} is not one of {list(LABEL_SOURCES)}")
    _check_text(trial.get("notes"), f"{path}.notes", findings,
                max_len=NOTES_MAX_LEN, allow_empty=True)

    # --- ground truth and self-report ---------------------------------------
    if intended in TRIAL_TYPES:
        expected_truth = (
            "blink" if intended in GENUINE_BLINK_TYPES
            else "no_blink" if intended in GENUINE_NON_BLINK_TYPES
            else "spoof"
        )
        if trial.get("ground_truth") != expected_truth:
            findings.append(
                f"{path}.ground_truth: {trial.get('ground_truth')!r} contradicts "
                f"intended_type {intended!r}, which implies {expected_truth!r}"
            )
        expected_report = _expected_self_report(intended)
        actual_report = trial.get("self_report")
        if valid is True and actual_report != expected_report:
            findings.append(
                f"{path}.self_report: a VALID {intended} trial requires "
                f"{expected_report!r}; {actual_report!r} is a ground-truth "
                f"disagreement and must be excluded as 'ambiguous_ground_truth'"
            )
        if valid is False and actual_report != expected_report and reason != "ambiguous_ground_truth":
            findings.append(
                f"{path}: self_report {actual_report!r} disagrees with intended_type "
                f"{intended!r}, so exclusion_reason must be 'ambiguous_ground_truth', "
                f"not {reason!r}"
            )

        # --- label source: what the label actually rests on -----------------
        label_source = trial.get("label_source")
        if intended in SPOOF_TYPES:
            if label_source != SPOOF_LABEL_SOURCE:
                findings.append(
                    f"{path}.label_source: a spoof trial has no participant to "
                    f"self-report, so its label rests on the schedule alone; expected "
                    f"{SPOOF_LABEL_SOURCE!r}, got {label_source!r}"
                )
        elif label_source != GENUINE_LABEL_SOURCE:
            findings.append(
                f"{path}.label_source: a genuine trial's label requires both the "
                f"scheduled action and the participant's self-report; expected "
                f"{GENUINE_LABEL_SOURCE!r}, got {label_source!r}"
            )

    # --- turn_ratios are only meaningful for a head-turn challenge ----------
    if isinstance(config, dict):
        enabled = config.get("enabled_challenges")
        turn_ratios = trial.get("turn_ratios")
        if isinstance(enabled, list) and enabled == ["BLINK"] and turn_ratios:
            findings.append(
                f"{path}.turn_ratios: {len(turn_ratios)} value(s) recorded, but "
                f"enabled_challenges is {enabled} - no head-turn challenge was issued, "
                f"so a turn-ratio series cannot have been observed for this trial"
            )

    # --- outcome verification -----------------------------------------------
    # Every trial, not only the valid ones: an excluded trial's recorded outcome
    # is just as derivable from its score series, and just as editable.
    if isinstance(config, dict):
        _verify_outcome(trial, config, path, findings)


def _validate_retries(trials: list[dict], findings: list[str]) -> None:
    """Retry invariants (plan §7.3): one retry, of an excluded original, same cell, after it."""
    by_index: dict[int, dict] = {
        t["trial_index"]: t for t in trials if _is_int(t.get("trial_index"))
    }
    retried: dict[int, list[int]] = {}

    for trial in trials:
        source = trial.get("trial_index")
        target = trial.get("retry_of_trial_index")
        if target is None:
            continue
        path = f"trial {source}"
        if not _is_int(target):
            findings.append(f"{path}.retry_of_trial_index: must be an integer or null")
            continue
        if target == source:
            findings.append(f"{path}.retry_of_trial_index: a trial cannot be a retry of itself")
            continue
        original = by_index.get(target)
        if original is None:
            findings.append(f"{path}.retry_of_trial_index: {target} matches no trial_index")
            continue
        if original.get("valid") is not False:
            findings.append(
                f"{path}.retry_of_trial_index: trial {target} is VALID; only an "
                f"excluded trial may be retried, otherwise the same cell is counted twice"
            )
        if original.get("retry_of_trial_index") is not None:
            findings.append(
                f"{path}.retry_of_trial_index: trial {target} is itself a retry; "
                f"at most one retry per cell"
            )
        if original.get("intended_type") != trial.get("intended_type"):
            findings.append(
                f"{path}.retry_of_trial_index: intended_type {trial.get('intended_type')!r} "
                f"differs from the original's {original.get('intended_type')!r}; a retry "
                f"must re-run the same cell"
            )
        if original.get("condition") != trial.get("condition"):
            findings.append(
                f"{path}.retry_of_trial_index: condition differs from the original's; "
                f"a retry must re-run the same condition cell"
            )
        if _is_int(source) and source <= target:
            findings.append(
                f"{path}.retry_of_trial_index: a retry must occur after the trial it "
                f"repeats (index {source} <= {target})"
            )
        if _is_int(source):
            retried.setdefault(target, []).append(source)

    for target, sources in sorted(retried.items()):
        if len(sources) > 1:
            findings.append(
                f"trial {target}: retried by {sorted(sources)} - at most one retry per cell"
            )

    for trial in trials:                       # independent cycle detection
        seen: set[int] = set()
        node = trial.get("trial_index")
        while _is_int(node) and node in by_index:
            if node in seen:
                findings.append(f"trial {trial.get('trial_index')}: retry chain forms a cycle")
                break
            seen.add(node)
            node = by_index[node].get("retry_of_trial_index")


# ------------------------------------------------------------------- session


def validate_session(session: Any) -> list[str]:
    """Return every finding for one session object. Empty means valid."""
    findings: list[str] = []

    if not isinstance(session, dict):
        return ["session: top level must be a JSON object"]

    _check_keys(session, SESSION_KEYS, "session", findings)

    classification = session.get("data_classification")
    if classification != REQUIRED_DATA_CLASSIFICATION:
        findings.append(
            f"session.data_classification: must be {REQUIRED_DATA_CLASSIFICATION!r}, got "
            f"{classification!r}. Stage 0 tooling processes synthetic manifests only; "
            f"handling real Stage 1/2 data requires a separate, owner-authorized, "
            f"reviewed change."
        )

    participant = session.get("participant_id")
    if not (isinstance(participant, str) and PARTICIPANT_ID_RE.match(participant)):
        findings.append(
            f"session.participant_id: {participant!r} must be a pseudonym like 'P01'"
        )
    session_id = session.get("session_id")
    if not (isinstance(session_id, str) and SESSION_ID_RE.match(session_id)):
        findings.append(f"session.session_id: {session_id!r} must be a pseudonym like 'S01'")

    date = session.get("date")
    if not isinstance(date, str):
        findings.append("session.date: must be a string")
    else:
        try:
            parsed = _datetime.date.fromisoformat(date)
        except ValueError:
            findings.append(f"session.date: {date!r} is not a real calendar date (YYYY-MM-DD)")
        else:
            if not 2000 <= parsed.year <= 2100:
                findings.append(f"session.date: year {parsed.year} is implausible")

    _check_text(session.get("operator_role"), "session.operator_role", findings)

    seed = session.get("randomisation_seed")
    if not _is_int(seed):
        findings.append("session.randomisation_seed: must be an integer, recorded for repeatability")
    elif not (SEED_MIN <= seed <= SEED_MAX):
        findings.append(
            f"session.randomisation_seed: {seed} is outside the documented range "
            f"{SEED_MIN}..{SEED_MAX}; a seed outside it cannot be replayed as recorded"
        )

    _validate_provenance(session.get("provenance"), findings)

    trials = session.get("trials")
    if not isinstance(trials, list) or not trials:
        findings.append("session.trials: must be a non-empty array")
        return findings

    provenance = session.get("provenance")
    config = provenance.get("liveness_config") if isinstance(provenance, dict) else None
    for index, trial in enumerate(trials):
        _validate_trial(trial, index, config if isinstance(config, dict) else {}, findings)

    dict_trials = [t for t in trials if isinstance(t, dict)]
    indices = [t.get("trial_index") for t in dict_trials if _is_int(t.get("trial_index"))]
    duplicates = sorted({i for i in indices if indices.count(i) > 1})
    if duplicates:
        findings.append(f"session.trials: duplicate trial_index values {duplicates}")

    _validate_retries(dict_trials, findings)
    return findings


def require_valid_session(session: Any, source: str) -> dict:
    """Validate or raise. Never returns a partially-validated manifest."""
    findings = validate_session(session)
    if findings:
        raise ManifestError([f"{source}: {f}" for f in findings])
    return session
