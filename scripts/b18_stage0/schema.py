"""Validation of B18 session manifests against the published schema.

The normative schema is ``docs/b18/forms/TRIAL_MANIFEST_SCHEMA.md``; this module
enforces it. Nothing here reads a camera, and nothing here is specific to real
participants - it validates a JSON document.

Design stance: **fail closed, and never drop a trial silently.** A manifest that
cannot be fully validated is rejected in its entirety rather than analysed in
part, because a partially-validated manifest produces rates whose denominators
nobody can defend.

Every check returns a precise, human-readable finding naming the exact JSON path
that failed, so a rejection is actionable rather than a bare "invalid".
"""

from __future__ import annotations

import math
import re
from typing import Any

# ---------------------------------------------------------------- vocabularies

GENUINE_BLINK_TYPES = ("G1", "G2", "G3")
GENUINE_NON_BLINK_TYPES = ("N1", "N2", "N3")
SPOOF_TYPES = ("S1", "S2", "S3", "S4", "S5")
TRIAL_TYPES = GENUINE_BLINK_TYPES + GENUINE_NON_BLINK_TYPES + SPOOF_TYPES

LIGHTING = ("bright_even", "dim", "side_light", "backlit")
HEAD_POSE = ("frontal", "yaw_left_15", "yaw_right_15", "pitch_up_10", "pitch_down_10")
EYEWEAR = ("none", "clear_glasses", "tinted")

ATTEMPT_OUTCOMES = ("accepted", "rejected")
GROUND_TRUTHS = ("blink", "no_blink", "spoof")
SELF_REPORTS = ("blinked", "did_not_blink", "unsure", "n/a")
EXCLUSION_REASONS = (
    "no_face_detected",
    "missed_prompt",
    "operator_error",
    "software_error",
    "ambiguous_ground_truth",
)

# Pseudonymous identifiers only. A name would not match these.
PARTICIPANT_ID_RE = re.compile(r"^P\d{2,4}$")
SESSION_ID_RE = re.compile(r"^S\d{2,4}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

# Schema §"Prohibited fields". Checked at every nesting depth, on key names.
PROHIBITED_KEYS = frozenset(
    {
        "name", "first_name", "last_name", "full_name", "initials",
        "email", "e_mail", "mail", "phone", "telephone", "address",
        "account", "account_id", "user", "user_id", "username", "login",
        "dob", "date_of_birth", "birthdate", "age",
        "serial", "serial_number", "device_serial", "mac", "mac_address",
        "photo", "photograph", "frame", "frames", "image", "images",
        "video", "recording", "audio", "signature", "contact",
        "file_path", "filepath", "path", "media_path", "media",
    }
)

# Bounds. Blink blendshape scores are 0..1 by construction.
SCORE_MIN, SCORE_MAX = 0.0, 1.0
DISTANCE_MIN_CM, DISTANCE_MAX_CM = 10, 500
MAX_FRAMES_ABSOLUTE = 100_000

# Derived values are recomputed and compared, not trusted. The tolerance covers
# JSON round-tripping of float32-derived values, not disagreement.
DERIVED_TOLERANCE = 1e-6

REQUIRED_SESSION_KEYS = (
    "session_id", "participant_id", "date", "operator_role",
    "randomisation_seed", "provenance", "trials",
)
REQUIRED_PROVENANCE_KEYS = (
    "faceauth_commit", "python_version", "pinned_dependencies",
    "face_landmarker_sha256", "liveness_config", "camera_label",
    "camera_resolution", "os_build",
)
REQUIRED_CONFIG_KEYS = (
    "blink_score_high", "blink_score_low", "enabled_challenges",
    "challenge_timeout_seconds", "max_frames_per_challenge", "min_face_continuity",
)
REQUIRED_TRIAL_KEYS = (
    "trial_index", "intended_type", "condition", "blink_scores",
    "max_blink_score", "min_blink_score", "frames_captured", "frames_with_face",
    "face_continuity", "attempt_outcome", "outcome_reason", "ground_truth",
    "self_report", "label_source", "valid", "exclusion_reason",
    "retry_of_trial_index",
)
REQUIRED_CONDITION_KEYS = ("lighting", "head_pose", "distance_cm", "eyewear")


class ManifestError(Exception):
    """A manifest failed validation. Carries every finding, not just the first."""

    def __init__(self, findings: list[str]):
        self.findings = findings
        super().__init__(f"{len(findings)} validation finding(s)")


def _is_finite_number(value: Any) -> bool:
    """bool is a subclass of int in Python; a flag is not a measurement."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _scan_prohibited_keys(node: Any, path: str, findings: list[str]) -> None:
    """Recursive key scan at every nesting depth (schema §Prohibited fields)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key.strip().lower() in PROHIBITED_KEYS:
                findings.append(
                    f"{path}.{key}: prohibited field - the schema forbids "
                    f"identifying or media fields at any nesting level"
                )
            _scan_prohibited_keys(value, f"{path}.{key}", findings)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _scan_prohibited_keys(item, f"{path}[{index}]", findings)


def _validate_provenance(provenance: Any, findings: list[str]) -> None:
    path = "provenance"
    if not isinstance(provenance, dict):
        findings.append(f"{path}: must be an object")
        return
    for key in REQUIRED_PROVENANCE_KEYS:
        if key not in provenance:
            findings.append(f"{path}.{key}: required field is missing")

    commit = provenance.get("faceauth_commit")
    if commit is not None and not (isinstance(commit, str) and COMMIT_RE.match(commit)):
        findings.append(f"{path}.faceauth_commit: must be a 40-character hex commit SHA")

    digest = provenance.get("face_landmarker_sha256")
    if digest is not None and not (isinstance(digest, str) and SHA256_RE.match(digest)):
        findings.append(f"{path}.face_landmarker_sha256: must be a 64-character hex SHA-256")

    deps = provenance.get("pinned_dependencies")
    if deps is not None and not (
        isinstance(deps, dict)
        and deps
        and all(isinstance(k, str) and isinstance(v, str) for k, v in deps.items())
    ):
        findings.append(f"{path}.pinned_dependencies: must be a non-empty name->version map")

    config = provenance.get("liveness_config")
    if config is None:
        return
    if not isinstance(config, dict):
        findings.append(f"{path}.liveness_config: must be an object")
        return

    for key in REQUIRED_CONFIG_KEYS:
        if key not in config:
            findings.append(f"{path}.liveness_config.{key}: required field is missing")

    # Thresholds must be explicit and internally consistent. The analysis reads
    # them from here rather than assuming, so a wrong pair must not pass.
    high, low = config.get("blink_score_high"), config.get("blink_score_low")
    for key, value in (("blink_score_high", high), ("blink_score_low", low)):
        if value is None:
            continue
        if not _is_finite_number(value):
            findings.append(f"{path}.liveness_config.{key}: must be a finite number")
        elif not SCORE_MIN <= float(value) <= SCORE_MAX:
            findings.append(
                f"{path}.liveness_config.{key}: {value} is outside the 0..1 score range"
            )
    if _is_finite_number(high) and _is_finite_number(low) and float(low) > float(high):
        findings.append(
            f"{path}.liveness_config: blink_score_low ({low}) exceeds "
            f"blink_score_high ({high}); the pair cannot both be satisfied"
        )

    continuity = config.get("min_face_continuity")
    if continuity is not None and not (
        _is_finite_number(continuity) and 0.0 < float(continuity) <= 1.0
    ):
        findings.append(f"{path}.liveness_config.min_face_continuity: must be in (0, 1]")

    challenges = config.get("enabled_challenges")
    if challenges is not None and not (
        isinstance(challenges, list) and challenges
        and all(isinstance(c, str) for c in challenges)
    ):
        findings.append(f"{path}.liveness_config.enabled_challenges: must be a non-empty list")


def _validate_condition(condition: Any, path: str, findings: list[str]) -> None:
    if not isinstance(condition, dict):
        findings.append(f"{path}: must be an object")
        return
    for key in REQUIRED_CONDITION_KEYS:
        if key not in condition:
            findings.append(f"{path}.{key}: required field is missing")

    for key, allowed in (
        ("lighting", LIGHTING), ("head_pose", HEAD_POSE), ("eyewear", EYEWEAR)
    ):
        value = condition.get(key)
        if value is not None and value not in allowed:
            findings.append(f"{path}.{key}: {value!r} is not one of {list(allowed)}")

    distance = condition.get("distance_cm")
    if distance is not None:
        if not _is_finite_number(distance):
            findings.append(f"{path}.distance_cm: must be a finite number")
        elif not DISTANCE_MIN_CM <= float(distance) <= DISTANCE_MAX_CM:
            findings.append(
                f"{path}.distance_cm: {distance} is outside "
                f"{DISTANCE_MIN_CM}..{DISTANCE_MAX_CM} cm"
            )


def _validate_trial(trial: Any, index: int, findings: list[str]) -> None:
    path = f"trials[{index}]"
    if not isinstance(trial, dict):
        findings.append(f"{path}: must be an object")
        return

    for key in REQUIRED_TRIAL_KEYS:
        if key not in trial:
            findings.append(f"{path}.{key}: required field is missing")

    trial_index = trial.get("trial_index")
    if not (isinstance(trial_index, int) and not isinstance(trial_index, bool) and trial_index >= 0):
        findings.append(f"{path}.trial_index: must be a non-negative integer")

    if trial.get("intended_type") not in TRIAL_TYPES:
        findings.append(
            f"{path}.intended_type: {trial.get('intended_type')!r} is not one of {list(TRIAL_TYPES)}"
        )

    _validate_condition(trial.get("condition"), f"{path}.condition", findings)

    # --- score series -------------------------------------------------------
    scores = trial.get("blink_scores")
    scores_ok = False
    if not isinstance(scores, list) or not scores:
        findings.append(f"{path}.blink_scores: must be a non-empty array")
    elif not all(_is_finite_number(s) for s in scores):
        findings.append(
            f"{path}.blink_scores: contains a non-finite or non-numeric value "
            f"(NaN and Infinity are rejected)"
        )
    elif not all(SCORE_MIN <= float(s) <= SCORE_MAX for s in scores):
        findings.append(f"{path}.blink_scores: a value is outside the 0..1 score range")
    else:
        scores_ok = True

    turn_ratios = trial.get("turn_ratios")
    if turn_ratios is not None:
        if not isinstance(turn_ratios, list) or not turn_ratios:
            findings.append(f"{path}.turn_ratios: must be null or a non-empty array")
        elif not all(_is_finite_number(t) for t in turn_ratios):
            findings.append(f"{path}.turn_ratios: contains a non-finite or non-numeric value")

    # --- derived values, recomputed not trusted -----------------------------
    if scores_ok:
        values = [float(s) for s in scores]
        for key, expected in (("max_blink_score", max(values)), ("min_blink_score", min(values))):
            stated = trial.get(key)
            if not _is_finite_number(stated):
                findings.append(f"{path}.{key}: must be a finite number")
            elif abs(float(stated) - expected) > DERIVED_TOLERANCE:
                findings.append(
                    f"{path}.{key}: stated {stated} but blink_scores gives {expected:.6f}"
                )

    # --- frames and continuity ---------------------------------------------
    captured = trial.get("frames_captured")
    with_face = trial.get("frames_with_face")
    frames_ok = True
    for key, value in (("frames_captured", captured), ("frames_with_face", with_face)):
        if not (isinstance(value, int) and not isinstance(value, bool) and value >= 0):
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
            elif abs(float(stated) - expected_continuity) > 1e-3:
                findings.append(
                    f"{path}.face_continuity: stated {stated} but "
                    f"{with_face}/{captured} gives {expected_continuity:.6f}"
                )

    # --- enums --------------------------------------------------------------
    for key, allowed in (
        ("attempt_outcome", ATTEMPT_OUTCOMES),
        ("ground_truth", GROUND_TRUTHS),
        ("self_report", SELF_REPORTS),
    ):
        if trial.get(key) not in allowed:
            findings.append(f"{path}.{key}: {trial.get(key)!r} is not one of {list(allowed)}")

    for key in ("outcome_reason", "label_source"):
        value = trial.get(key)
        if not isinstance(value, str) or not value.strip():
            findings.append(f"{path}.{key}: must be a non-empty string")

    notes = trial.get("notes")
    if notes is not None and not isinstance(notes, str):
        findings.append(f"{path}.notes: must be a string or absent")

    # --- validity / exclusion consistency -----------------------------------
    valid = trial.get("valid")
    reason = trial.get("exclusion_reason")
    if not isinstance(valid, bool):
        findings.append(f"{path}.valid: must be a boolean")
    elif valid and reason is not None:
        findings.append(
            f"{path}: valid is true but exclusion_reason is {reason!r}; "
            f"the schema requires valid == false <-> exclusion_reason != null"
        )
    elif not valid and reason is None:
        findings.append(
            f"{path}: valid is false but exclusion_reason is null; "
            f"an excluded trial must say why"
        )
    if reason is not None and reason not in EXCLUSION_REASONS:
        findings.append(f"{path}.exclusion_reason: {reason!r} is not one of {list(EXCLUSION_REASONS)}")

    # --- ground truth consistency (schema invariant) ------------------------
    intended = trial.get("intended_type")
    truth = trial.get("ground_truth")
    if intended in TRIAL_TYPES and truth in GROUND_TRUTHS:
        expected_truth = (
            "blink" if intended in GENUINE_BLINK_TYPES
            else "no_blink" if intended in GENUINE_NON_BLINK_TYPES
            else "spoof"
        )
        if truth != expected_truth:
            findings.append(
                f"{path}.ground_truth: {truth!r} contradicts intended_type "
                f"{intended!r}, which implies {expected_truth!r}"
            )


def _validate_retries(trials: list[dict], findings: list[str]) -> None:
    """Retry references must resolve, not self-reference, and not form cycles.

    The protocol allows at most one retry per cell (plan §7.3), so a chain of
    retries is itself a finding even when it is acyclic.
    """
    by_index: dict[int, dict] = {}
    for trial in trials:
        index = trial.get("trial_index")
        if isinstance(index, int) and not isinstance(index, bool):
            by_index[index] = trial

    retried_targets: dict[int, list[int]] = {}
    for trial in trials:
        source = trial.get("trial_index")
        target = trial.get("retry_of_trial_index")
        if target is None:
            continue
        path = f"trial {source}"
        if not (isinstance(target, int) and not isinstance(target, bool)):
            findings.append(f"{path}.retry_of_trial_index: must be an integer or null")
            continue
        if target == source:
            findings.append(f"{path}.retry_of_trial_index: a trial cannot be a retry of itself")
            continue
        if target not in by_index:
            findings.append(
                f"{path}.retry_of_trial_index: {target} does not match any trial_index"
            )
            continue
        if by_index[target].get("retry_of_trial_index") is not None:
            findings.append(
                f"{path}.retry_of_trial_index: trial {target} is itself a retry; the "
                f"protocol allows at most one retry per cell"
            )
        if isinstance(source, int):
            retried_targets.setdefault(target, []).append(source)

    for target, sources in sorted(retried_targets.items()):
        if len(sources) > 1:
            findings.append(
                f"trial {target}: retried by {sorted(sources)} - at most one retry per cell"
            )

    # Cycle detection over the retry graph, independent of the checks above.
    for trial in trials:
        seen: set[int] = set()
        node = trial.get("trial_index")
        while isinstance(node, int) and node in by_index:
            if node in seen:
                findings.append(
                    f"trial {trial.get('trial_index')}: retry_of_trial_index forms a cycle"
                )
                break
            seen.add(node)
            node = by_index[node].get("retry_of_trial_index")


def validate_session(session: Any) -> list[str]:
    """Return every finding for one session object. Empty means valid."""
    findings: list[str] = []

    if not isinstance(session, dict):
        return ["session: top level must be a JSON object"]

    for key in REQUIRED_SESSION_KEYS:
        if key not in session:
            findings.append(f"session.{key}: required field is missing")

    participant = session.get("participant_id")
    if not (isinstance(participant, str) and PARTICIPANT_ID_RE.match(participant)):
        findings.append(
            f"session.participant_id: {participant!r} must be a pseudonym like 'P01' - "
            f"a name or any other identifier is prohibited"
        )
    session_id = session.get("session_id")
    if not (isinstance(session_id, str) and SESSION_ID_RE.match(session_id)):
        findings.append(f"session.session_id: {session_id!r} must be a pseudonym like 'S01'")

    date = session.get("date")
    if not (isinstance(date, str) and DATE_RE.match(date)):
        findings.append("session.date: must be an ISO date, YYYY-MM-DD")

    operator = session.get("operator_role")
    if not (isinstance(operator, str) and operator.strip()):
        findings.append("session.operator_role: must be a non-empty role string")

    seed = session.get("randomisation_seed")
    if not (isinstance(seed, int) and not isinstance(seed, bool)):
        findings.append("session.randomisation_seed: must be an integer, recorded for repeatability")

    _validate_provenance(session.get("provenance"), findings)
    _scan_prohibited_keys(session, "session", findings)

    trials = session.get("trials")
    if not isinstance(trials, list) or not trials:
        findings.append("session.trials: must be a non-empty array")
        return findings

    for index, trial in enumerate(trials):
        _validate_trial(trial, index, findings)

    indices = [
        t.get("trial_index") for t in trials
        if isinstance(t, dict) and isinstance(t.get("trial_index"), int)
        and not isinstance(t.get("trial_index"), bool)
    ]
    duplicates = sorted({i for i in indices if indices.count(i) > 1})
    if duplicates:
        findings.append(f"session.trials: duplicate trial_index values {duplicates}")

    _validate_retries([t for t in trials if isinstance(t, dict)], findings)
    return findings


def require_valid_session(session: Any, source: str) -> dict:
    """Validate or raise. Never returns a partially-validated manifest."""
    findings = validate_session(session)
    if findings:
        raise ManifestError([f"{source}: {f}" for f in findings])
    return session
