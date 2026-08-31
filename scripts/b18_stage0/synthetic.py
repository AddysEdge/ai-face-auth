"""Deterministic synthetic manifests for the Stage 0 dry run.

**Every value here is invented.** There is no participant, no camera, no
recording and no measurement behind any of it - the labels say `SYNTHETIC` for
exactly that reason, and every session declares
``data_classification: "synthetic_stage0"``, which is the only classification
the Stage 0 tooling will process.

Nothing in this module is evidence about the liveness control, and no threshold
or acceptance criterion may be derived from it.

Outcomes here are *computed from the scores*, never asserted. The validator
recomputes the same decision and rejects any disagreement, so a fixture cannot
quietly encode an impossible result.
"""

from __future__ import annotations

from typing import Any

from scripts.b18_stage0 import schema
from scripts.b18_stage0.decision import outcome_for

SYNTHETIC_COMMIT = "0" * 40
SYNTHETIC_MODEL_SHA = "1" * 64
CAMERA_A = "SYNTHETIC-CAM-A (fictional)"
CAMERA_B = "SYNTHETIC-CAM-B (fictional)"

HIGH = 0.40
LOW = 0.20
MIN_CONTINUITY = 0.5
MIN_FRAMES_FOR_CONTINUITY = 5

DATA_CLASSIFICATION = "synthetic_stage0"


def _provenance(camera: str) -> dict[str, Any]:
    return {
        "faceauth_commit": SYNTHETIC_COMMIT,
        "python_version": "3.12.0",
        "pinned_dependencies": {"ai-edge-litert": "2.2.0", "opencv-contrib-python": "5.0.0.93"},
        "face_landmarker_sha256": SYNTHETIC_MODEL_SHA,
        "liveness_config": {
            "blink_score_high": HIGH,
            "blink_score_low": LOW,
            "enabled_challenges": ["BLINK"],
            "challenge_timeout_seconds": 5.0,
            "max_frames_per_challenge": 300,
            "min_face_continuity": MIN_CONTINUITY,
        },
        "camera_label": camera,
        "camera_resolution": "1280x720",
        "os_build": "SYNTHETIC-OS-BUILD",
        "liveness_implementation": "litert_landmarker",
        "schema_version": schema.SCHEMA_VERSION,
        "tool_version": schema.TOOL_VERSION,
    }


def _expected_self_report(intended_type: str) -> str:
    if intended_type.startswith("G"):
        return "blinked"
    if intended_type.startswith("N"):
        return "did_not_blink"
    return "n/a"


def make_trial(
    trial_index: int,
    intended_type: str,
    scores: list[float],
    *,
    lighting: str = "bright_even",
    head_pose: str = "frontal",
    distance_cm: int = 70,
    eyewear: str = "none",
    frames_captured: int = 60,
    frames_with_face: int | None = None,
    valid: bool = True,
    exclusion_reason: str | None = None,
    retry_of_trial_index: int | None = None,
    self_report: str | None = None,
    notes: str = "",
) -> dict[str, Any]:
    """Build one internally consistent trial.

    The attempt outcome and its reason are *derived* from the scores, the frame
    counts and the shipping decision rule - not passed in. That keeps every
    fixture honest by construction.
    """
    ground_truth = (
        "blink" if intended_type.startswith("G")
        else "no_blink" if intended_type.startswith("N")
        else "spoof"
    )
    if self_report is None:
        self_report = _expected_self_report(intended_type)
    if frames_with_face is None:
        frames_with_face = max(len(scores), frames_captured - 2)

    # Derived through the one shared implementation, which delegates to the
    # shipping decide_blink. A fixture built by a second copy of the rule could
    # encode an outcome the real system would never produce, and the validator
    # would then be checked against a fiction.
    outcome = outcome_for(
        list(scores), HIGH, LOW,
        frames_captured=frames_captured,
        frames_with_face=frames_with_face,
        min_face_continuity=MIN_CONTINUITY,
        min_frames_for_continuity_check=MIN_FRAMES_FOR_CONTINUITY,
    )
    attempt_outcome, outcome_reason = outcome.outcome, outcome.reason
    max_score: float | None = max(scores) if scores else None
    min_score: float | None = min(scores) if scores else None

    return {
        "trial_index": trial_index,
        "intended_type": intended_type,
        "condition": {
            "lighting": lighting,
            "head_pose": head_pose,
            "distance_cm": distance_cm,
            "eyewear": eyewear,
        },
        "blink_scores": list(scores),
        "turn_ratios": None,
        "max_blink_score": max_score,
        "min_blink_score": min_score,
        "frames_captured": frames_captured,
        "frames_with_face": frames_with_face,
        "face_continuity": round(frames_with_face / frames_captured, 6),
        "attempt_outcome": attempt_outcome,
        "outcome_reason": outcome_reason,
        "ground_truth": ground_truth,
        "self_report": self_report,
        "label_source": (
            schema.SPOOF_LABEL_SOURCE if intended_type in schema.SPOOF_TYPES
            else schema.GENUINE_LABEL_SOURCE
        ),
        "valid": valid,
        "exclusion_reason": exclusion_reason,
        "retry_of_trial_index": retry_of_trial_index,
        "notes": notes,
    }


def session_one() -> dict[str, Any]:
    """P01 / camera A. Accepts, rejects, an honest exclusion, and one retry."""
    excluded_condition = {"lighting": "bright_even", "head_pose": "frontal",
                          "distance_cm": 70, "eyewear": "none"}
    trials = [
        # Genuine blink accepted: rises to 0.62, dips to 0.18.
        make_trial(0, "G1", [0.25, 0.18, 0.62, 0.31]),
        # Genuine blink accepted, exercising BOTH exact inclusive boundaries.
        make_trial(1, "G1", [0.20, 0.40], lighting="dim"),
        # Genuine blink rejected - peak never reaches 0.40. An FRR event.
        make_trial(2, "G2", [0.24, 0.19, 0.37], lighting="side_light"),
        # Genuine non-blink, correctly rejected.
        make_trial(3, "N1", [0.22, 0.26, 0.24], head_pose="yaw_left_15"),
        # Still-image spoof rejected, near the threshold (0.382 -> margin 0.018).
        make_trial(4, "S1", [0.168, 0.29, 0.382], distance_cm=40),
        # Still-image spoof rejected, comfortably below.
        make_trial(5, "S1", [0.15, 0.21, 0.24], eyewear="clear_glasses"),
        # Excluded, no face detected: ZERO observations and zero face frames.
        # Nothing is fabricated to satisfy the schema.
        make_trial(
            6, "G1", [], frames_captured=60, frames_with_face=0,
            valid=False, exclusion_reason="no_face_detected", **excluded_condition,
        ),
        # The single permitted retry: same type, same condition cell, after it,
        # and of an EXCLUDED original.
        make_trial(7, "G1", [0.23, 0.19, 0.55], retry_of_trial_index=6, **excluded_condition),
    ]
    return {
        "session_id": "S01",
        "participant_id": "P01",
        "date": "2026-01-01",
        "operator_role": "synthetic operator",
        "randomisation_seed": 20260101,
        "data_classification": DATA_CLASSIFICATION,
        "provenance": _provenance(CAMERA_A),
        "trials": trials,
    }


def session_two() -> dict[str, Any]:
    """P02 / camera B. Includes an accepted S4 replay - the known gap."""
    trials = [
        make_trial(0, "G1", [0.26, 0.17, 0.71], lighting="backlit"),
        make_trial(1, "G3", [0.28, 0.20, 0.49], distance_cm=100),
        make_trial(2, "N2", [0.23, 0.25]),
        make_trial(3, "N3", [0.21, 0.27], head_pose="pitch_up_10"),
        # Hand-held still image, rejected.
        make_trial(4, "S2", [0.16, 0.22, 0.33]),
        # Video replay ACCEPTED - reported separately, never pooled.
        make_trial(5, "S4", [0.19, 0.66]),
        # Excluded for an ambiguous label: the self-report disagrees with the
        # intended type, which is precisely what that exclusion reason is for.
        make_trial(
            6, "G2", [0.22, 0.24], valid=False,
            exclusion_reason="ambiguous_ground_truth", self_report="unsure",
        ),
    ]
    return {
        "session_id": "S02",
        "participant_id": "P02",
        "date": "2026-01-02",
        "operator_role": "synthetic operator",
        "randomisation_seed": 20260102,
        "data_classification": DATA_CLASSIFICATION,
        "provenance": _provenance(CAMERA_B),
        "trials": trials,
    }


def corpus() -> list[dict[str, Any]]:
    """The full synthetic Stage 0 corpus, in a stable order.

    S3 and S5 deliberately have no trials, so the analysis is exercised against
    zero-denominator groups as well as zero-event ones.
    """
    return [session_one(), session_two()]
