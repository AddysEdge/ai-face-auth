"""Deterministic synthetic manifests for the Stage 0 dry run.

**Every value here is invented.** There is no participant, no camera, no
recording and no measurement behind any of it - the IDs say `SYNTHETIC` for
exactly that reason. This exists so the validator and the analysis can be
exercised end to end before anyone is ever recorded, which is what Stage 0 is
for (plan §5).

Nothing in this module is evidence about the liveness control, and no threshold
or acceptance criterion may be derived from it.
"""

from __future__ import annotations

from typing import Any

SYNTHETIC_COMMIT = "0" * 40
SYNTHETIC_MODEL_SHA = "1" * 64
CAMERA_A = "SYNTHETIC-CAM-A (fictional)"
CAMERA_B = "SYNTHETIC-CAM-B (fictional)"

HIGH = 0.40
LOW = 0.20


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
            "min_face_continuity": 0.5,
        },
        "camera_label": camera,
        "camera_resolution": "1280x720",
        "os_build": "SYNTHETIC-OS-BUILD",
    }


def make_trial(
    trial_index: int,
    intended_type: str,
    scores: list[float],
    attempt_outcome: str,
    *,
    lighting: str = "bright_even",
    head_pose: str = "frontal",
    distance_cm: int = 70,
    eyewear: str = "none",
    frames_captured: int = 60,
    frames_with_face: int = 58,
    valid: bool = True,
    exclusion_reason: str | None = None,
    retry_of_trial_index: int | None = None,
    self_report: str | None = None,
    outcome_reason: str | None = None,
) -> dict[str, Any]:
    """Build one internally consistent trial. Derived fields are computed here."""
    ground_truth = (
        "blink" if intended_type.startswith("G")
        else "no_blink" if intended_type.startswith("N")
        else "spoof"
    )
    if self_report is None:
        self_report = (
            "blinked" if ground_truth == "blink"
            else "did_not_blink" if ground_truth == "no_blink"
            else "n/a"
        )
    if outcome_reason is None:
        outcome_reason = (
            "blink_detected" if attempt_outcome == "accepted"
            else "no_transient_blink_detected"
        )
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
        "max_blink_score": max(scores),
        "min_blink_score": min(scores),
        "frames_captured": frames_captured,
        "frames_with_face": frames_with_face,
        "face_continuity": round(frames_with_face / frames_captured, 6),
        "attempt_outcome": attempt_outcome,
        "outcome_reason": outcome_reason,
        "ground_truth": ground_truth,
        "self_report": self_report,
        "label_source": "schedule+self_report",
        "valid": valid,
        "exclusion_reason": exclusion_reason,
        "retry_of_trial_index": retry_of_trial_index,
        "notes": "",
    }


def session_one() -> dict[str, Any]:
    """P01 / camera A. Covers accepts, rejects, exclusions and one retry."""
    trials = [
        # Genuine blink, accepted: rises past 0.40 and dips to 0.18.
        make_trial(0, "G1", [0.25, 0.18, 0.62, 0.31], "accepted"),
        # Genuine blink, accepted, exercising the EXACT inclusive boundaries.
        make_trial(1, "G1", [0.20, 0.40], "accepted", lighting="dim"),
        # Genuine blink, REJECTED - peak never reaches 0.40 (an FRR event).
        make_trial(2, "G2", [0.24, 0.19, 0.37], "rejected", lighting="side_light"),
        # Genuine non-blink, correctly rejected.
        make_trial(3, "N1", [0.22, 0.26, 0.24], "rejected", head_pose="yaw_left_15"),
        # Static photo spoof, rejected - close to the threshold (0.382).
        make_trial(4, "S1", [0.168, 0.29, 0.382], "rejected", distance_cm=40),
        # Static photo spoof, rejected, comfortably below.
        make_trial(5, "S1", [0.15, 0.21, 0.24], "rejected", eyewear="clear_glasses"),
        # Excluded: no face detected. Must enter no numerator or denominator.
        make_trial(
            6, "G1", [0.21, 0.22], "rejected",
            valid=False, exclusion_reason="no_face_detected", frames_with_face=5,
        ),
        # A single valid retry of trial 6.
        make_trial(7, "G1", [0.23, 0.19, 0.55], "accepted", retry_of_trial_index=6),
    ]
    return {
        "session_id": "S01",
        "participant_id": "P01",
        "date": "2026-01-01",
        "operator_role": "synthetic operator",
        "randomisation_seed": 20260101,
        "provenance": _provenance(CAMERA_A),
        "trials": trials,
    }


def session_two() -> dict[str, Any]:
    """P02 / camera B. Includes a spoof ACCEPTED, so FAR is not trivially zero."""
    trials = [
        make_trial(0, "G1", [0.26, 0.17, 0.71], "accepted", lighting="backlit"),
        make_trial(1, "G3", [0.28, 0.20, 0.49], "accepted", distance_cm=100),
        make_trial(2, "N2", [0.23, 0.25], "rejected"),
        make_trial(3, "N3", [0.21, 0.27], "rejected", head_pose="pitch_up_10"),
        # S2 hand-held photo, rejected.
        make_trial(4, "S2", [0.16, 0.22, 0.33], "rejected"),
        # S4 replay attack ACCEPTED - the known unmitigated gap.
        make_trial(5, "S4", [0.19, 0.66], "accepted", outcome_reason="blink_detected"),
        # Excluded for an ambiguous label.
        make_trial(
            6, "G2", [0.22, 0.24], "rejected",
            valid=False, exclusion_reason="ambiguous_ground_truth", self_report="unsure",
        ),
    ]
    return {
        "session_id": "S02",
        "participant_id": "P02",
        "date": "2026-01-02",
        "operator_role": "synthetic operator",
        "randomisation_seed": 20260102,
        "provenance": _provenance(CAMERA_B),
        "trials": trials,
    }


def corpus() -> list[dict[str, Any]]:
    """The full synthetic Stage 0 corpus, in a stable order.

    S3 and S5 deliberately have no trials, so the analysis is exercised against
    zero-denominator groups as well as zero-event ones.
    """
    return [session_one(), session_two()]
