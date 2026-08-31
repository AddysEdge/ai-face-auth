"""Deterministic aggregate analysis of B18 session manifests.

Consumes validated manifests and produces a machine-readable result plus a
reviewable Markdown report. Every number is recomputed from the trial records;
nothing stated in a manifest is trusted as a summary.

Two properties this module treats as load-bearing:

**Determinism.** Identical input produces byte-identical output. There is no
timestamp anywhere in the result, and every iteration is over a sorted sequence.
A report that changed between runs could not be used to check that an analysis
was reproduced, which plan §13 requires.

**It cannot clear B18.** There is no code path that emits a pass, a clearance,
or an approval. The analysis reports numbers and their limitations; only the
recorded human security review in `docs/b18/forms/SECURITY_REVIEW_CHECKLIST.md`
can clear the criterion.
"""

from __future__ import annotations

import math
import statistics
from typing import Any

from scripts.b18_stage0.schema import (
    GENUINE_BLINK_TYPES,
    GENUINE_NON_BLINK_TYPES,
    SPOOF_TYPES,
)

Z_95 = 1.959963984540054  # two-sided 95%
ALPHA = 0.05
NEAR_MISS_WINDOW = 0.05  # plan §9.3: count spoof maxima within this of the high threshold

# Reproduced verbatim in every artefact this module writes.
STAGE0_BANNER = (
    "SYNTHETIC STAGE 0 EVIDENCE ONLY - B18 REMAINS OPEN. "
    "No real-input validation occurred. No population or security-performance "
    "claim is supported. This report cannot authorize Stage 1, Stage 2, or Phase 3."
)

CLUSTERING_WARNING = (
    "Every rate and interval below is DESCRIPTIVE and TRIAL-LEVEL: it summarises "
    "the trials analysed, nothing more. Trials are clustered within a small number "
    "of non-randomly-chosen participants and attack instances, so these intervals "
    "UNDERSTATE uncertainty about people and attacks. They are not population "
    "bounds, they do not establish generalisation, and they certify nothing."
)


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> tuple[float, float] | None:
    """Wilson score interval. ``None`` when there is no denominator.

    Preferred over the normal approximation because it stays inside [0, 1] and
    behaves at small n and at rates near 0 - which is where this study lives.
    """
    if trials <= 0:
        return None
    p = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def zero_event_upper_bound(trials: int, alpha: float = ALPHA) -> float | None:
    """One-sided 95% upper bound when zero events were observed.

    Exact form ``1 - alpha**(1/n)``; the familiar "rule of three" (3/n) is its
    approximation. Reported instead of "0%", which would assert a certainty the
    data cannot support.
    """
    if trials <= 0:
        return None
    return 1.0 - alpha ** (1.0 / trials)


def _rate(numerator: int, denominator: int) -> dict[str, Any]:
    """A rate always travels with its counts and its interval."""
    entry: dict[str, Any] = {
        "numerator": numerator,
        "denominator": denominator,
        "rate": None if denominator == 0 else round(numerator / denominator, 6),
        "wilson_95": None,
        "zero_event_upper_bound_95": None,
        "basis": "descriptive, trial-level",
    }
    interval = wilson_interval(numerator, denominator)
    if interval is not None:
        entry["wilson_95"] = [round(interval[0], 6), round(interval[1], 6)]
    if denominator > 0 and numerator == 0:
        bound = zero_event_upper_bound(denominator)
        entry["zero_event_upper_bound_95"] = None if bound is None else round(bound, 6)
    return entry


def _distribution(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"n": 0, "min": None, "median": None, "max": None}
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "min": round(ordered[0], 6),
        "median": round(statistics.median(ordered), 6),
        "max": round(ordered[-1], 6),
    }


def _valid_trials(session: dict) -> list[dict]:
    """Excluded trials enter neither a numerator nor a denominator."""
    return [t for t in session["trials"] if t.get("valid") is True]


def _thresholds(sessions: list[dict]) -> tuple[float, float, list[str]]:
    """Thresholds come from the manifests, and must agree across them."""
    notes: list[str] = []
    pairs = sorted(
        {
            (
                float(s["provenance"]["liveness_config"]["blink_score_high"]),
                float(s["provenance"]["liveness_config"]["blink_score_low"]),
            )
            for s in sessions
        }
    )
    if len(pairs) != 1:
        notes.append(
            f"Sessions disagree on thresholds: {pairs}. Rates computed against "
            f"different thresholds are not comparable; the first pair is used and "
            f"this disagreement must be resolved before the report is relied on."
        )
    return pairs[0][0], pairs[0][1], notes


def analyse(sessions: list[dict]) -> dict[str, Any]:
    """Aggregate analysis. Input must already be schema-valid."""
    if not sessions:
        raise ValueError("no sessions to analyse")

    ordered_sessions = sorted(sessions, key=lambda s: (s["participant_id"], s["session_id"]))
    high, low, threshold_notes = _thresholds(ordered_sessions)

    participants = sorted({s["participant_id"] for s in ordered_sessions})
    session_ids = sorted({s["session_id"] for s in ordered_sessions})
    cameras = sorted({s["provenance"]["camera_label"] for s in ordered_sessions})

    attempted = sum(len(s["trials"]) for s in ordered_sessions)
    all_valid = [t for s in ordered_sessions for t in _valid_trials(s)]
    excluded_trials = [
        t for s in ordered_sessions for t in s["trials"] if t.get("valid") is not True
    ]

    exclusions: dict[str, int] = {}
    for trial in excluded_trials:
        reason = trial.get("exclusion_reason") or "unspecified"
        exclusions[reason] = exclusions.get(reason, 0) + 1

    def group(trials: list[dict], types: tuple[str, ...]) -> list[dict]:
        return [t for t in trials if t["intended_type"] in types]

    def frr(trials: list[dict]) -> dict[str, Any]:
        genuine = group(trials, GENUINE_BLINK_TYPES)
        rejected = sum(1 for t in genuine if t["attempt_outcome"] == "rejected")
        return _rate(rejected, len(genuine))

    def far(trials: list[dict], types: tuple[str, ...]) -> dict[str, Any]:
        spoofs = group(trials, types)
        accepted = sum(1 for t in spoofs if t["attempt_outcome"] == "accepted")
        return _rate(accepted, len(spoofs))

    def correct_rejection(trials: list[dict]) -> dict[str, Any]:
        non_blink = group(trials, GENUINE_NON_BLINK_TYPES)
        rejected = sum(1 for t in non_blink if t["attempt_outcome"] == "rejected")
        return _rate(rejected, len(non_blink))

    # --- per-participant, reported before any aggregate ---------------------
    per_participant = []
    for participant in participants:
        trials = [
            t for s in ordered_sessions if s["participant_id"] == participant
            for t in _valid_trials(s)
        ]
        per_participant.append(
            {
                "participant_id": participant,
                "sessions": sorted(
                    s["session_id"] for s in ordered_sessions
                    if s["participant_id"] == participant
                ),
                "valid_trials": len(trials),
                "frr": frr(trials),
                "far_all_spoof_types": far(trials, SPOOF_TYPES),
                "correct_rejection_non_blink": correct_rejection(trials),
                "spoof_max_blink": _distribution(
                    [float(t["max_blink_score"]) for t in group(trials, SPOOF_TYPES)]
                ),
            }
        )

    per_camera = []
    for camera in cameras:
        trials = [
            t for s in ordered_sessions if s["provenance"]["camera_label"] == camera
            for t in _valid_trials(s)
        ]
        per_camera.append(
            {
                "camera_label": camera,
                "valid_trials": len(trials),
                "frr": frr(trials),
                "far_all_spoof_types": far(trials, SPOOF_TYPES),
                "spoof_max_blink": _distribution(
                    [float(t["max_blink_score"]) for t in group(trials, SPOOF_TYPES)]
                ),
            }
        )

    # --- spoof margin: the primary outcome (plan §6.3) ----------------------
    spoof_trials = group(all_valid, SPOOF_TYPES)
    spoof_maxima = [float(t["max_blink_score"]) for t in spoof_trials]
    observed_max = max(spoof_maxima) if spoof_maxima else None
    near_miss = sum(1 for m in spoof_maxima if m >= high - NEAR_MISS_WINDOW)

    per_attack_type = []
    for attack in SPOOF_TYPES:
        typed = group(all_valid, (attack,))
        if not typed:
            per_attack_type.append(
                {
                    "type": attack, "far": _rate(0, 0),
                    "max_blink": _distribution([]),
                    "margin_to_high": None,
                    "within_0_05_of_high": 0,
                }
            )
            continue
        maxima = [float(t["max_blink_score"]) for t in typed]
        per_attack_type.append(
            {
                "type": attack,
                "far": far(all_valid, (attack,)),
                "max_blink": _distribution(maxima),
                "margin_to_high": round(high - max(maxima), 6),
                "within_0_05_of_high": sum(1 for m in maxima if m >= high - NEAR_MISS_WINDOW),
            }
        )

    # --- threshold-crossing evidence, both boundaries inclusive -------------
    reached_high = [t for t in all_valid if float(t["max_blink_score"]) >= high]
    reached_low = [t for t in all_valid if float(t["min_blink_score"]) <= low]
    crossing = {
        "high_threshold": high,
        "low_threshold": low,
        "comparison": "max(scores) >= high AND min(scores) <= low; both inclusive",
        "trials_reaching_high": len(reached_high),
        "trials_reaching_low": len(reached_low),
        "trials_exactly_at_high": sum(
            1 for t in all_valid if float(t["max_blink_score"]) == high
        ),
        "trials_exactly_at_low": sum(
            1 for t in all_valid if float(t["min_blink_score"]) == low
        ),
        "both_boundaries_exercised": bool(reached_high) and bool(reached_low),
    }

    # --- condition coverage --------------------------------------------------
    coverage: dict[str, dict[str, int]] = {}
    for factor in ("lighting", "head_pose", "distance_cm", "eyewear"):
        counts: dict[str, int] = {}
        for trial in all_valid:
            key = str(trial["condition"][factor])
            counts[key] = counts.get(key, 0) + 1
        coverage[factor] = dict(sorted(counts.items()))
    coverage["camera_label"] = dict(
        sorted(
            (
                camera,
                sum(
                    len(_valid_trials(s)) for s in ordered_sessions
                    if s["provenance"]["camera_label"] == camera
                ),
            )
            for camera in cameras
        )
    )

    provenance = sorted(
        (
            {
                "session_id": s["session_id"],
                "faceauth_commit": s["provenance"]["faceauth_commit"],
                "python_version": s["provenance"]["python_version"],
                "face_landmarker_sha256": s["provenance"]["face_landmarker_sha256"],
                "camera_label": s["provenance"]["camera_label"],
                "camera_resolution": s["provenance"]["camera_resolution"],
                "os_build": s["provenance"]["os_build"],
                "pinned_dependencies": dict(sorted(s["provenance"]["pinned_dependencies"].items())),
                "liveness_config": dict(sorted(s["provenance"]["liveness_config"].items())),
                "randomisation_seed": s["randomisation_seed"],
            }
            for s in ordered_sessions
        ),
        key=lambda entry: entry["session_id"],
    )

    return {
        "banner": STAGE0_BANNER,
        "b18_status": "OPEN",
        "clears_b18": False,
        "authorizes_capture": False,
        "statistical_basis": CLUSTERING_WARNING,
        "notes": threshold_notes,
        "counts": {
            "participants": len(participants),
            "participant_ids": participants,
            "sessions": len(session_ids),
            "session_ids": session_ids,
            "cameras": len(cameras),
            "trials_attempted": attempted,
            "trials_valid": len(all_valid),
            "trials_excluded": len(excluded_trials),
        },
        "exclusions_by_reason": dict(sorted(exclusions.items())),
        "per_participant": per_participant,
        "per_camera": per_camera,
        "aggregate": {
            "frr_genuine_blink": frr(all_valid),
            "correct_rejection_genuine_non_blink": correct_rejection(all_valid),
            "far_all_spoof_types_pooled": far(all_valid, SPOOF_TYPES),
            "pooling_caveat": (
                "Pooling attack types hides the ones expected to succeed - notably "
                "S4 video replay. Read the per-attack-type table, not this number."
            ),
        },
        "per_attack_type": per_attack_type,
        "distributions": {
            "genuine_blink_max": _distribution(
                [float(t["max_blink_score"]) for t in group(all_valid, GENUINE_BLINK_TYPES)]
            ),
            "genuine_blink_min": _distribution(
                [float(t["min_blink_score"]) for t in group(all_valid, GENUINE_BLINK_TYPES)]
            ),
            "genuine_non_blink_max": _distribution(
                [float(t["max_blink_score"]) for t in group(all_valid, GENUINE_NON_BLINK_TYPES)]
            ),
            "spoof_max": _distribution(spoof_maxima),
        },
        "spoof_margin": {
            "high_threshold": high,
            "observed_max_over_all_spoofs": None if observed_max is None else round(observed_max, 6),
            "margin_to_high": None if observed_max is None else round(high - observed_max, 6),
            "within_0_05_of_high": near_miss,
            "why_this_matters": (
                "Spoof rejection hinges on max(blink_score) failing to reach the high "
                "threshold. A far of zero with a thin margin is not evidence of spoof "
                "resistance; the margin is the finding, not the rate."
            ),
        },
        "threshold_crossing": crossing,
        "condition_coverage": coverage,
        "provenance": provenance,
    }


def _fmt_rate(entry: dict[str, Any]) -> str:
    if entry["denominator"] == 0:
        return "n/a (0 trials)"
    text = f"{entry['numerator']}/{entry['denominator']} = {entry['rate']:.4f}"
    if entry["wilson_95"]:
        low, high = entry["wilson_95"]
        text += f" (Wilson 95% [{low:.4f}, {high:.4f}])"
    if entry["zero_event_upper_bound_95"] is not None:
        text += f"; zero observed, one-sided 95% upper bound {entry['zero_event_upper_bound_95']:.4f}"
    return text


def _fmt_distribution(dist: dict[str, Any]) -> str:
    if dist["n"] == 0:
        return "n=0"
    return (
        f"n={dist['n']}  min={dist['min']:.4f}  "
        f"median={dist['median']:.4f}  max={dist['max']:.4f}"
    )


def render_markdown(result: dict[str, Any]) -> str:
    """Aggregate report. Contains no participant-level score series by design."""
    counts = result["counts"]
    lines: list[str] = []
    add = lines.append

    add("# B18 Stage 0 analysis report")
    add("")
    add(f"> **{result['banner']}**")
    add("")
    add(f"- B18 status: **{result['b18_status']}**")
    add(f"- Clears B18: **{result['clears_b18']}**")
    add(f"- Authorizes capture: **{result['authorizes_capture']}**")
    add("")
    add("## Statistical basis - read before any number below")
    add("")
    add(result["statistical_basis"])
    add("")
    for note in result["notes"]:
        add(f"> **Note:** {note}")
    if result["notes"]:
        add("")

    add("## Counts")
    add("")
    add("| | |")
    add("|---|---|")
    add(f"| Participants | **{counts['participants']}** |")
    add(f"| Sessions | {counts['sessions']} |")
    add(f"| Cameras | {counts['cameras']} |")
    add(f"| Trials attempted | {counts['trials_attempted']} |")
    add(f"| Trials valid | {counts['trials_valid']} |")
    add(f"| Trials excluded | {counts['trials_excluded']} |")
    add("")
    add("The **participant** count, not the trial count, is the sample size for")
    add("anything said about people.")
    add("")

    add("### Exclusions by reason")
    add("")
    if result["exclusions_by_reason"]:
        add("| Reason | Count |")
        add("|---|---|")
        for reason, count in result["exclusions_by_reason"].items():
            add(f"| {reason} | {count} |")
    else:
        add("None.")
    add("")

    add("## Per-participant results (primary)")
    add("")
    add("| Participant | Sessions | Valid trials | FRR | FAR (all spoof types) | Correct rejection (N*) | Spoof max(blink) |")
    add("|---|---|---|---|---|---|---|")
    for entry in result["per_participant"]:
        add(
            f"| {entry['participant_id']} | {', '.join(entry['sessions'])} | "
            f"{entry['valid_trials']} | {_fmt_rate(entry['frr'])} | "
            f"{_fmt_rate(entry['far_all_spoof_types'])} | "
            f"{_fmt_rate(entry['correct_rejection_non_blink'])} | "
            f"{_fmt_distribution(entry['spoof_max_blink'])} |"
        )
    add("")

    add("## Per-camera results")
    add("")
    add("| Camera | Valid trials | FRR | FAR (all spoof types) | Spoof max(blink) |")
    add("|---|---|---|---|---|")
    for entry in result["per_camera"]:
        add(
            f"| {entry['camera_label']} | {entry['valid_trials']} | "
            f"{_fmt_rate(entry['frr'])} | {_fmt_rate(entry['far_all_spoof_types'])} | "
            f"{_fmt_distribution(entry['spoof_max_blink'])} |"
        )
    add("")

    add("## Aggregate (secondary to the per-participant table)")
    add("")
    aggregate = result["aggregate"]
    add(f"- FRR, genuine blink: {_fmt_rate(aggregate['frr_genuine_blink'])}")
    add(
        "- Correct rejection, genuine non-blink: "
        f"{_fmt_rate(aggregate['correct_rejection_genuine_non_blink'])}"
    )
    add(f"- FAR, all spoof types pooled: {_fmt_rate(aggregate['far_all_spoof_types_pooled'])}")
    add("")
    add(f"> {aggregate['pooling_caveat']}")
    add("")

    add("## Per attack type")
    add("")
    add("| Type | FAR | max(blink) | Margin to high | Within 0.05 of high |")
    add("|---|---|---|---|---|")
    for entry in result["per_attack_type"]:
        margin = "n/a" if entry["margin_to_high"] is None else f"{entry['margin_to_high']:.4f}"
        add(
            f"| {entry['type']} | {_fmt_rate(entry['far'])} | "
            f"{_fmt_distribution(entry['max_blink'])} | {margin} | "
            f"{entry['within_0_05_of_high']} |"
        )
    add("")

    add("## Spoof margin - the primary outcome")
    add("")
    margin_block = result["spoof_margin"]
    add(f"- High threshold: **{margin_block['high_threshold']}**")
    observed = margin_block["observed_max_over_all_spoofs"]
    add(f"- Observed max over all spoof trials: **{'n/a' if observed is None else f'{observed:.4f}'}**")
    gap = margin_block["margin_to_high"]
    add(f"- Margin to the high threshold: **{'n/a' if gap is None else f'{gap:.4f}'}**")
    add(f"- Spoof trials within 0.05 of the high threshold: **{margin_block['within_0_05_of_high']}**")
    add("")
    add(f"> {margin_block['why_this_matters']}")
    add("")

    add("## Threshold crossing")
    add("")
    crossing = result["threshold_crossing"]
    add(f"- Decision: `{crossing['comparison']}`")
    add(f"- Trials reaching the high threshold ({crossing['high_threshold']}): {crossing['trials_reaching_high']}")
    add(f"- Trials reaching the low threshold ({crossing['low_threshold']}): {crossing['trials_reaching_low']}")
    add(f"- Trials exactly at the high boundary: {crossing['trials_exactly_at_high']}")
    add(f"- Trials exactly at the low boundary: {crossing['trials_exactly_at_low']}")
    add(f"- Both boundaries exercised: **{crossing['both_boundaries_exercised']}**")
    add("")

    add("## Condition coverage")
    add("")
    for factor, counts_by_level in result["condition_coverage"].items():
        levels = ", ".join(f"{level} ({count})" for level, count in counts_by_level.items())
        add(f"- **{factor}**: {levels if levels else 'none'}")
    add("")

    add("## Provenance")
    add("")
    add("| Session | Commit | Python | Model SHA-256 | Camera | Seed |")
    add("|---|---|---|---|---|---|")
    for entry in result["provenance"]:
        add(
            f"| {entry['session_id']} | `{entry['faceauth_commit'][:12]}` | "
            f"{entry['python_version']} | `{entry['face_landmarker_sha256'][:12]}` | "
            f"{entry['camera_label']} | {entry['randomisation_seed']} |"
        )
    add("")
    add("---")
    add("")
    add(f"**{result['banner']}**")
    add("")
    add("Only the recorded human security review in")
    add("`docs/b18/forms/SECURITY_REVIEW_CHECKLIST.md`, against completed evidence,")
    add("can clear B18. This tool never marks it cleared.")
    return "\n".join(lines) + "\n"
