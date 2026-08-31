"""Deterministic aggregate analysis of B18 Stage 0 session manifests.

Consumes validated, mutually-comparable manifests and produces a
machine-readable result plus a reviewable Markdown report. Every number is
recomputed from the trial records; nothing a manifest states as a summary is
trusted.

Three properties are load-bearing.

**Determinism.** Identical input produces byte-identical output. No timestamp
appears anywhere and every iteration is over a sorted sequence, so the
reproduction check plan §13 requires actually means something.

**Attack types are never pooled into a headline number.** S1-S3 (printed photo
and still display) and S4 (video replay) fail for different reasons and are
expected to behave differently - replay is a known unmitigated gap. Averaging
them manufactures a moderate-looking figure that describes no real attack. The
primary still-image margin is computed over S1-S3 only; replay is reported
beside it, never inside it.

**It cannot clear B18.** No code path emits a pass, a clearance, or an
approval. Only the recorded human security review can clear the criterion.
"""

from __future__ import annotations

import math
import statistics
from typing import Any

from scripts.b18_stage0.corpus import require_aggregatable, thresholds
from scripts.b18_stage0.schema import (
    GENUINE_BLINK_TYPES,
    GENUINE_NON_BLINK_TYPES,
    OTHER_SPOOF_TYPES,
    REPLAY_SPOOF_TYPES,
    SPOOF_TYPES,
    STILL_SPOOF_TYPES,
)

Z_95 = 1.959963984540054
ALPHA = 0.05

#: A rejected spoof is a "near miss" only when its peak sat just *below* the
#: threshold. A peak at or above it is not a near miss - it is an attack that
#: crossed the decision boundary, and is reported as such.
NEAR_MISS_WINDOW = 0.05

#: Boundary comparisons run on values that survived a JSON round trip, so an
#: exact ``==`` would be brittle.
BOUNDARY_TOLERANCE = 1e-9

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

POOLING_REFUSAL = (
    "FAR is reported per attack type and is deliberately NOT pooled. S1-S3 "
    "(printed photo, still display) and S4 (video replay) fail by different "
    "mechanisms, and replay is a known unmitigated gap - averaging them produces "
    "a number that describes no real attack and must not inform a B18 decision."
)


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> tuple[float, float] | None:
    """Wilson score interval. ``None`` when there is no denominator."""
    if trials <= 0:
        return None
    p = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def zero_event_upper_bound(trials: int, alpha: float = ALPHA) -> float | None:
    """Exact one-sided 95% upper bound when zero events were observed.

    ``1 - alpha**(1/n)``; the familiar "rule of three" is its approximation.
    Reported instead of "0%", which would assert a certainty the data lacks.
    """
    if trials <= 0:
        return None
    return 1.0 - alpha ** (1.0 / trials)


def _rate(numerator: int, denominator: int, *, participants: int, excluded: int) -> dict[str, Any]:
    """A rate never travels alone: counts, interval, scope and basis ride with it."""
    entry: dict[str, Any] = {
        "numerator": numerator,
        "denominator": denominator,
        "rate": None if denominator == 0 else round(numerator / denominator, 6),
        "wilson_95": None,
        "zero_event_upper_bound_95": None,
        "participants": participants,
        "excluded_trials_in_scope": excluded,
        "basis": "descriptive, trial-level",
        "not_a_population_rate": True,
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


def _valid(session: dict) -> list[dict]:
    return [t for t in session["trials"] if t.get("valid") is True]


def _of_types(trials: list[dict], types: tuple[str, ...]) -> list[dict]:
    return [t for t in trials if t["intended_type"] in types]


def _maxima(trials: list[dict]) -> list[float]:
    return [float(t["max_blink_score"]) for t in trials if t.get("max_blink_score") is not None]


def _margin_block(trials: list[dict], high: float, label: str, note: str) -> dict[str, Any]:
    """Margin analysis for one coherent family of attacks."""
    maxima = _maxima(trials)
    rejected_maxima = [
        float(t["max_blink_score"]) for t in trials
        if t["attempt_outcome"] == "rejected" and t.get("max_blink_score") is not None
    ]
    observed = max(maxima) if maxima else None
    # Near miss: below the threshold, but within the window of it. A peak at or
    # above the threshold is a crossing, not a near miss.
    near_miss = [
        m for m in rejected_maxima
        if 0.0 <= high - m <= NEAR_MISS_WINDOW + BOUNDARY_TOLERANCE
    ]
    crossings = [m for m in maxima if m >= high - BOUNDARY_TOLERANCE]
    return {
        "scope": label,
        "note": note,
        "high_threshold": high,
        "trials": len(trials),
        "max_blink_distribution": _distribution(maxima),
        "observed_max": None if observed is None else round(observed, 6),
        "margin_to_high": None if observed is None else round(high - observed, 6),
        "near_misses_within_0_05_below_high": len(near_miss),
        "threshold_crossings_at_or_above_high": len(crossings),
        "near_miss_definition": "rejected trial with 0 <= high - max(blink_score) <= 0.05",
    }


def analyse(sessions: list[dict], paths: list | None = None) -> dict[str, Any]:
    """Aggregate analysis. Sessions must already be schema-valid.

    Cross-session comparability is enforced here, before any number is computed:
    duplicates, conflicting thresholds, or differing code/model/dependencies
    raise rather than producing a note beside a wrong aggregate.
    """
    require_aggregatable(list(paths or []), sessions)
    high, low = thresholds(sessions)

    ordered = sorted(sessions, key=lambda s: (s["participant_id"], s["session_id"]))
    participants = sorted({s["participant_id"] for s in ordered})
    session_ids = sorted({s["session_id"] for s in ordered})
    cameras = sorted({s["provenance"]["camera_label"] for s in ordered})

    attempted = sum(len(s["trials"]) for s in ordered)
    all_valid = [t for s in ordered for t in _valid(s)]
    excluded = [t for s in ordered for t in s["trials"] if t.get("valid") is not True]

    exclusions: dict[str, int] = {}
    for trial in excluded:
        reason = trial.get("exclusion_reason") or "unspecified"
        exclusions[reason] = exclusions.get(reason, 0) + 1

    n_participants = len(participants)
    n_excluded = len(excluded)

    def frr(trials: list[dict], *, people: int, drops: int) -> dict[str, Any]:
        genuine = _of_types(trials, GENUINE_BLINK_TYPES)
        rejected = sum(1 for t in genuine if t["attempt_outcome"] == "rejected")
        return _rate(rejected, len(genuine), participants=people, excluded=drops)

    def correct_rejection(trials: list[dict], *, people: int, drops: int) -> dict[str, Any]:
        non_blink = _of_types(trials, GENUINE_NON_BLINK_TYPES)
        rejected = sum(1 for t in non_blink if t["attempt_outcome"] == "rejected")
        return _rate(rejected, len(non_blink), participants=people, excluded=drops)

    def far_by_type(trials: list[dict], *, people: int, drops: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for attack in SPOOF_TYPES:
            typed = _of_types(trials, (attack,))
            accepted = sum(1 for t in typed if t["attempt_outcome"] == "accepted")
            out[attack] = _rate(accepted, len(typed), participants=people, excluded=drops)
        return out

    # --- per-participant, before any aggregate ------------------------------
    per_participant = []
    for participant in participants:
        trials = [t for s in ordered if s["participant_id"] == participant for t in _valid(s)]
        drops = sum(
            1 for s in ordered if s["participant_id"] == participant
            for t in s["trials"] if t.get("valid") is not True
        )
        per_participant.append({
            "participant_id": participant,
            "sessions": sorted(s["session_id"] for s in ordered if s["participant_id"] == participant),
            "valid_trials": len(trials),
            "excluded_trials": drops,
            "frr": frr(trials, people=1, drops=drops),
            "correct_rejection_non_blink": correct_rejection(trials, people=1, drops=drops),
            "far_by_attack_type": far_by_type(trials, people=1, drops=drops),
            "still_image_margin": _margin_block(
                _of_types(trials, STILL_SPOOF_TYPES), high, "S1-S3", POOLING_REFUSAL
            ),
        })

    per_camera = []
    for camera in cameras:
        trials = [t for s in ordered if s["provenance"]["camera_label"] == camera for t in _valid(s)]
        drops = sum(
            1 for s in ordered if s["provenance"]["camera_label"] == camera
            for t in s["trials"] if t.get("valid") is not True
        )
        people = len({
            s["participant_id"] for s in ordered if s["provenance"]["camera_label"] == camera
        })
        per_camera.append({
            "camera_label": camera,
            "valid_trials": len(trials),
            "excluded_trials": drops,
            "participants": people,
            "frr": frr(trials, people=people, drops=drops),
            "far_by_attack_type": far_by_type(trials, people=people, drops=drops),
            "still_image_margin": _margin_block(
                _of_types(trials, STILL_SPOOF_TYPES), high, "S1-S3", POOLING_REFUSAL
            ),
        })

    # --- per attack type ----------------------------------------------------
    per_attack_type = []
    for attack in SPOOF_TYPES:
        typed = _of_types(all_valid, (attack,))
        accepted = sum(1 for t in typed if t["attempt_outcome"] == "accepted")
        family = (
            "still_image" if attack in STILL_SPOOF_TYPES
            else "video_replay" if attack in REPLAY_SPOOF_TYPES
            else "other"
        )
        per_attack_type.append({
            "type": attack,
            "family": family,
            "far": _rate(accepted, len(typed), participants=n_participants, excluded=n_excluded),
            "margin": _margin_block(typed, high, attack, f"{attack} only"),
        })

    still_trials = _of_types(all_valid, STILL_SPOOF_TYPES)
    replay_trials = _of_types(all_valid, REPLAY_SPOOF_TYPES)
    other_trials = _of_types(all_valid, OTHER_SPOOF_TYPES)

    # --- threshold-crossing evidence, both boundaries inclusive -------------
    scored = [t for t in all_valid if t.get("max_blink_score") is not None]
    reached_high = [t for t in scored if float(t["max_blink_score"]) >= high - BOUNDARY_TOLERANCE]
    reached_low = [t for t in scored if float(t["min_blink_score"]) <= low + BOUNDARY_TOLERANCE]
    crossing = {
        "high_threshold": high,
        "low_threshold": low,
        "comparison": "max(scores) >= high AND min(scores) <= low; both inclusive",
        "boundary_tolerance": BOUNDARY_TOLERANCE,
        "trials_reaching_high": len(reached_high),
        "trials_reaching_low": len(reached_low),
        "trials_at_high_boundary": sum(
            1 for t in scored if abs(float(t["max_blink_score"]) - high) <= BOUNDARY_TOLERANCE
        ),
        "trials_at_low_boundary": sum(
            1 for t in scored if abs(float(t["min_blink_score"]) - low) <= BOUNDARY_TOLERANCE
        ),
        "both_boundaries_exercised": bool(reached_high) and bool(reached_low),
    }

    coverage: dict[str, dict[str, int]] = {}
    for factor in ("lighting", "head_pose", "distance_cm", "eyewear"):
        counts: dict[str, int] = {}
        for trial in all_valid:
            key = str(trial["condition"][factor])
            counts[key] = counts.get(key, 0) + 1
        coverage[factor] = dict(sorted(counts.items()))
    coverage["camera_label"] = dict(sorted(
        (camera, sum(len(_valid(s)) for s in ordered if s["provenance"]["camera_label"] == camera))
        for camera in cameras
    ))

    provenance = sorted(
        ({
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
            "data_classification": s["data_classification"],
        } for s in ordered),
        key=lambda entry: entry["session_id"],
    )

    return {
        "banner": STAGE0_BANNER,
        "b18_status": "OPEN",
        "clears_b18": False,
        "authorizes_capture": False,
        "data_classification": "synthetic_stage0",
        "statistical_basis": CLUSTERING_WARNING,
        "pooling_policy": POOLING_REFUSAL,
        "counts": {
            "participants": n_participants,
            "participant_ids": participants,
            "sessions": len(session_ids),
            "session_ids": session_ids,
            "cameras": len(cameras),
            "trials_attempted": attempted,
            "trials_valid": len(all_valid),
            "trials_excluded": n_excluded,
        },
        "exclusions_by_reason": dict(sorted(exclusions.items())),
        "per_participant": per_participant,
        "per_camera": per_camera,
        "aggregate": {
            "frr_genuine_blink": frr(all_valid, people=n_participants, drops=n_excluded),
            "correct_rejection_genuine_non_blink": correct_rejection(
                all_valid, people=n_participants, drops=n_excluded
            ),
            "far_by_attack_type": far_by_type(
                all_valid, people=n_participants, drops=n_excluded
            ),
            "far_pooled_across_attack_types": None,
            "why_no_pooled_far": POOLING_REFUSAL,
        },
        "per_attack_type": per_attack_type,
        "still_image_margin": _margin_block(
            still_trials, high, "S1-S3 (printed photo, still display)",
            "The primary spoof outcome. Rejection of a still image hinges on "
            "max(blink_score) failing to reach the high threshold; the margin is "
            "the finding, not the rate.",
        ),
        "video_replay": {
            "scope": "S4",
            "trials": len(replay_trials),
            "far": _rate(
                sum(1 for t in replay_trials if t["attempt_outcome"] == "accepted"),
                len(replay_trials), participants=n_participants, excluded=n_excluded,
            ),
            "max_blink_distribution": _distribution(_maxima(replay_trials)),
            "note": (
                "Video replay is a KNOWN UNMITIGATED GAP (docs/THREAT_MODEL.md §4). "
                "It is expected to be accepted, is reported separately, and is never "
                "folded into the still-image margin or any pooled rate."
            ),
        },
        "other_spoof": {
            "scope": "S5",
            "trials": len(other_trials),
            "max_blink_distribution": _distribution(_maxima(other_trials)),
            "note": "Reported separately; not part of the S1-S3 still-image margin.",
        },
        "distributions": {
            "genuine_blink_max": _distribution(_maxima(_of_types(all_valid, GENUINE_BLINK_TYPES))),
            "genuine_blink_min": _distribution([
                float(t["min_blink_score"]) for t in _of_types(all_valid, GENUINE_BLINK_TYPES)
                if t.get("min_blink_score") is not None
            ]),
            "genuine_non_blink_max": _distribution(
                _maxima(_of_types(all_valid, GENUINE_NON_BLINK_TYPES))
            ),
        },
        "threshold_crossing": crossing,
        "condition_coverage": coverage,
        "provenance": provenance,
    }


# ----------------------------------------------------------------- rendering


def md_escape(value: Any) -> str:
    """Escape a value for a Markdown table cell.

    Validation already rejects control characters, newlines and pipes in
    report-visible fields; this is the second layer, so a future schema
    relaxation cannot silently turn a manifest value into table syntax.
    """
    text = str(value)
    text = text.replace("\\", "\\\\").replace("|", "\\|")
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return "".join(ch if ch.isprintable() or ch == " " else " " for ch in text)


def _fmt_rate(entry: dict[str, Any]) -> str:
    if entry["denominator"] == 0:
        return "n/a (0 trials)"
    text = f"{entry['numerator']}/{entry['denominator']} = {entry['rate']:.4f}"
    if entry["wilson_95"]:
        low, high = entry["wilson_95"]
        text += f" (Wilson 95% [{low:.4f}, {high:.4f}])"
    if entry["zero_event_upper_bound_95"] is not None:
        text += f"; zero observed, 95% upper bound {entry['zero_event_upper_bound_95']:.4f}"
    text += f" [n_participants={entry['participants']}, excluded={entry['excluded_trials_in_scope']}]"
    return text


def _fmt_distribution(dist: dict[str, Any]) -> str:
    if dist["n"] == 0:
        return "n=0"
    return (
        f"n={dist['n']}  min={dist['min']:.4f}  "
        f"median={dist['median']:.4f}  max={dist['max']:.4f}"
    )


def _fmt_margin(block: dict[str, Any]) -> list[str]:
    lines = [
        f"- Scope: **{md_escape(block['scope'])}** ({block['trials']} valid trials)",
        f"- High threshold: **{block['high_threshold']}**",
    ]
    observed = block["observed_max"]
    lines.append(f"- Observed max: **{'n/a' if observed is None else f'{observed:.4f}'}**")
    gap = block["margin_to_high"]
    lines.append(f"- Margin to high: **{'n/a' if gap is None else f'{gap:.4f}'}**")
    lines.append(
        f"- Near misses (rejected, within 0.05 **below** high): "
        f"**{block['near_misses_within_0_05_below_high']}**"
    )
    lines.append(
        f"- Threshold crossings (max at or above high): "
        f"**{block['threshold_crossings_at_or_above_high']}**"
    )
    lines.append(f"- Distribution: {_fmt_distribution(block['max_blink_distribution'])}")
    return lines


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
    add(f"- Data classification: **{md_escape(result['data_classification'])}**")
    add("")
    add("## Statistical basis - read before any number below")
    add("")
    add(result["statistical_basis"])
    add("")
    add(f"> **On pooling:** {result['pooling_policy']}")
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
            add(f"| {md_escape(reason)} | {count} |")
    else:
        add("None.")
    add("")

    add("## Per-participant results (primary)")
    add("")
    add("| Participant | Sessions | Valid | Excluded | FRR | Correct rejection (N*) |")
    add("|---|---|---|---|---|---|")
    for entry in result["per_participant"]:
        add(
            f"| {md_escape(entry['participant_id'])} | "
            f"{md_escape(', '.join(entry['sessions']))} | {entry['valid_trials']} | "
            f"{entry['excluded_trials']} | {_fmt_rate(entry['frr'])} | "
            f"{_fmt_rate(entry['correct_rejection_non_blink'])} |"
        )
    add("")
    add("### FAR per attack type, per participant")
    add("")
    add("| Participant | " + " | ".join(SPOOF_TYPES) + " |")
    add("|---" * (len(SPOOF_TYPES) + 1) + "|")
    for entry in result["per_participant"]:
        cells = " | ".join(_fmt_rate(entry["far_by_attack_type"][a]) for a in SPOOF_TYPES)
        add(f"| {md_escape(entry['participant_id'])} | {cells} |")
    add("")

    add("## Per-camera results")
    add("")
    add("| Camera | Participants | Valid | Excluded | FRR |")
    add("|---|---|---|---|---|")
    for entry in result["per_camera"]:
        add(
            f"| {md_escape(entry['camera_label'])} | {entry['participants']} | "
            f"{entry['valid_trials']} | {entry['excluded_trials']} | "
            f"{_fmt_rate(entry['frr'])} |"
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
    add("")
    add("### FAR per attack type")
    add("")
    add("| Type | Family | FAR |")
    add("|---|---|---|")
    for entry in result["per_attack_type"]:
        add(
            f"| {md_escape(entry['type'])} | {md_escape(entry['family'])} | "
            f"{_fmt_rate(entry['far'])} |"
        )
    add("")
    add(f"> **No pooled FAR is reported.** {aggregate['why_no_pooled_far']}")
    add("")

    add("## Still-image spoof margin (S1-S3) - the primary outcome")
    add("")
    for line in _fmt_margin(result["still_image_margin"]):
        add(line)
    add("")
    add(f"> {result['still_image_margin']['note']}")
    add("")

    add("## Video replay (S4) - reported separately")
    add("")
    replay = result["video_replay"]
    add(f"- Trials: {replay['trials']}")
    add(f"- FAR: {_fmt_rate(replay['far'])}")
    add(f"- max(blink): {_fmt_distribution(replay['max_blink_distribution'])}")
    add("")
    add(f"> {replay['note']}")
    add("")

    add("## Threshold crossing")
    add("")
    crossing = result["threshold_crossing"]
    add(f"- Decision: `{crossing['comparison']}`")
    add(f"- Comparison tolerance: {crossing['boundary_tolerance']}")
    add(f"- Trials reaching high ({crossing['high_threshold']}): {crossing['trials_reaching_high']}")
    add(f"- Trials reaching low ({crossing['low_threshold']}): {crossing['trials_reaching_low']}")
    add(f"- Trials at the high boundary: {crossing['trials_at_high_boundary']}")
    add(f"- Trials at the low boundary: {crossing['trials_at_low_boundary']}")
    add(f"- Both boundaries exercised: **{crossing['both_boundaries_exercised']}**")
    add("")

    add("## Condition coverage")
    add("")
    for factor, counts_by_level in result["condition_coverage"].items():
        levels = ", ".join(
            f"{md_escape(level)} ({count})" for level, count in counts_by_level.items()
        )
        add(f"- **{md_escape(factor)}**: {levels if levels else 'none'}")
    add("")

    add("## Provenance")
    add("")
    add("| Session | Commit | Python | Model SHA-256 | Camera | Seed | Classification |")
    add("|---|---|---|---|---|---|---|")
    for entry in result["provenance"]:
        add(
            f"| {md_escape(entry['session_id'])} | `{md_escape(entry['faceauth_commit'][:12])}` | "
            f"{md_escape(entry['python_version'])} | "
            f"`{md_escape(entry['face_landmarker_sha256'][:12])}` | "
            f"{md_escape(entry['camera_label'])} | {entry['randomisation_seed']} | "
            f"{md_escape(entry['data_classification'])} |"
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
