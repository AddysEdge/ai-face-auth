# B18 trial manifest — SCHEMA

> Defines the per-trial record the analysis consumes. **This file is the schema
> only.** Populated manifests contain participant-level data and must live
> outside the repository (plan §11.3).

One JSON object per session. Field names are normative — the analysis script
depends on them.

**The schema is a whitelist.** Every object has an exact allowed key set, and an
unknown field is a hard validation failure. A blacklist of forbidden names is a
guess about what a leak will be called; a whitelist cannot be out-guessed.

**`data_classification` is mandatory.** The Stage 0 tooling processes
`"synthetic_stage0"` and nothing else, so it cannot consume a real participant
manifest and emit a report describing the data as synthetic. Handling Stage 1 or
Stage 2 manifests requires a separate, owner-authorized, reviewed change.

## Session object

```jsonc
{
  "session_id": "S01",
  "participant_id": "P01",           // pseudonym only; never a name
  "date": "YYYY-MM-DD",              // a real calendar date
  "operator_role": "repository owner",
  "randomisation_seed": 123456,
  "data_classification": "synthetic_stage0",   // REQUIRED; Stage 0 accepts only this

  "provenance": {                    // plan §11.4 - safe to publish
    "faceauth_commit": "<40-hex>",
    "python_version": "3.12.x",
    "pinned_dependencies": { "ai-edge-litert": "2.2.0", "opencv-contrib-python": "5.0.0.93" },
    "face_landmarker_sha256": "<64-hex>",
    "liveness_config": {
      "blink_score_high": 0.40,
      "blink_score_low": 0.20,
      "enabled_challenges": ["BLINK"],
      "challenge_timeout_seconds": 5.0,
      "max_frames_per_challenge": 300,
      "min_face_continuity": 0.5
    },
    "camera_label": "<model / interface>",   // NOT a serial number
    "camera_resolution": "1280x720",
    "os_build": "<...>"
  },

  "trials": [ /* trial objects */ ]
}
```

## Trial object

```jsonc
{
  "trial_index": 7,
  "intended_type": "G1",             // G1|G2|G3|N1|N2|N3|S1|S2|S3|S4|S5
  "condition": {
    "lighting": "dim",               // bright_even|dim|side_light|backlit
    "head_pose": "frontal",          // frontal|yaw_left_15|yaw_right_15|pitch_up_10|pitch_down_10
    "distance_cm": 70,               // ~40 | ~70 | ~100
    "eyewear": "none"                // none|clear_glasses|tinted
  },

  "blink_scores": [0.24, 0.21, 0.63], // full per-frame series - REQUIRED (plan §8, §10.2)
  "turn_ratios": null,                // only when head-turn is under evaluation

  "max_blink_score": 0.63,            // derived; primary spoof outcome (plan §6.3)
  "min_blink_score": 0.21,

  "frames_captured": 74,
  "frames_with_face": 71,
  "face_continuity": 0.959,

  "attempt_outcome": "accepted",      // accepted|rejected - POST-continuity, as shipped
  "outcome_reason": "blink_detected",

  "ground_truth": "blink",            // blink|no_blink|spoof - assigned independently (§7.4)
  "self_report": "blinked",           // blinked|did_not_blink|unsure|n/a
  "label_source": "schedule+self_report",

  "valid": true,
  "exclusion_reason": null,           // no_face_detected|missed_prompt|operator_error|
                                      // software_error|ambiguous_ground_truth
  "retry_of_trial_index": null,       // at most one retry per cell (§7.3)
  "notes": ""                         // never identifying
}
```

## Empty observation series

A trial the detector never saw a face in has nothing to record. Fabricating a
score series to satisfy a validator would be inventing measurements, so
`blink_scores` **may be empty** — with `max_blink_score` and `min_blink_score`
both `null` — for an excluded trial whose reason is `no_face_detected` or
`software_error`. `no_face_detected` additionally requires `frames_with_face: 0`.
Every other trial must carry its series.

## Invariants the analysis must enforce

- `attempted == valid + excluded`; both reported (plan §9.2).
- `valid == false` ⟺ `exclusion_reason != null`.
- Excluded trials appear in **neither** numerator nor denominator.
- `max_blink_score` / `min_blink_score` equal the max/min of `blink_scores` —
  recomputed, not trusted.
- `attempt_outcome` is the post-continuity result, not `decide_blink` alone.
- `ground_truth` was never derived from any model output.
- A trial whose `intended_type` disagrees with `self_report` is
  `ambiguous_ground_truth` and excluded. A **valid** genuine-blink trial requires
  `self_report: "blinked"`, a valid genuine non-blink trial requires
  `"did_not_blink"`, and a valid spoof trial requires `"n/a"`.
- `attempt_outcome` and `outcome_reason` are **recomputed** from the observation
  series, the frame counts and the shipping decision rule
  (`max >= high` and `min <= low`, both inclusive, then the
  `min_face_continuity` override). A recorded outcome that contradicts the
  recomputation is rejected — an editable outcome field would otherwise let a
  manifest assert any FAR or FRR its author wanted.
- A retry may reference only an **excluded** original, must repeat the same
  `intended_type` and the same `condition` cell, must occur after it, and there
  may be at most one. Chains, cycles and cross-cell retries are rejected.
- No field anywhere contains a name, contact detail, serial number, or image —
  enforced by the whitelist, not by a list of forbidden names.

## Prohibited fields

`name`, `email`, `account`, `user_id`, `dob`, `serial`, `photo`, `frame`,
`image`, `video`, `file_path` to any media — and any free text that could
identify a person.
