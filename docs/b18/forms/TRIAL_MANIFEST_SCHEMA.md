# B18 trial manifest — SCHEMA

> Defines the per-trial record the analysis consumes. **This file is the schema
> only.** Populated manifests contain participant-level data and must live
> outside the repository (plan §11.3).

One JSON object per session. Field names are normative — the analysis script
depends on them.

## Session object

```jsonc
{
  "session_id": "S01",
  "participant_id": "P01",           // pseudonym only; never a name
  "date": "YYYY-MM-DD",
  "operator_role": "repository owner",
  "randomisation_seed": 123456,

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

## Invariants the analysis must enforce

- `attempted == valid + excluded`; both reported (plan §9.2).
- `valid == false` ⟺ `exclusion_reason != null`.
- Excluded trials appear in **neither** numerator nor denominator.
- `max_blink_score` / `min_blink_score` equal the max/min of `blink_scores` —
  recomputed, not trusted.
- `attempt_outcome` is the post-continuity result, not `decide_blink` alone.
- `ground_truth` was never derived from any model output.
- A trial whose `intended_type` disagrees with `self_report` is
  `ambiguous_ground_truth` and excluded.
- No field anywhere contains a name, contact detail, serial number, or image.

## Prohibited fields

`name`, `email`, `account`, `user_id`, `dob`, `serial`, `photo`, `frame`,
`image`, `video`, `file_path` to any media — and any free text that could
identify a person.
