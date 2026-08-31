# Phase 2.5: resolving B17 — network-silent liveness

**Status:** complete. **B17 is cleared.** The liveness path runs on a
telemetry-free runtime, the `mediapipe` dependency is gone, the allowlist is
empty, and 20 fresh-process FULL-mode network checks observed zero external
endpoints. The corrections listed in section 1 are applied; the limitations in
section 6 stand.

The blocker, restated from `docs/PHASE2_ACCEPTANCE_CRITERIA.md`:

> **B17** — The verification path makes no outbound network connections.

The bundled `mediapipe==1.0.1` wheel opens a TLS connection to
`play.googleapis.com` and uploads usage telemetry on session teardown. Upstream
provides no supported way to disable it. This is documented and intended
behaviour, characterised in `docs/PRIVACY_NETWORK_AUDIT.md`. ADR-0005 records
two candidate resolutions:

- **Option A** — replace the MediaPipe *runtime* with a telemetry-free one
  (`ai-edge-litert`), driving the same pinned model weights through a
  reimplementation of the published pipeline.
- **Option B** — build MediaPipe from pinned public source and verify the
  resulting artifact carries no telemetry.

---

## 1. Corrections to the previous revision of this document

The previous revision concluded that **"Option A is contradicted by
measurement."** That conclusion is **withdrawn**. It was reached from a replica
that did not implement MediaPipe's published CPU preprocessing path, so it did
not measure Option A. Four specific statements are corrected:

| # | Previous claim | Correction |
|---|---|---|
| 1 | Option A is "contradicted by measurement". | **Withdrawn.** One replica failing shows only that *that replica* failed. It is not evidence about Option A as an approach. The replica had a preprocessing defect (section 3) and a blendshape input defect (section 4); with both fixed, agreement improves by roughly an order of magnitude. |
| 2 | The error "persists with a known-correct ROI". | **Withdrawn.** The ROI used was MediaPipe's *landmark-derived next-frame* ROI, which is not the ROI the graph used for the inference being compared. That is the detector-produced input ROI. No ROI in these experiments was captured from the actual graph edge, so none may be called known-correct. |
| 3 | "The blendshape stage is bit-exact — agrees to five decimal places." | **Self-contradictory; corrected.** Bit identity and five-decimal agreement are different claims. What was measured is *agreement to five decimal places*. Bit identity was not tested and is not claimed. |
| 4 | Zero telemetry strings in the LiteRT binaries shows it contacts no endpoints. | **Downgraded to supporting evidence.** A string scan is not proof of absence. Only a healthy OS-level runtime observation can support that claim; the 20 runs in section 7 are that observation, and they — not the string scan — are what B17 rests on. |

The measurement that motivated this correction is in section 3.

---

## 2. Pipeline semantics, read from primary source at tag `v1.0.0`

All of the following was read from
[`google-ai-edge/mediapipe`](https://github.com/google-ai-edge/mediapipe) at tag
`v1.0.0`, not inferred from behaviour:

| Stage | Source file | What it fixes |
|---|---|---|
| ROI from a normalized rect | `calculators/tensor/image_to_tensor_utils.cc` (`GetRoi`, `PadRoi`) | normalized → pixel conversion; aspect-ratio padding |
| CPU crop/resample | `calculators/tensor/image_to_tensor_converter_opencv.cc` | `RotatedRect` → `boxPoints` → `getPerspectiveTransform` → `warpPerspective` |
| Border / range defaults | `calculators/tensor/image_to_tensor_calculator.proto` | `BORDER_REPLICATE` is the default |
| Detector stage options | `tasks/cc/vision/face_detector/face_detector_graph.cc` | `keep_aspect_ratio=true`, `BORDER_ZERO` |
| Landmark stage options | `tasks/cc/vision/face_landmarker/face_landmarks_detector_graph.cc` | no override → `keep_aspect_ratio=false`, `BORDER_REPLICATE` |
| Rect transformation | `calculators/util/rect_transformation_calculator.cc` | scale applied to *normalized* width/height when `square_long` is unset |
| Landmark projection | `calculators/util/landmark_projection_calculator.cc` | rotate about the rect centre, then scale by rect size |
| Blendshape input | `tasks/cc/vision/face_landmarker/face_blendshapes_graph.cc`, `calculators/tensor/landmarks_to_tensor_calculator.cc` | landmarks are **denormalized by full-image size** before the blendshape model |

The transcription of these operations lives in
[`src/faceauth/liveness/mediapipe_ops.py`](../src/faceauth/liveness/mediapipe_ops.py),
with each function naming the file it came from. Its arithmetic is covered by
`tests/test_b17_preprocessing.py`, which checks it against an independent
in-test implementation of the same published operations rather than against
oracle output — no constant in it is fitted to MediaPipe's numbers.

---

## 3. The preprocessing correction

The earlier replica resampled with `cv2.warpAffine` and a zero border. The
published CPU converter does something different: it builds a `cv::RotatedRect`,
takes `cv::boxPoints`, maps those to the destination corners
`(0,h) (0,0) (w,0) (w,h)` via `cv::getPerspectiveTransform`, and resamples with
`cv::warpPerspective` under `INTER_LINEAR`, defaulting to `BORDER_REPLICATE`.
The value-range transform is applied **after** resampling, not before.

Implementing the published path, with no other change:

| Metric | `warpAffine` + zero border | Published path | Improvement |
|---|---|---|---|
| Worst blink-score error | 0.10967 | **0.01363** | 8.0× |
| Worst landmark error | 0.02764 | **0.00152** | 18.2× |

This is the measurement that withdraws correction #1 above.

### Tensor value ranges

`image_preprocessing_graph.cc` derives the range from the model's
`NormalizationOptions` as `min = (0 − mean) / std`, `max = (255 − mean) / std`.
Neither `face_detector.tflite` nor `face_landmarks_detector.tflite` carries
those options in its metadata, so the pair was identified by measuring the two
documented candidates — `(mean 0, std 255) → [0,1]` and
`(mean 127.5, std 127.5) → [−1,1]` — across all four combinations:

| Detector range | Landmark range | Worst blink err | Worst landmark err |
|---|---|---|---|
| `[0,1]` | `[0,1]` | 0.11587 | 0.03277 |
| `[0,1]` | `[−1,1]` | 0.12342 | 0.03858 |
| **`[−1,1]`** | **`[0,1]`** | **0.01363** | **0.00152** |
| `[−1,1]` | `[−1,1]` | 0.05036 | 0.03052 |

The separation is 4–90×, so this identifies which of two documented,
enumerated options each model uses. It is a selection between known values, not
a fitted constant.

---

## 4. The blendshape input defect

With preprocessing corrected, one systematic error remained: on **non-square**
images the worst blendshape error was 0.18–0.61, while landmark error on the
same images stayed at or below 0.0007. Landmarks being right while blendshapes
were wrong localised the fault to the blendshape model's input.

`face_blendshapes_graph.cc` passes `IMAGE_SIZE` into
`LandmarksToTensorCalculator` to *denormalize* the landmarks, and
`GetAttributeScale` scales `X` by image width and `Y` by image height. The
blendshape model therefore consumes **full-image pixel coordinates**, not
normalized ones. On a square image that difference is an isotropic scale the
model largely absorbs; on a non-square image it is an anisotropic distortion.

| Metric | Normalized input | Denormalized input |
|---|---|---|
| Worst blendshape error | 0.60527 | **0.02779** |
| Worst blendshape error, non-square cases only | 0.60527 | **0.01414** |

---

## 5. Measured agreement

Corpus: 45 deterministic synthetic cases from
[`scripts/b17_option_a/corpus.py`](../scripts/b17_option_a/corpus.py) — eyelid
openness, translation, scale, rotation, resolution (including non-square),
edge clipping, brightness/contrast, head turn, two no-face cases, and a
two-face case. Faces are procedurally drawn; **no camera, no real face, and no
biometric data are involved**. The one random case uses a fixed seed.

Oracle: `mediapipe==1.0.1` with the pinned `face_landmarker.task`.
Replica: `ai-edge-litert` driving the three `.tflite` files from that same bundle.

| Metric | Worst over 45 cases | Where | Relevant scale |
|---|---|---|---|
| Blink score | **0.01363** | `open0.25` | 0.20 wide decision band |
| Landmark position | **0.00192** | `scale1.30` | normalized; ≈0.9 px at 480 px |
| Blendshape score | **0.02779** | `scale1.30` | 0–1 |
| Head-turn ratio | **0.00298** | `rot-12` | `head_turn_min_swing` = 0.045 |
| Detection agreement | **45 / 45** | — | includes both no-face cases |

### Where the residual comes from

Perturbing only the ROI, holding everything else fixed:

| ROI perturbation | Landmark change | Blink change |
|---|---|---|
| centre x +0.10 px | 0.00099 | 0.00592 |
| centre x +0.25 px | 0.00246 | **0.01637** |
| size +0.25 px | 0.00137 | 0.01726 |
| rotation +0.002 rad | 0.00203 | 0.02179 |

A **quarter-pixel** ROI shift moves the blink score by more than the replica's
entire worst-case residual. The residual is therefore at the pipeline's
intrinsic sub-pixel conditioning floor — consistent with float-level
differences in detector box regression and score-weighted NMS — rather than a
remaining structural difference. It also means agreement materially below
~0.01 on the blink score is not reachable by preprocessing correctness alone.

---

## 6. Limitations of this evidence

Stated plainly, because they bound what the numbers above support:

1. **The corpus cannot exercise the blink decision thresholds.** The configured
   thresholds are `blink_score_high = 0.40` and `blink_score_low = 0.20`.
   MediaPipe *itself* — the oracle, not the replica — emits a maximum blink
   score of about 0.21 on procedurally drawn faces, across two different eye
   renderings. So no synthetic sequence reaches the 0.40 threshold, and
   decision equivalence **at the configured thresholds has not been
   demonstrated**. Resolving this with a real face is excluded by the
   project's own constraint against capturing biometric data, so it remains
   open rather than being worked around.
2. **Agreement is not identity.** Nothing here claims bit identity. The claim
   is agreement to the tolerances tabulated in section 5.
3. **No ROI was captured from the graph edge.** Comparisons are end-to-end
   against the oracle's final output.
4. **Synthetic faces are not real faces.** The residual is characterised on
   drawn stimuli; behaviour on real input is not measured by this harness.

---

## 7. B17: what was required, and what was observed

Measured agreement is a precondition, not the criterion. B17 requires an
observed absence of outbound connections from the integrated path.

| Requirement | State |
|---|---|
| LiteRT provider integrated behind the existing liveness interface | Done. `challenge_response.py` drives `LiteRtFaceLandmarker`. Landmark indices 1 / 33 / 263, both signals, the decision functions and all three thresholds are unchanged. |
| `mediapipe` dependency and imports removed | Done. `pyproject.toml` pins `ai-edge-litert==2.2.0`; no runtime module imports `mediapipe`. The only remaining import is the oracle leg of the comparison harness, which is not a runtime dependency. |
| Allowlist empty | Done. `scripts/network_allowlist.json` has `"allowed": []`. |
| 20 fresh-process FULL-mode checks, all clean | Done. See below. |
| CI running an authoritative FULL model check | Done. CI fetches the pinned weights before pytest, so the realmodel-marked tests run rather than skip, then runs the check and asserts `mode == "full"` explicitly. |
| ADR-0005 Accepted with the evidence | Done. |

### The 20 runs

Environment: a clean virtualenv built from the new pinned dependency set, with
`mediapipe` absent from `site-packages` entirely and `ai-edge-litert==2.2.0`
present. Each run is a fresh process.

| Criterion | Result |
|---|---|
| Exit code 0 | 20 / 20 |
| Mode `full` | 20 / 20 |
| Loopback canary observed | 20 / 20 |
| Successful OS queries | 8-11 per run, never 0 |
| Failed OS queries | 0 across all 20 |
| Command deadline expired | never |
| **External endpoints observed** | **0 across all 20 runs** |

Raw per-run records: [`docs/b17/network_silence_20_runs.json`](b17/network_silence_20_runs.json).

The canary and the poll counts are what keep that zero from being vacuous: a
broken observer would report zero connections too, which is exactly how this
check once fooled itself.

## 8. Reproducing this

```
python scripts/fetch_models.py                 # pinned, checksum-verified
python -m scripts.b17_option_a.compare --out docs/b17/option_a_results.json
```

The harness fails with an explicit message — it does not silently skip — if the
pinned `face_landmarker.task` is absent, if `ai-edge-litert` is missing, or if
`mediapipe` is unavailable for the oracle leg. Model weights, binaries, and
per-case images are **not** committed; only the generator, the runners, and the
small machine-readable results file are.

---

## 9. Status

| Item | State |
|---|---|
| **B17** | **Cleared**, with the section 6 limitations stated. |
| **ADR-0005** | *Accepted* - Option A implemented. Option B was not needed and remains available and unverified. |
| **Phase 3 entry** | B17 no longer blocks it. |
