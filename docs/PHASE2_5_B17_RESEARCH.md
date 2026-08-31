# Phase 2.5: resolving B17 — network-silent liveness

**Status:** complete. **B17 - network silence - is cleared.** The liveness path
runs on a telemetry-free runtime, the `mediapipe` dependency is gone, the
allowlist is empty, and 20 fresh-process FULL-mode network checks observed zero
external endpoints. The corrections listed in section 1 are applied; the
limitations in section 6 stand.

**B17 is not a claim about detection quality.** It says the software makes no
outbound connections. It does *not* say the replacement detects liveness as
well as what it replaced - the synthetic corpus cannot reach the configured
`blink_score_high` of 0.40, so that has never been tested end to end. Real-input
validation is Phase 3 entry criterion **B18** ([issue #14](https://github.com/AddysEdge/ai-face-auth/issues/14)), and it is **OPEN**.

**Post-merge correction (2026-08-31):** an audit found two defects in this work
- a missing face-presence gate and a non-enforcing oracle comparison. Both are
fixed; see section 8.

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

Corpus: 46 deterministic synthetic cases from
[`scripts/b17_option_a/corpus.py`](../scripts/b17_option_a/corpus.py) — eyelid
openness, translation, scale, rotation, resolution (including non-square),
edge clipping, brightness/contrast, head turn, two no-face cases, a
detector-positive/presence-negative case, and a two-face case. Faces are
procedurally drawn; **no camera, no real face, and no biometric data are
involved**. Both random cases use fixed seeds.

Oracle: `mediapipe==1.0.1` with the pinned `face_landmarker.task`.
Replica: `ai-edge-litert` driving the three `.tflite` files from that same bundle.

Every row below is **enforced** by the harness's exit status, against a limit
declared in `scripts/b17_option_a/compare.py` before the evidence was
regenerated. An earlier revision computed these and then exited on detection
agreement alone, so no magnitude of error could fail it (section 8).

| Metric | Limit | Worst over 46 cases | Where |
|---|---|---|---|
| Landmark position | 1.0 px | **0.92339 px** | `scale1.30` |
| Blink score | 0.02 | **0.01363** | `open0.25` |
| Head-turn ratio | 0.0045 | **0.00298** | `rot-12` |
| Blendshape score (each of 52) | 0.05 | **0.02779** | `scale1.30` |
| Detection agreement | 100% | **46 / 46** | — |
| Presence-gate agreement | 100% | **44 / 44** | over the cases where the detector fired |

Landmark error is enforced in *source pixels*, not normalized units: x is
normalized by width and y by height, so a fixed normalized limit would be
lenient on large frames and harsh on small ones.

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
| Successful OS queries | 5-6 per run, never 0 |
| Inference stages completed | **4 / 4 on every run** (detector, presence gate, landmarks, blendshapes) |
| Failed OS queries | 0 across all 20 |
| Command deadline expired | never |
| **External endpoints observed** | **0 across all 20 runs** |

Raw per-run records: [`docs/b17/network_silence_20_runs.json`](b17/network_silence_20_runs.json).

The canary and the poll counts are what keep that zero from being vacuous: a
broken observer would report zero connections too, which is exactly how this
check once fooled itself.

The probe drives the **real** liveness provider — `new_challenge` / `observe` /
`finalize` plus teardown — against a procedurally drawn synthetic face rather
than a blank frame. That matters: on a blank frame the detector finds nothing
and `observe()` returns early, so the landmark and blendshape models would load
but never run inference, and a runtime that only phoned home after doing real
work would go unobserved. The run output prints the liveness reason, so a
regression back to a blank-frame probe is visible rather than silent.

## 8. Post-merge correction (2026-08-31)

An audit after PR #9 merged found two defects in the work above. Neither
changes the network-silence result — that is an OS-level observation of
connections, independent of landmark correctness — but both are corrected, and
the evidence in sections 5 and 7 was regenerated against the fixed code.

### 8.1 The landmark face-presence gate was missing

The published graph does not accept landmarks because the face detector fired.
`face_landmarks_detector_graph.cc` splits the landmark model's output tensors
(`kFaceLandmarksOutputTensorsNum = 2`, so presence is the tensor at declared
output index 1), sigmoids the presence logit through
`TensorsToFloatsCalculator`, thresholds it with `ThresholdingCalculator` at
`min_detection_confidence` (default 0.5), and gates **both** the projected
landmarks and the blendshapes behind that flag with `AllowIf`.
`ThresholdingCalculator::Process` computes
`accept = static_cast<double>(value) > threshold_` — strictly greater, so a
score of exactly 0.5 rejects.

`_landmarks_for()` picked the landmark tensor by size and ignored the presence
output entirely, so the second stage could not reject anything the first stage
let through: a fail-open gate in a security control.

Inspecting the shipped bundle shows the landmark model has **three** outputs,
two of them float32 scalars:

| Declared index | Name | Shape | Role |
|---|---|---|---|
| 0 | `Identity` | (1,1,1,1434) | 478×3 landmarks |
| 1 | `Identity_1` | (1,1,1,1) | **face-presence logit** |
| 2 | `Identity_2` | (1,1) | not consumed by the graph |

Measured directly against the model, `Identity_1` reads **+10.28** on a
synthetic face and **−12.6 to −14.1** on noise, flat black and flat white,
while `Identity_2` barely moves (0.50–0.73 after sigmoid). Shape alone
therefore cannot tell the two scalars apart, and MediaPipe's own selection is
positional. The implementation takes MediaPipe's positions and *validates*
shape and dtype at each, refusing to load if the layout is not the one it was
written against.

The gate is not theoretical. A new corpus case, `presence_gate_reject` — noise
behind a blank skin-tone oval — makes the detector fire at **0.63** while the
presence logit returns about **−15**. The MediaPipe oracle returns zero faces
for it. Before this fix the replica accepted it and produced landmarks and
blendshapes for a blank oval.

Non-finite presence is an error rather than a value: `+inf` would sigmoid to
1.0 and pass the threshold, turning a broken model into a confident accept.

### 8.2 The oracle comparison was non-enforcing

`compare.py` returned `0 if detection_agreement == cases else 1`. Landmark,
blink, blendshape and turn-ratio errors were computed, printed and stored, but
no magnitude of error could fail the command — and CI never ran it at all.
Tolerances are now declared in the module and enforced by exit status, presence
agreement is tracked separately from detection agreement, and a dedicated CI
job runs the comparison against a `mediapipe==1.0.1` oracle in a separate,
deliberately **non**-network-silent environment.

### 8.3 The rest of the graph, audited

Checked for the same class of omission and found correct: the detector's
`min_score_thresh` comparison (`tensors_to_detections_calculator.cc` skips on
`score < thresh`, so `>=` accepts — a *different* operator from the presence
gate's `>`), score clipping before the sigmoid, `WEIGHTED` NMS blending rather
than dropping, letterbox removal, `ClipVectorSize` bounding results to
`num_faces`, the blendshape split range `[0,1)`, and
`TensorsToClassificationCalculator` returning coefficients as-is with `top_k`
disabled — no activation.

---

## 9. Reproducing this

```
python scripts/fetch_models.py                 # pinned, checksum-verified
python -m scripts.b17_option_a.compare --out docs/b17/option_a_results.json
```

The harness fails with an explicit message — it does not silently skip — if the
pinned `face_landmarker.task` is absent, if `ai-edge-litert` is missing, or if
`mediapipe` is unavailable for the oracle leg. **It also exits nonzero if any
declared tolerance is exceeded**, so it is usable as a gate rather than a
report. Model weights, binaries, and per-case images are **not** committed;
only the generator, the runners, and the small machine-readable results file
are.

`mediapipe` is deliberately **not** a project dependency, so the oracle leg
needs a throwaway environment. CI runs it in the `oracle-equivalence` job,
which installs `mediapipe==1.0.1` alongside the normal pinned set. That
environment is **not** network-silent and is not evidence about B17; the
network evidence comes from the `python` job, which asserts `mediapipe` is
absent before it measures anything.

---

## 10. Status

| Item | State |
|---|---|
| **B17** | **Cleared** - network silence only, with the section 6 limitations stated. |
| **B18** | **Open.** Real-input liveness validation: genuine blinks and non-blinks, the configured 0.40/0.20 thresholds actually exercised, FAR/FRR, static-photo and replay attacks, lighting/pose/distance/camera variation, a written calibration methodology, and a recorded security review. Not satisfiable by more synthetic measurement. |
| **ADR-0005** | *Accepted* - Option A implemented. Option B was not needed and remains available and unverified. |
| **Phase 3 entry** | B17 no longer blocks it. **B18 does.** |
