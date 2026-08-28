# Phase 2.5: resolving B17 — network-silent liveness

**Date:** 2026-08-27
**Starting main:** `78899cda042541a2fa11b25f9fc49e1a052f3f2b`
**Tracking:** [issue #6](https://github.com/AddysEdge/ai-face-auth/issues/6), ADR-0005
**Scope:** B17 only. No Phase 3 work, no Credential Provider, no service, no
registry, no camera, no Windows-authentication state. No firewall, proxy,
hosts-file, DNS, or certificate change was made at any point.
**Method:** synthetic drawn faces only. No camera was opened and no biometric
data was captured, read, or processed.

---

## 0. Outcome

**B17 is not cleared.**

**Option A — replacing the MediaPipe runtime by independently reimplementing its
pipeline — is contradicted by measurement.** The public pipeline semantics were
reproduced from primary source and the residual mismatch was localised: even
when the replica is handed *MediaPipe's own ROI*, the blink score still differs
by up to **0.070**, against a decision band only 0.20 wide. The cause is image
resampling fidelity in the 256×256 landmark crop, not the ROI arithmetic.

**Option B — a pinned public-source MediaPipe build — is available and
unverified, and is now the leading candidate.** It has not been attempted.

### Correction to the previous revision of this document

An earlier revision of this file **rejected Option B**, and did so on a
requirement that does not appear in B17 or issue #6: equivalence to the
telemetry-bearing 1.0.1 wheel. That was wrong and is withdrawn.

B17 asks for a build that is pinned to public source, transparently identified
as project-built, reproducible, verified telemetry-free, and verified to
preserve this project's liveness behaviour. **It does not ask for source or
binary equivalence to 1.0.1.** The absence of a public `v1.0.1` tag shows only
that the *current wheel* cannot be traced to matching public source — it says
nothing about whether a `v1.0.0` build is valid. Likewise, zero `clearcut` hits
in the public tree *supports* evaluating a telemetry-free source build; it does
not disqualify one, and the upstream collaborator states plainly in
[mediapipe#6291](https://github.com/google-ai-edge/mediapipe/issues/6291) that a
source-built SDK does not include telemetry.

A second claim is also withdrawn: that YuNet's five points make the head-turn
signal MediaPipe-free. YuNet's eye points are **not** demonstrated equivalent to
MediaPipe landmarks 33 and 263, and no such equivalence was measured. The
existing 478-landmark turn-ratio calculation stands unchanged.

---

## 1. The requirement, quoted unchanged

From `docs/PHASE2_ACCEPTANCE_CRITERIA.md`, criterion B17:

> ADR-0005 must move from *Proposed* to *Accepted* with **Option A** (replace
> MediaPipe) or **Option B** (transparently build and verify MediaPipe without
> telemetry) selected **and implemented**. [...]
> `scripts/check_network_activity.py` run against the Phase 3 verification
> path, showing **zero** outbound connections, with
> `scripts/network_allowlist.json` empty.

Not redefined here.

---

## 2. Baseline, independently reproduced

Three fresh-process FULL-mode runs on `78899cd`:

| Run | Exit | Canary | Successful queries | Failed queries | Deadline expired | External endpoints |
|---|---|---|---|---|---|---|
| 1 | 0 | YES (55038) | 8 | 0 | no | **1** |
| 2 | 0 | YES (55042) | 10 | 0 | no | **1** |
| 3 | 0 | YES (55046) | 9 | 0 | no | **1** |

Observer health proven on every run. Dependency identity:

| | |
|---|---|
| mediapipe | 1.0.1 |
| onnxruntime | 1.29.0 |
| opencv-contrib-python | 5.0.0.93 |
| `libmediapipe.dll` sha256 | `31335db8bb8cd4bb294fd689b6b06086eb33782ee9c7f4667e12a6014a68436c` |
| `face_landmarker.task` sha256 | `64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff` (verified, matches `model_registry.py`) |

---

## 3. What the liveness contract requires

`MediaPipeChallengeResponseLiveness` needs two per-frame signals:

| Signal | Source | Consumer |
|---|---|---|
| blink score | mean of `eyeBlinkLeft` / `eyeBlinkRight` blendshapes | `decide_blink`, thresholds **high 0.40 / low 0.20** |
| turn ratio | **478-landmark** indices 1, 33, 263 | `decide_head_turn`, `min_swing 0.045` |

`DEFAULT_ENABLED_CHALLENGES` is BLINK only, so the blink score is the live
security boundary. Both signals must be preserved; the turn ratio keeps its
478-landmark definition.

---

## 4. Option A: what was built, and what it proves

### 4.1 Components, all from the pinned bundle

`models/face_landmarker.task` is a zip containing exactly the models needed:

| Member | Size |
|---|---|
| `face_detector.tflite` | 229,746 |
| `face_landmarks_detector.tflite` | 2,553,590 |
| `face_blendshapes.tflite` | 955,312 |

Same Apache-2.0 entry, same pinned URL and SHA-256 already in
`src/faceauth/model_registry.py`. Signatures:

```
face_detector.tflite            [1,128,128,3] f32 -> regressors [1,896,16], classificators [1,896,1]
face_landmarks_detector.tflite  [1,256,256,3] f32 -> [1,1,1,1434] (478x3) + 2 scalars
face_blendshapes.tflite         [1,146,2]     f32 -> [52]
```

### 4.2 A telemetry-free runtime exists

`ai-edge-litert` **2.2.0** publishes `cp312-cp312-win_amd64`. All 18 native
binaries scanned with the same method that found the Clearcut client in
`libmediapipe.dll`:

| Indicator | Hits |
|---|---|
| `play.googleapis` | **0** |
| `clearcut` | **0** |
| `playlog` | **0** |

Only embedded URLs are TensorFlow docs and `crbug.com` references.

### 4.3 Pipeline semantics, read from primary source at tag `v1.0.0`

| Element | Value | Source |
|---|---|---|
| SSD anchors | `num_layers 4`, `min_scale 0.1484375`, `max_scale 0.75`, `128x128`, `offset 0.5/0.5`, `strides [8,16,16,16]`, `aspect_ratios [1.0]`, `fixed_anchor_size`, `interpolated_scale_aspect_ratio 1.0` → 896 anchors | `face_detector_graph.cc` |
| NMS | `WEIGHTED`, `INTERSECTION_OVER_UNION` | `face_detector_graph.cc` |
| Weighted-NMS blending | score-weighted mean of box and all 6 keypoints over the IoU cluster | `non_max_suppression_calculator.cc` |
| Rotation | `rotation = target_angle − atan2(−(y1−y0), x1−x0)`, keypoints 0/1, target 0° | `detections_to_rects_calculator.cc` |
| ROI expansion | `scale_x = scale_y = 1.5` (no `square_long` on the detector path) | `face_detector_graph.cc` |
| Blendshape subset | `kLandmarksSubsetIdxs`, 146 indices | `face_blendshapes_graph.cc` |
| Blendshape names | `kBlendshapeNames`, 52 entries; `eyeBlinkLeft` = 9, `eyeBlinkRight` = 10 | `face_blendshapes_graph.cc` |

All of these were implemented. Measured empirically: detector tensor range
`[-1,1]`, landmark tensor range `[0,1]`, landmark output in 0–256 crop-pixel
space.

### 4.4 The blendshape stage is bit-exact

Given MediaPipe's own 478 landmarks, the extracted blendshape model on LiteRT
reproduces MediaPipe's output exactly:

| Synthetic face | MediaPipe `eyeBlinkL / R` | LiteRT replica |
|---|---|---|
| seed 0 | 0.00590 / 0.00151 | 0.00590 / 0.00151 |
| seed 1 | 0.00197 / 0.00148 | 0.00197 / 0.00148 |
| seed 2 | 0.00310 / 0.00109 | 0.00310 / 0.00109 |

Five decimal places, and scale-invariant. **This stage is not the problem.**

### 4.5 The measured failure

Blink score across an eyelid-openness sweep, replica vs MediaPipe, on synthetic
faces at several positions/scales/rotations:

| Openness | Case | MediaPipe | Replica | Abs diff |
|---|---|---|---|---|
| 1.00 | base | 0.00139 | 0.00262 | 0.00123 |
| 0.70 | dx+30 | 0.00128 | 0.00131 | 0.00003 |
| 0.45 | dx+30 | 0.00477 | 0.00227 | 0.00249 |
| **0.25** | **base** | **0.14711** | **0.08571** | **0.06140** |
| **0.25** | **dx+30** | **0.22282** | **0.11315** | **0.10967** |
| 0.25 | scale1.2 | 0.11783 | 0.15434 | 0.03651 |
| 0.10 | dx+30 | 0.16662 | 0.09947 | 0.06714 |
| 0.02 | dx+30 | 0.16662 | 0.09947 | 0.06714 |

Agreement is tight while the signal is near zero — and **breaks down precisely
where the control operates**. Worst absolute error **0.10967**, which is **55 %
of the 0.20-wide decision band** (`low 0.20` → `high 0.40`). A blink reading
0.223 under MediaPipe reads 0.113 under the replica: the same event, on opposite
sides of the `low` threshold.

### 4.6 The residual is not in the ROI

To localise it, the replica was handed **MediaPipe's own landmark-derived ROI**
(indices 33/263, `square_long`, scale 1.5), removing the detector and ROI stages
from the comparison entirely:

| Case | MediaPipe | Replica | Abs diff | Landmark max err |
|---|---|---|---|---|
| open 0.25 base | 0.14711 | 0.14987 | 0.00276 | 0.01624 |
| open 0.25 dx+30 | 0.22282 | 0.15259 | **0.07023** | 0.01686 |
| open 0.10 base | 0.11892 | 0.15304 | 0.03412 | 0.01727 |
| open 0.10 dx+30 | 0.16662 | 0.21218 | 0.04556 | 0.01211 |

The error **persists at 0.070** with a known-correct ROI, and landmark error
stays at 0.012–0.022 normalised. So the mismatch is not the anchor grid, the
NMS, the rotation formula, or the ROI expansion — each of which was taken
directly from source and, where testable, verified.

**Root cause:** the 256×256 crop. An independent resampling (OpenCV
`warpAffine`, INTER_LINEAR, BORDER_ZERO) does not produce bit-identical tensor
input to MediaPipe's internal `ImageToTensorCalculator`, and the landmark CNN
amplifies those sub-pixel differences into decision-relevant blendshape
differences. Matching it would require reproducing MediaPipe's resampling
arithmetic exactly — which is the thing an independent reimplementation cannot
assume it has done, and which no amount of constant-tuning would establish.

This is a concrete, reproducible contradiction of the exact-replication route,
not an assertion that the work is hard.

---

## 5. Option B: available, unverified, and now the leading candidate

Not attempted. Nothing found in this phase disqualifies it, and the earlier
rejection is withdrawn (§0).

What B17 actually asks of it, and the current state of each:

| Requirement | Status |
|---|---|
| Pinned public-source build | `v1.0.0` is tagged and available (released 2026-07-28). Not built. |
| Transparently identified as project-built | Design question, not yet done |
| Reproducible provenance | Not yet established |
| Verified absence of telemetry | Supported by upstream's statement and by zero `clearcut` hits in the public tree; **not yet verified on a built artifact** |
| Verified preservation of liveness behaviour | Testable against the 1.0.1 oracle built in §4; not yet done |

**Honest scope note.** A MediaPipe Bazel build on Windows for Python 3.12 is a
large, fragile undertaking (upstream issues #5687, #6159, #2545 record repeated
failures), needs a Bazel/MSVC/protoc toolchain, and was not attempted here. That
is a statement about what this phase did, not a judgement that it will fail.

---

## 6. Decision matrix

Verified network silence and preservation of the liveness security boundary are
**hard requirements**, not weighted preferences.

| Criterion | Option A (independent reimplementation) | Option B (public-source build) |
|---|---|---|
| **Verified network silence** | Achievable — LiteRT scanned clean | Plausible; unverified on a built artifact |
| **Preserves liveness behaviour** | **FAILS as measured** — blink error up to 0.110 vs a 0.20 band | Expected to hold — same code path |
| **Spoof-resistance risk** | **Unacceptable as built** | Low |
| **Provenance** | Excellent — models already SHA-pinned | `v1.0.0` tag available; build provenance to be established |
| **Reproducibility** | No build needed | Must be demonstrated |
| **Licence** | Apache-2.0 throughout | Apache-2.0 |
| **Maintenance** | Moderate | High and recurring |
| **CI feasibility** | Good | Poor — long Windows Bazel builds |
| **Status** | **Contradicted by evidence** | **Available, unverified** |

Option A's failure is on a hard requirement, so it cannot be selected as built.
Option B is not disqualified by anything measured in this phase.

---

## 7. What would finish this

**Option B**, as specified in B17: build `v1.0.0` from pinned public source for
Windows / Python 3.12, identify the artifact as project-built, record hashes and
provenance, verify telemetry absence on the built binary, verify liveness
behaviour against the 1.0.1 oracle from §4, then run the FULL 20-process
network-silence test with an empty allowlist.

**Option A remains reachable only** if the crop resampling can be made to match
MediaPipe's exactly — reproducing `ImageToTensorCalculator`'s arithmetic rather
than approximating it with `warpAffine`. The oracle harness and every other
stage are already built and verified, so that is the single remaining gap. It
should not be attempted by tuning constants against the oracle; that would fit
the test rather than the transform.

**Not an option:** re-calibrating `blink_score_high` / `blink_score_low` to a
divergent replica. That needs a live camera and a real person, and it would
re-derive a security threshold to fit an implementation rather than the other
way round.

### Deliberately not done

- No firewall rule, hosts-file edit, DNS change, proxy, IP block, certificate,
  or TLS interception. A machine policy that prevents transmission is not a
  property of the software and does not clear B17.
- No weakening of the liveness API, thresholds, network checker, or allowlist.
- No partial replacement landed. `mediapipe` remains the runtime.

---

## 8. Status after this phase

| | |
|---|---|
| **B17** | **Open.** Not cleared. |
| **ADR-0005** | Still *Proposed*. Option A contradicted as built; Option B available and unverified. |
| **Issue #6** | Open. |
| **Phase 3** | Blocked — by B17 and every other open Part B criterion. |
| **Runtime behaviour** | Unchanged. Allowlist still declares `play.googleapis.com:443`. |
