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

**B17 is not cleared.** Option B is **rejected** on primary-source evidence.
Option A is **selected as the resolution path** and has been substantially
de-risked, but it is **not implemented**, because a first-pass replication does
not reproduce MediaPipe's pipeline closely enough to keep the calibrated blink
thresholds valid, and closing that gap needs evidence this phase could not
safely produce.

Nothing in this change alters runtime behaviour. The allowlist still declares
`play.googleapis.com:443`, the network checker is unchanged, and Phase 3 remains
blocked by B17 along with every other open Part B criterion.

---

## 1. The requirement, quoted unchanged

From `docs/PHASE2_ACCEPTANCE_CRITERIA.md`, criterion B17:

> ADR-0005 must move from *Proposed* to *Accepted* with **Option A** (replace
> MediaPipe) or **Option B** (transparently build and verify MediaPipe without
> telemetry) selected **and implemented**. Those are the only two resolutions.
> [...] `scripts/check_network_activity.py` run against the Phase 3 verification
> path, showing **zero** outbound connections, with
> `scripts/network_allowlist.json` empty.

That language is not redefined here. It is the bar this phase measured itself
against, and did not reach.

---

## 2. Baseline, independently reproduced

Three fresh-process FULL-mode runs on `78899cd`, before any research:

| Run | Exit | Canary | Successful queries | Failed queries | Deadline expired | External endpoints |
|---|---|---|---|---|---|---|
| 1 | 0 | YES (port 55038) | 8 | 0 | no | **1** |
| 2 | 0 | YES (port 55042) | 10 | 0 | no | **1** |
| 3 | 0 | YES (port 55046) | 9 | 0 | no | **1** |

Observer health was proven on every run, so the single external endpoint is a
real observation rather than a blind pass. Dependency identity at the time of
measurement:

| | |
|---|---|
| mediapipe | 1.0.1 |
| onnxruntime | 1.29.0 |
| opencv-contrib-python | 5.0.0.93 |
| `libmediapipe.dll` sha256 | `31335db8bb8cd4bb294fd689b6b06086eb33782ee9c7f4667e12a6014a68436c` |
| `face_landmarker.task` sha256 | `64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff` |

The existing limitations are unchanged and still apply: the observer records
`IP:port`, not payloads; hostnames are DNS inference, not proof; no TLS was
decrypted; the Clearcut envelope is uncharacterised; nothing establishes the
telemetry is anonymous.

---

## 3. Option B — build MediaPipe from source without telemetry

**Rejected.** Two primary-source findings make it unverifiable as specified.

### 3.1 There is no public source for the shipped wheel

The installed wheel is **mediapipe 1.0.1**. Upstream tags and releases
(`repos/google-ai-edge/mediapipe`, retrieved 2026-08-27):

```
v1.0.0     released 2026-07-28
v0.10.35   released 2026-04-28
v0.10.33   v0.10.32   v0.10.26   ...
```

**There is no `v1.0.1` tag or release.** This matches what the PR #3 dependency
review already recorded: 1.0.1 is a PyPI-only patch with no published notes.
Option B's first requirement — "exact upstream source corresponding to the
installed wheel" — cannot be satisfied, because that source is not published.

### 3.2 The telemetry is not in the public source at all

GitHub code search over the repository:

```
search/code?q=clearcut+repo:google-ai-edge/mediapipe   ->   total_count: 0
```

Zero hits. This confirms the reporter's observation in
[mediapipe#6291](https://github.com/google-ai-edge/mediapipe/issues/6291) that
"there is no reference to `clearcut` in the entire open source mediapipe
repository", and that the PyPI wheels are built internally at Google.

### 3.3 Why that is disqualifying rather than convenient

At first glance "telemetry is absent from the public source" sounds like Option
B is trivially satisfied. It is the opposite. It means the public tree is a
**different artifact** from the wheel this project audited and ships. Building
from source would not be *removing* telemetry from the audited binary; it would
be producing a different binary, from a different (and for 1.0.1, non-existent)
source, with no way to establish behavioural equivalence to what was measured.

The maintainer's statement that a source build "will not include telemetry" is
consistent with this and remains authoritative — but it speaks to the absence of
telemetry, not to equivalence with the shipped wheel.

On top of that, Option B would require a Bazel/MSVC build of a large C++ project
on Windows, pinned and reproduced on every upstream update, with a recurring
obligation to re-verify telemetry absence. ADR-0005 already recorded that
recurring cost as its principal risk. The provenance gap above is what moves it
from "expensive" to "not verifiable as specified".

**No opt-out was invented, and none was found.** The upstream refusal recorded
in issue #6 stands.

---

## 4. Option A — replace the MediaPipe runtime

**Selected as the path.** Substantially de-risked, not implemented.

### 4.1 What the liveness contract actually needs

`MediaPipeChallengeResponseLiveness` needs exactly two signals per frame:

| Signal | Source today | Used by |
|---|---|---|
| blink score | mean of `eyeBlinkLeft` / `eyeBlinkRight` blendshapes | `decide_blink`, thresholds high `0.40` / low `0.20` |
| turn ratio | landmarks 1 (nose), 33 / 263 (eye corners) | `decide_head_turn`, `min_swing 0.045` |

`DEFAULT_ENABLED_CHALLENGES` is **BLINK only**, so the blink score is the live
security boundary; head-turn is implemented and tested but not a default (see
`docs/THREAT_MODEL.md` section 2).

**The turn ratio needs no new model.** `FaceBox.landmarks` already carries
YuNet's five points `(right_eye, left_eye, nose, r_mouth, l_mouth)`, which is
everything `_turn_ratio` uses. Only the blink signal depends on MediaPipe.

### 4.2 The models are already in a pinned bundle

`models/face_landmarker.task` is a plain zip archive:

| Member | Size |
|---|---|
| `face_detector.tflite` | 229,746 |
| `face_landmarks_detector.tflite` | 2,553,590 |
| `face_blendshapes.tflite` | 955,312 |
| `geometry_pipeline_metadata_landmarks.binarypb` | 19,376 |

These are the **same weights the project already fetches**, under the same
Apache-2.0 entry with a pinned URL and SHA-256 in `src/faceauth/model_registry.py`.
Using them directly needs no new model provenance and no new licence review.

Signatures (read with LiteRT):

```
face_detector.tflite              in [1,128,128,3] f32  -> regressors [1,896,16], classificators [1,896,1]
face_landmarks_detector.tflite    in [1,256,256,3] f32  -> [1,1,1,1434] (478 x 3), score, score
face_blendshapes.tflite           in [1,146,2]     f32  -> [52]
```

### 4.3 A telemetry-free runtime exists

`ai-edge-litert` **2.2.0** publishes `cp312-cp312-win_amd64`. Every native
binary in the wheel was scanned:

| Indicator | Hits across all 18 `.dll` / `.pyd` |
|---|---|
| `play.googleapis` | **0** |
| `clearcut` | **0** |
| `playlog` | **0** |

The only embedded URLs are TensorFlow documentation links and `crbug.com`
references. This is the same inspection method that found the Clearcut client
in `libmediapipe.dll`, applied to the candidate replacement.

### 4.4 The blendshape stage reproduces MediaPipe exactly

The 146-landmark subset and the 52 blendshape names were read from
`mediapipe/tasks/cc/vision/face_landmarker/face_blendshapes_graph.cc` at tag
`v1.0.0` (`kLandmarksSubsetIdxs`, `kBlendshapeNames`; `eyeBlinkLeft` is index 9,
`eyeBlinkRight` index 10).

Feeding **MediaPipe's own landmarks** through the extracted
`face_blendshapes.tflite` on LiteRT reproduces MediaPipe's blendshapes exactly:

| Synthetic face | MediaPipe `eyeBlinkL / R` | LiteRT replica `eyeBlinkL / R` |
|---|---|---|
| seed 0 | 0.00590 / 0.00151 | 0.00590 / 0.00151 |
| seed 1 | 0.00197 / 0.00148 | 0.00197 / 0.00148 |
| seed 2 | 0.00310 / 0.00109 | 0.00310 / 0.00109 |

Agreement to five decimal places, and scale-invariant (the model normalises its
input internally, so normalised and pixel coordinates give identical output).
**The blendshape stage is solved.**

### 4.5 What is not solved: the ROI stage

The remaining stage is detector → region-of-interest → 256×256 crop. The
constants are public, from `face_landmarks_detector_graph.cc` at `v1.0.0`:

```
rotation_vector_start_keypoint_index = 0     (left eye)
rotation_vector_end_keypoint_index   = 1     (right eye)
rotation_vector_target_angle_degrees = 0
scale_x = scale_y = 1.5
square_long = true
```

A first-pass replication was built from those constants (BlazeFace decode with
the standard short-range-128 anchor grid, keypoint-driven rotation, 1.5× square
ROI, inverse-affine mapping back to image coordinates) and compared against
MediaPipe on synthetic faces:

| Case | MediaPipe blink | Replica blink | Max landmark error (normalised) |
|---|---|---|---|
| centered | 0.00560 | 0.00229 | 0.01448 |
| shift +20px x | 0.00332 | 0.00156 | 0.02682 |
| shift −20px x | 0.00609 | 0.00326 | 0.01244 |
| shift +20px y | 0.00619 | 0.00488 | 0.02764 |
| scale 0.85 | 0.00678 | 0.00280 | 0.01050 |
| scale 1.15 | 0.00726 | 0.00875 | 0.02023 |

Landmark error of 0.010–0.028 normalised is 5–13 pixels on a 480-pixel frame.
Close, but **not exact** — and exactness is what this needs.

### 4.6 Why "close" is not good enough here

Blendshape output is materially sensitive to the ROI. Reframing the *same*
synthetic face changes the blink score by 9–41 % relative:

| Reframing | Blink score | Δ vs baseline |
|---|---|---|
| baseline | 0.00560 | — |
| shift +20px x | 0.00332 | −40.6 % |
| shift −20px x | 0.00609 | +8.9 % |
| shift +20px y | 0.00619 | +10.5 % |
| scale 0.85 | 0.00678 | +21.2 % |
| scale 1.15 | 0.00726 | +29.7 % |

The blink decision band is `low 0.20` to `high 0.40` — a width of 0.20. A
10–40 % relative shift in the operating range is a change of roughly 0.02–0.16,
which is a large fraction of that band. Those thresholds were derived from
**live human calibration** (`scripts/calibrate_liveness.py`, see
`docs/RESEARCH.md`) against MediaPipe's exact output scale. A replacement that
shifts the scale silently invalidates them.

This is the whole risk, stated plainly: the failure mode is not a crash or a
missing landmark. It is an anti-spoofing control that still returns plausible
numbers while its calibrated decision boundary no longer means what it meant.
Nothing in a smoke test would show it.

---

## 5. Decision matrix

Verified network silence and preservation of the liveness security boundary are
**hard requirements**, not weighted preferences.

| Criterion | Option A — replace runtime | Option B — build from source |
|---|---|---|
| **Verified network silence** | Achievable: LiteRT scanned clean (0 telemetry strings) | Plausible but unverifiable against the audited wheel |
| **Preserves liveness behaviour** | Only if the pipeline is replicated **exactly**; first pass is not | Yes by construction — same code path |
| **Spoof-resistance risk** | Real: ROI drift silently moves the calibrated blink band | Low |
| **Provenance** | Excellent: models already SHA-pinned, Apache-2.0, no new source | **Blocking: no `v1.0.1` tag exists** |
| **Build reproducibility** | No build needed; extract from the pinned bundle | Bazel + MSVC on Windows, not demonstrated |
| **Equivalence to audited artifact** | N/A — a deliberate, documented replacement | **Cannot be established** |
| **Licence** | Apache-2.0 throughout, no change | Apache-2.0, unchanged |
| **New dependency risk** | `ai-edge-litert` (Google, Apache-2.0), scanned clean | None added, but a self-built binary is owned forever |
| **Maintenance burden** | Moderate: track upstream landmarker/graph changes | High and recurring: rebuild, re-pin, re-verify every release |
| **CI feasibility** | Good — pure Python + pinned models | Poor — long Windows Bazel builds |
| **Auditability** | High: three small models, readable code | Low: opaque self-built wheel |
| **Remaining work** | Exact ROI replication, then verification | Build system, provenance story, equivalence argument |

**Option B is rejected** — it fails the provenance and equivalence requirements
outright (§3.1, §3.2), independently of its cost.

**Option A is selected as the path** — every hard requirement is reachable and
most of the risk is now retired (§4.2–4.4). It is not yet implementable to the
standard B17 demands, for the reason in §4.5–4.6.

---

## 6. What would finish Option A

Two routes, both real, neither completable within this phase:

1. **Exact ROI replication.** Continue refining the detector decode and ROI
   transform until landmarks agree with MediaPipe to a tight tolerance across a
   broad synthetic-input sweep (position, scale, rotation, resolution). Because
   exactness is input-independent, agreement across varied synthetic inputs is
   sufficient evidence — no real face data is required. With landmarks matching,
   the blendshapes match by §4.4 and the calibrated thresholds carry over
   unchanged.

2. **Re-calibration.** Accept a close-but-not-exact replication and re-derive
   `blink_score_high` / `blink_score_low` with `scripts/calibrate_liveness.py`.
   This needs a live camera and a real person, and it produces biometric data.
   **That is the repository owner's call and the owner's face** — it is not
   something this phase could or should do.

Route 1 is preferable: it removes the calibration question entirely instead of
reopening it.

### Deliberately not done

- No firewall rule, hosts-file edit, DNS change, proxy, IP block, certificate,
  or TLS interception. A machine policy that prevents transmission is not a
  property of the software and does not clear B17.
- No weakening of the liveness API, the network checker, or the allowlist to
  make the phase appear to pass.
- No change to runtime code. The replacement is not half-landed.

---

## 7. Status after this phase

| | |
|---|---|
| **B17** | **Open.** Not cleared. |
| **ADR-0005** | Still *Proposed*. Option B rejected; Option A selected as the path. |
| **Issue #6** | Open. |
| **Phase 3** | Blocked — by B17 and by every other open Part B criterion. |
| **Runtime behaviour** | Unchanged. Allowlist still declares `play.googleapis.com:443`. |

The mandatory interim disclosure from PR #5 remains what it was: accurate
documentation, not a resolution.
