# Model / License Information

This document is the authoritative license reference for every model file
this repository uses or documents as an alternative. See
`src/faceauth/model_registry.py` for the machine-readable version (filename,
source URL, SHA-256, license) and `docs/RESEARCH.md` section 5 for the
research trail behind these entries.

## Shipped by default (commercial-clean stack)

| File | Model | License | Commercial use | Source |
|---|---|---|---|---|
| `models/yunet_2023mar.onnx` | YuNet face detector | **MIT** | Yes | [opencv/opencv_zoo](https://github.com/opencv/opencv_zoo/tree/main/models/face_detection_yunet) |
| `models/sface_2021dec.onnx` | SFace face embedding (128-d) | **Apache-2.0** | Yes | [opencv/opencv_zoo](https://github.com/opencv/opencv_zoo/tree/main/models/face_recognition_sface) |
| `models/face_landmarker.task` | MediaPipe Face Landmarker (landmarks + blendshapes) | **Apache-2.0** | Yes | [Google AI Edge / MediaPipe](https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task) |

All three were downloaded, checksum-verified, and loaded/run for real during
development (see `docs/RESEARCH.md` and `scripts/fetch_models.py`). Every
file's SHA-256 is pinned in `src/faceauth/model_registry.py` and re-checked
by `scripts/fetch_models.py` on every fetch.

## Documented alternatives (NOT shipped by default - opt-in only)

| Model | License | Commercial use | Why not the default |
|---|---|---|---|
| InsightFace `buffalo_l` / ArcFace | Code: MIT. **Pretrained weights: non-commercial research only** | **No** (contact `recognition-oss-pack@insightface.ai` for a commercial license) | Higher accuracy (~99.83% LFW vs SFace's ~99.6%), but the model weights' license would make any commercial Phase 2 legally encumbered unless separately licensed. |
| dlib `shape_predictor_68_face_landmarks.dat` | Trained on the iBUG 300-W dataset, whose license **excludes commercial use** | **No** | Not used anywhere in this repo; MediaPipe Face Landmarker (Apache-2.0) is used instead for exactly this purpose. |
| Silent-Face-Anti-Spoofing / MiniFASNet | Apache-2.0 | Yes | License-clean, but the reference repository (`minivision-ai/Silent-Face-Anti-Spoofing`) has had no substantive commits since 2020. The architecture is compatible with the optional `PassiveOnnxSpoofLiveness` backend (`src/faceauth/liveness/passive_onnx.py`), but no specific checkpoint is bundled - see that module's docstring for the exact contract a checkpoint must satisfy, and calibrate/validate any checkpoint you supply yourself. |

## If you enable the InsightFace alternative

`buffalo_l`'s pretrained models require contacting InsightFace for a
commercial license before any commercial use. Research/personal/educational
use under InsightFace's stated non-commercial terms is a decision you make
explicitly by wiring in that backend yourself - this repository's default
configuration never downloads or uses InsightFace models.

## Re-verifying a license claim

Licenses can change. Before relying on any entry above for a real decision,
re-check the primary source:
- YuNet/SFace: the `LICENSE` file in the respective `opencv_zoo` model directory.
- MediaPipe: [Google AI Edge MediaPipe documentation](https://developers.google.com/mediapipe).
- InsightFace: the [deepinsight/insightface](https://github.com/deepinsight/insightface) README, "License" section.
