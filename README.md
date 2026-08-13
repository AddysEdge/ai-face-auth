# FaceAuth (Phase 1 MVP)

A local, offline, webcam-based face-authentication **demo/research
prototype**. It is Phase 1 of a longer-term exploration into whether a
legitimate, Microsoft-supported Windows Credential Provider could one day
offer face authentication as an alternative sign-in method. Phase 1 itself
is a standalone application - it does not touch Windows sign-in in any way.

## What this project does

- Enrolls a user from webcam frames: detects a face, checks frame quality,
  requires a live challenge-response (blink or head-turn) per sample,
  extracts a face embedding, and stores an encrypted template locally.
- Authenticates a user the same way: capture → detect → quality-gate →
  liveness challenge → embed → compare against the stored template →
  threshold decision → grant/deny.
- Runs entirely offline, on CPU, using open, license-clean pretrained
  models (see "Models" below). No cloud API, no API key, no network access
  required at runtime.
- Rate-limits repeated failures with escalating cooldown, persisted to disk
  so it survives across separate CLI invocations, not just within one
  running process (see `docs/THREAT_MODEL.md` §12 for why this matters -
  found and fixed via live testing).
- Fails closed: any unexpected internal failure denies access, never grants it.
- Ships a demo "lock screen" Tkinter window showing the pipeline's state
  machine live against your webcam.
- Ships an evaluation tool (`faceauth evaluate`) that computes FAR/FRR/EER
  from similarity scores you supply.

## What this project does NOT do

- It does **not** replace, patch, hook, or otherwise modify Windows
  LogonUI, Winlogon, LSA, Credential Guard, or Windows Hello.
- It does **not** read, store, or transmit your Windows account password.
- It is **not** Windows Hello-equivalent security. Windows Hello's face
  authentication requires certified IR-camera hardware and meets a
  documented FAR < 0.001% / FRR < 5% bar
  (`docs/RESEARCH.md`); this project uses an ordinary RGB webcam and makes
  no such claim. See "RGB webcam limitations" below - this is stated
  repeatedly, deliberately, because it's the most important caveat in this
  repository.
- It does **not** retain raw enrollment photos by default.
- It does **not** log biometric data, raw images, passwords, or secrets
  (enforced structurally - see `docs/ARCHITECTURE.md` "Logging").
- It does **not** implement Phase 2 (the Windows Credential Provider) -
  that is a design document only (`docs/PHASE2_CREDENTIAL_PROVIDER.md`),
  not code.

## Setup

Requires Windows and Python 3.12 (pinned in `pyproject.toml` - the CV/ML
dependency ecosystem here, especially `mediapipe`, is most reliably
supported on 3.12 at the time this was built; see `docs/RESEARCH.md`).

```powershell
# From the repository root:
uv venv --python 3.12 .venv
uv pip install --python .venv -e ".[dev]"
python scripts/fetch_models.py   # downloads + checksum-verifies the ONNX/task model files into models/
```

(Any standard `venv` + `pip install -e ".[dev]"` workflow works too; `uv`
is just what was used during development.)

## Enrolling

```powershell
.venv\Scripts\faceauth.exe enroll --user-id alice
```

Collects `enrollment.num_samples` (default 5) independently-verified
samples via your webcam - for each, you'll need to satisfy a randomly
chosen liveness challenge (blink, or turn your head) within a short window.
Samples that fail quality or liveness checks are silently retried (up to an
attempt budget) rather than counted.

## Authenticating

```powershell
.venv\Scripts\faceauth.exe authenticate --user-id alice
```

Prints `ACCESS GRANTED (...)` or `ACCESS DENIED (...)` and exits 0/1
accordingly (2 if currently rate-limited).

## Demo lock-screen window

```powershell
.venv\Scripts\faceauth.exe demo --user-id alice --mode authenticate
# or: --mode enroll
```

A plain window (explicitly labeled "NOT Windows Hello / NOT LogonUI") that
shows the real pipeline's state live: CAMERA READY → FACE DETECTED →
CHECKING LIVENESS → VERIFYING IDENTITY → ACCESS GRANTED/DENIED → TRY AGAIN
/ COOLDOWN ACTIVE.

## Running tests

```powershell
.venv\Scripts\python.exe -m pytest -q
```

All tests run against mocked/fake camera, model, and liveness backends -
no webcam or GPU required - except `tests/test_real_models.py` (marked
`realmodel`) and `tests/test_storage_dpapi_backend.py`, which run against
the actual downloaded model files / real Windows DPAPI respectively, and
skip automatically if their prerequisites aren't present.

## Running the evaluation tool

`faceauth evaluate` computes FAR/FRR/EER from genuine/impostor similarity
scores **you already collected** - it does not scrape or ship any face
dataset. Prepare a JSON file:

```json
{"genuine": [0.7, 0.75, ...], "impostor": [0.1, 0.2, ...]}
```

```powershell
.venv\Scripts\faceauth.exe evaluate --scores scores.json --target-far 0.00001
```

Outputs EER, the EER threshold, a recommended operating threshold for your
target FAR, and a full ROC table (JSON).

## Models

| Stage | Model | License | File |
|---|---|---|---|
| Face detection | YuNet | MIT | `models/yunet_2023mar.onnx` |
| Face embedding | SFace (128-d) | Apache-2.0 | `models/sface_2021dec.onnx` |
| Liveness landmarks/blendshapes | MediaPipe Face Landmarker | Apache-2.0 | `models/face_landmarker.task` |

Full license detail, provenance, and the (deliberately not used by default)
InsightFace/dlib alternatives are in `docs/MODEL_LICENSES.md`. All three
files are checksum-pinned in `src/faceauth/model_registry.py` and
re-verified by `scripts/fetch_models.py`.

## Privacy design

- Raw enrollment frames are discarded immediately after embedding
  extraction, by default (`EnrollmentConfig.retain_raw_frames`, off by
  default; enabling it logs a loud warning every time).
- Templates store only fixed-size embedding vectors, never images.
- Templates are encrypted at rest (DPAPI on Windows;
  see `docs/RESEARCH.md` section 11).
- Logging cannot emit biometric data, images, or secrets - enforced by the
  logger's own type contract, not just convention (`docs/ARCHITECTURE.md`
  "Logging").

## Security assumptions & threat model

See `docs/THREAT_MODEL.md` for the full analysis (stolen templates, photo/
display/video spoofing, unknown users, log leakage, configuration
tampering, threshold manipulation, model replacement, corrupted templates,
denial of service, repeated guessing, and fail-closed behavior).

## RGB webcam limitations (read this before relying on this for anything real)

Windows Hello's own facial-recognition requirement is FAR < 0.001% and
TAR > 95%, achieved with a **dedicated IR camera** and certified
presentation-attack defenses
(`learn.microsoft.com/windows-hardware/design/device-experiences/windows-hello-biometric-requirements`).
This project uses an ordinary RGB webcam. An RGB sensor cannot
structurally distinguish a live face from a high-quality photo/video the
way an IR sensor can - there is no near-infrared reflectance signal to
check. **Do not describe or rely on this system as providing
Windows-Hello-equivalent security.** It is a convenience/demo
authentication control with a materially weaker presentation-attack
resistance profile, most importantly against video replay (see
`docs/THREAT_MODEL.md` §4).

## Liveness limitations

The default liveness check is active challenge-response via MediaPipe
blendshapes/landmarks, **BLINK challenges only by default**. It does
**not** defeat a video replay of the legitimate user performing the
requested action (no defense exists against this in Phase 1 - see
`docs/THREAT_MODEL.md` §4).

**This was live-tested against real spoof attempts with a real phone
screen, and the results are reported honestly, including a real gap that
was found and mitigated (not hidden):**

- **Blink correctly rejects a genuinely static photo.** A 10-second live
  trial holding a phone photo perfectly stationary showed the blink signal
  never came close to either pass threshold - see
  `docs/THREAT_MODEL.md` §2 for the exact numbers.
- **Head-turn detection was found, via live testing, to be spoofable by a
  stationary photo** - the same trial's turn-ratio signal crossed the pass
  threshold from ordinary camera/environmental jitter alone, no deliberate
  manipulation needed. This is a structural limitation (a 2D-landmark
  estimate can't distinguish real head rotation from any 2D shift of a
  flat image) rather than a mistuned number. **As a direct result, head-turn
  is excluded from the default challenge pool** (`LivenessConfig.enabled_
  challenges`, `DEFAULT_ENABLED_CHALLENGES` in `challenge_response.py`) -
  it remains implemented and selectable for anyone who wants to opt back in
  after further hardening, but is not a default security boundary.
- A secondary, independent mitigation (`min_face_continuity` in
  `capture_utils.py`) rejects attempts where face detection wasn't
  continuous through the window - it catches a phone/photo being visibly
  waved around, though it alone would not have been sufficient (hence
  disabling head-turn by default rather than relying on it).

An optional, disabled-by-default passive spoof-classifier backend exists
(`liveness/passive_onnx.py`) for anyone who wants to plug in their own
calibrated model; no such model is bundled (see `docs/MODEL_LICENSES.md`
for why).

The blink/head-turn thresholds themselves were calibrated against real
measured data (`scripts/calibrate_liveness.py`,
`tests/test_liveness_calibration.py`) after live testing found the
original guessed values unusable (0/12 real head-turn attempts passed
before recalibration).

## Troubleshooting

- **"could not open camera at device index 0"** - another application may
  have the webcam open, or `camera.device_index` in your config doesn't
  match your device. Check Windows Settings → Camera privacy settings too.
- **Enrollment/authentication keeps failing liveness** - make sure you
  actually perform the requested action (the window/CLI output shows which
  challenge is active) within the timeout; ensure good, even lighting.
- **`ModuleNotFoundError` for `win32crypt`/`pywin32`** - you're not on
  Windows, or the venv wasn't set up with the Windows-only dependency
  group; `storage.backend` falls back to `"file_dev"` in that case (see
  Configuration below), which is explicitly **not** secure for production.
- **Model file not found errors** - run `python scripts/fetch_models.py`.

## Configuration

Pass `--config path/to/config.json` to any CLI command; any subset of
`AppConfig`'s sections can be overridden (unspecified fields keep their
validated defaults). See `src/faceauth/config.py` for the full schema and
`docs/RESEARCH.md` for why each default was chosen. Example - relaxing the
rate limiter for local testing:

```json
{"rate_limit": {"max_consecutive_failures": 20, "base_cooldown_seconds": 5}}
```

## Architecture

See `docs/ARCHITECTURE.md` for the full component flow, interface table,
and folder structure.

## Future development

- Phase 2 (Windows Credential Provider) - design only, see
  `docs/PHASE2_CREDENTIAL_PROVIDER.md`. Not started.
- TPM-backed template hardening (NCrypt/Platform Crypto Provider) -
  designed, not implemented; see `docs/RESEARCH.md` section 11.
- Using this machine's IR camera (present on the dev machine, unused by
  Phase 1) for a real liveness/security improvement.
- Fine-tuning/replacing the embedding model - the `FaceEmbeddingModel`
  interface and ONNX Runtime backend make this a drop-in change; see
  `docs/RESEARCH.md` section 24.
