# FaceAuth

[![CI](https://github.com/AddysEdge/ai-face-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/AddysEdge/ai-face-auth/actions/workflows/ci.yml)
[![CodeQL](https://github.com/AddysEdge/ai-face-auth/actions/workflows/codeql.yml/badge.svg)](https://github.com/AddysEdge/ai-face-auth/actions/workflows/codeql.yml)

A local, offline, webcam-based face-authentication **demo/research
prototype**. It is a longer-term exploration into whether a legitimate,
Microsoft-supported Windows Credential Provider could one day offer face
authentication as an alternative sign-in method. **It does not touch Windows
sign-in in any way, and after the Phase 2 review it is clear that for a local
Windows account it never can - see below.**

## Current status

| | |
|---|---|
| **Phase 1 - standalone Python application** | **Complete.** Enrollment, authentication, liveness, encrypted templates, rate limiting, CLI, demo window, evaluation tooling. 137 tests. |
| **Phase 2 - security and feasibility review + inert native scaffold** | **Complete.** Architecture review, four ADRs, and a non-activating C++ IPC contract scaffold under [`native/`](native/). |
| **Phase 3 - an actual Windows Credential Provider** | **Not started, and gated.** Two blockers are unproven. See [entry criteria](docs/PHASE2_ACCEPTANCE_CRITERIA.md). |

**No Credential Provider is registered. No Windows service is installed. No
Windows password is handled anywhere in this repository.** Nothing here reads
or changes Windows authentication, registry, LSA, Winlogon, LogonUI, Credential
Guard, or Windows Hello state.

### The Phase 2 result, stated plainly

The [Phase 2 security review](docs/PHASE2_SECURITY_REVIEW.md) reached
**CONDITIONAL GO** - and the condition changes the product:

> The originally intended use case - **face unlock for a local Windows account
> on a personal machine** - is a **NO-GO**. There is no documented, publicly
> supported Windows credential mechanism that lets a third-party credential
> provider authenticate a *local* account without handling that account's
> password, which this project forbids absolutely.

| Windows account type | Result |
|---|---|
| Local Windows account | **NO-GO** |
| Microsoft account (MSA) | **NO-GO** |
| Active Directory domain account | **CONDITIONAL GO** - needs a domain controller, an enterprise PKI, certificate enrolment, account mapping, and CRL/OCSP reachable before sign-in |
| Microsoft Entra ID account | **DEFERRED - unproven** |

Why: certificate logon is Kerberos PKINIT and terminates at a KDC holding an
AD DS account object; Windows Hello for Business has no local-account
deployment model; and there is no public API by which a third party can gate
the Windows Hello NGC container. Each of those is quoted from Microsoft's own
documentation in
[ADR-0001](docs/adr/0001-windows-account-and-credential-strategy.md).

So for a personal machine, this repository's application-level control **is**
the answer, not a stepping stone to one.

Two blockers remain open before any Phase 3 work could begin: whether a
third-party Session 0 service can open a camera before interactive logon
(**B1**), and whether pre-logon latency and reliability are acceptable
(**B2**). If B1 cannot be cleared using documented APIs, the architecture is a
NO-GO outright.

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
- It does **not** implement a Windows Credential Provider. Nothing registers
  a COM class or a CLSID, nothing installs a Windows service, and nothing
  constructs a Windows credential structure. The `native/` directory holds an
  **inert** IPC contract scaffold whose fake client and server use opaque test
  identities and simulated outcomes, and label every result
  `PROTOCOL-TEST RESULT (NOT A WINDOWS AUTHENTICATION DECISION)`.

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
.venv\Scripts\ruff.exe check --no-cache src tests scripts
.venv\Scripts\mypy.exe --no-incremental src
```

All tests run against mocked/fake camera, model, and liveness backends -
no webcam or GPU required - except `tests/test_real_models.py` (marked
`realmodel`) and `tests/test_storage_dpapi_backend.py`, which run against
the actual downloaded model files / real Windows DPAPI respectively, and
skip automatically if their prerequisites aren't present.

If your environment denies pytest access to the system temp directory,
redirect it into the repository (`.pytest_tmp/` is gitignored):

```powershell
.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest_tmp
```

## Building and testing the native scaffold

Optional - only needed if you are working on `native/`. Requires Windows x64,
MSVC (VS 2022 Build Tools, "Desktop development with C++"), and CMake 3.21+.
There are no third-party native dependencies.

```powershell
cmake -S native -B native/build -A x64
cmake --build native/build --config Debug
ctest --test-dir native/build -C Debug --output-on-failure
cmake --build native/build --config Release
ctest --test-dir native/build -C Release --output-on-failure
```

Warnings are errors (`/W4 /permissive- /WX`). See [`native/README.md`](native/README.md)
for what the scaffold is, what it deliberately is not, and how its 43 protocol
tests map to the required coverage.

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

## Documentation

| Document | What it covers |
|---|---|
| [`docs/PHASE2_SECURITY_REVIEW.md`](docs/PHASE2_SECURITY_REVIEW.md) | The Phase 2 architecture and security review, and its GO/NO-GO result |
| [`docs/PHASE2_ACCEPTANCE_CRITERIA.md`](docs/PHASE2_ACCEPTANCE_CRITERIA.md) | What Phase 2 delivered, and the exact entry criteria for Phase 3 |
| [`docs/adr/0001-...`](docs/adr/0001-windows-account-and-credential-strategy.md) | Which Windows accounts can be supported, and what credential is actually submitted |
| [`docs/adr/0002-...`](docs/adr/0002-process-service-and-camera-boundaries.md) | Process/service topology, Session 0 camera blockers, why the preview was removed |
| [`docs/adr/0003-...`](docs/adr/0003-ipc-security-protocol.md) | The versioned IPC protocol and its threat model |
| [`docs/adr/0004-...`](docs/adr/0004-enrollment-provisioning-and-recovery.md) | Enrollment, provisioning, revocation, recovery, uninstall |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | The implemented Phase 1 architecture |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | 13 threats, mitigations, and residual risks |
| [`docs/RESEARCH.md`](docs/RESEARCH.md) | Why every model and design choice was made |
| [`docs/MODEL_LICENSES.md`](docs/MODEL_LICENSES.md) | Model provenance and licensing |
| [`docs/ACCEPTANCE_AUDIT.md`](docs/ACCEPTANCE_AUDIT.md) | Requirement-to-proof mapping |
| [`native/README.md`](native/README.md) | The inert IPC scaffold: build, test, and what it deliberately is not |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability, and what this project will never do |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Setup, commands, security boundaries, prohibited changes |

## Future development

- **Phase 3 (Windows Credential Provider) - gated, not started.** Blocked on
  B1/B2 plus a domain+PKI lab and an explicit product decision to accept the
  AD-domain-only scope. See
  [`docs/PHASE2_ACCEPTANCE_CRITERIA.md`](docs/PHASE2_ACCEPTANCE_CRITERIA.md)
  Part B. Note that for a local account this is a **NO-GO**, so "wait for
  Phase 3" is not the answer for a personal machine - this application is.
- TPM-backed template hardening (NCrypt/Platform Crypto Provider) -
  designed, not implemented; see `docs/RESEARCH.md` section 11.
- Using this machine's IR camera (present on the dev machine, unused today)
  for a real liveness/security improvement.
- Fine-tuning/replacing the embedding model - the `FaceEmbeddingModel`
  interface and ONNX Runtime backend make this a drop-in change; see
  `docs/RESEARCH.md` section 24.
