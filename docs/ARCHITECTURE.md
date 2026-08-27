# Architecture

This document describes the actual, implemented Phase 1 architecture. For
the research and rationale behind each choice, see `docs/RESEARCH.md`. For
what could go wrong, see `docs/THREAT_MODEL.md`.

For the Windows Credential Provider direction, read
`docs/PHASE2_SECURITY_REVIEW.md` and the ADRs in `docs/adr/` **before**
`docs/PHASE2_CREDENTIAL_PROVIDER.md` - the latter is a Phase 1-era design that
the review supersedes in part.

## What exists, and what does not

| Component | State |
|---|---|
| Python pipeline (`src/faceauth/`) | **Implemented and working.** Everything below describes this. |
| Native IPC contract scaffold (`native/`) | **Implemented, and deliberately inert.** A versioned message contract, parser, state machines, and a fake client/server pair that run on the normal desktop with opaque test identities and simulated outcomes. See `native/README.md`. |
| Windows Credential Provider | **Does not exist.** No COM implementation, no CLSID, no registration. |
| Windows service | **Does not exist.** No SCM code, no service binary, no installer. |
| Credential serialization | **Does not exist.** No `KERB_*` structure is constructed anywhere. |
| TPM / certificate / camera access from native code | **Does not exist.** |

Nothing in this repository reads or changes Windows authentication, registry,
LSA, Winlogon, LogonUI, Credential Guard, or Windows Hello state, and nothing
handles a Windows password.

## Component flow

```
                 Webcam (RGB)
                      |
                 CameraProvider           (camera/opencv_camera.py)
                      |
                 FaceDetector             (detection/yunet_detector.py - YuNet, cv2.FaceDetectorYN)
                      |
                 FaceQualityChecker       (quality/heuristic_quality.py)
                      |
                 LivenessProvider         (liveness/challenge_response.py - MediaPipe blink/head-turn
                      |                    challenge; optional passive_onnx.py backend via composite.py)
                 FaceEmbeddingModel       (embedding/sface_embedding.py - SFace, ONNX Runtime)
                      |
                 SimilarityEngine         (similarity/cosine_similarity.py)
                      |
                 AuthenticationPolicy     (policy/threshold_policy.py)
                      |
                 RateLimiter              (rate_limiting/cooldown_rate_limiter.py)
                      |
              ACCESS GRANTED / DENIED
```

Two orchestration services sit above these stages:

- `enrollment.py` — `EnrollmentService.enroll(user_id)`: repeats
  capture→detect→quality→liveness→embed until `EnrollmentConfig.num_samples`
  independently-verified samples are collected (with outlier rejection and
  an attempt budget), then stores a centroid + all sample embeddings via
  `TemplateStore`.
- `authentication.py` — `AuthenticationService.authenticate(user_id)`: runs
  the full pipeline once, fails closed at every stage (see
  `docs/THREAT_MODEL.md`), and returns an explicit `AuthResult` or raises
  `RateLimitedError` before any attempt is made.

Both share `capture_utils.run_liveness_challenge()` - the bounded capture
loop that issues a liveness challenge, feeds qualifying frames into it, and
returns the best (frame, face) pair alongside the liveness verdict.

`pipeline_factory.py` is the single place that maps `AppConfig` to concrete
implementations - every other module depends only on the interfaces in
`faceauth/interfaces/`.

## Interfaces (`src/faceauth/interfaces/`)

| Interface | Purpose | Default implementation |
|---|---|---|
| `CameraProvider` | Frame source | `OpenCvCameraProvider` (also: `ArrayFeedCameraProvider` for replay/tests) |
| `FaceDetector` | Locate faces + 5-pt landmarks | `YuNetFaceDetector` |
| `FaceQualityChecker` | Reject unusable frames | `HeuristicFaceQualityChecker` |
| `LivenessProvider` | Challenge-response / passive spoof check | `MediaPipeChallengeResponseLiveness` (BLINK-only by default - see `docs/THREAT_MODEL.md` §2 for why head-turn was disabled after live testing), optionally composed with `PassiveOnnxSpoofLiveness` via `CompositeLivenessProvider` |
| `FaceEmbeddingModel` | Face → normalized vector | `SFaceEmbeddingModel` |
| `SimilarityEngine` | Compare probe vs. stored template | `CentroidCosineSimilarityEngine` (also: `MaxSampleCosineSimilarityEngine`) |
| `AuthenticationPolicy` | Similarity → GRANT/DENY | `ThresholdAuthenticationPolicy` |
| `TemplateStore` | Encrypted template persistence | `DpapiTemplateStore` (Windows), `FileTemplateStore` (dev fallback) |
| `RateLimiter` | Cooldown/backoff | `PersistentCooldownRateLimiter` (default - file-backed, survives process restarts), `CooldownRateLimiter` (in-memory, used directly by fast unit tests) |

Swapping any backend means adding one class + one branch in
`pipeline_factory.py` - no other file changes.

## Data types (`pipeline_types.py`)

`Frame`, `FaceBox`, `QualityReport`, `LivenessResult`, `Embedding` (enforces
L2-normalization in `__post_init__`), `StoredTemplate`, `AuthResult`,
`EnrollmentResult`, `DemoState`. All immutable dataclasses.

## Configuration (`config.py`)

Pydantic models (`AppConfig` and one sub-model per pipeline stage), loaded
via `ConfigSource` (`DefaultConfigSource` or `JsonFileConfigSource`).
Invalid configuration (bad JSON, out-of-range values, cross-field
constraints like `min_face_area_ratio >= max_face_area_ratio`) raises a
single `ConfigurationError` - callers never need to catch
pydantic/json-specific exceptions.

## Logging (`logging_utils.py`)

`SecurityLogger.log_event(event, **fields)` is the only logging entry
point application code uses. It statically rejects (raises `TypeError`)
any field whose name matches a biometric/secret denylist (except safe
`*_id` identifiers) or whose value isn't a JSON primitive - so an embedding
vector or raw frame cannot be logged even by a future coding mistake. A
`PrivacyRedactionFilter` on the log handler is a second, independent layer
that redacts anything that looks like a numpy array repr regardless of how
it reached the logger.

## Demo UI (`demo_ui.py`)

A plain Tkinter window (NOT a Windows LogonUI clone) that drives the real
`EnrollmentService`/`AuthenticationService` on a background thread and
reflects the actual `DemoState` transitions those services report through
an optional `on_state` callback: `CAMERA_READY → FACE_DETECTED →
CHECKING_LIVENESS → VERIFYING_IDENTITY → ACCESS_GRANTED/DENIED → TRY_AGAIN /
COOLDOWN_ACTIVE`. The callback only ever reports states derived from the
real decision already made in `authentication.py`/`enrollment.py` - the UI
cannot influence the decision.

## CLI (`cli.py`)

`faceauth enroll|authenticate|demo|evaluate|list-users|delete-user`, all
built from `pipeline_factory.py`. See the README for full usage.

## Project folder structure

```
ai-face-auth/
  pyproject.toml
  README.md
  models/                       real ONNX/task weights (+ scripts/fetch_models.py to (re)download)
  data/                         created at runtime: templates/, logs/ (gitignored)
  docs/
    RESEARCH.md                   research synthesis / source of truth
    ARCHITECTURE.md               this file
    THREAT_MODEL.md
    PHASE2_SECURITY_REVIEW.md     Phase 2 architecture + security review, GO/NO-GO result
    PHASE2_ACCEPTANCE_CRITERIA.md what Phase 2 delivered; Phase 3 entry criteria
    PHASE2_CREDENTIAL_PROVIDER.md Phase 1-era design, superseded in part by the review
    MODEL_LICENSES.md
    ACCEPTANCE_AUDIT.md
    adr/
      0001-windows-account-and-credential-strategy.md
      0002-process-service-and-camera-boundaries.md
      0003-ipc-security-protocol.md
      0004-enrollment-provisioning-and-recovery.md
  scripts/
    fetch_models.py
    calibrate_liveness.py         live diagnostic tool - prints real blink/head-turn signal values
  src/faceauth/
    interfaces/                  abstract contracts
    camera/ detection/ quality/ embedding/ liveness/ similarity/ storage/ policy/ rate_limiting/
    config.py  logging_utils.py  exceptions.py  pipeline_types.py
    capture_utils.py  enrollment.py  authentication.py
    pipeline_factory.py  demo_ui.py  cli.py  evaluate.py  model_registry.py
  tests/
    conftest.py  test_*.py
  native/                        INERT IPC contract scaffold - not a provider, not a service
    CMakeLists.txt  README.md
    include/faceauth/ipc/        protocol, wire, state_machine, replay_cache,
                                 diagnostics, random, clock, transport, boundaries, fake_peer
    src/                         implementations
    tools/fake_peer_main.cpp     faceauth_ipc_fake - runs one protocol exchange
    tests/                       74 protocol + 8 named-pipe test cases
  .github/
    workflows/                   ci.yml (Python + native x64 Debug/Release + hygiene), codeql.yml
    dependabot.yml  pull_request_template.md  ISSUE_TEMPLATE/
```

## Proposed Phase 3 topology (not implemented)

Recorded here only so the boundary between "what runs today" and "what is
designed" is visible in one place. Full detail and its open blockers are in
`docs/adr/0002-process-service-and-camera-boundaries.md`.

```
LogonUI.exe (secure desktop, SYSTEM)
  |   thin credential provider DLL - status-only UI, NO camera preview,
  |   no ML, no model files, no camera handle
  |
  |   named pipe, explicit SDDL: SYSTEM + NT SERVICE\FaceAuthVerifier only
  |   messages carry NO frames, embeddings, templates, passwords,
  |   certificates, keys, or reusable assertions
  v
verification service (Session 0, LOCAL SERVICE, restricted service SID)
  |   opens the camera, runs the pipeline, returns a short-lived, single-use,
  |   request/identity/nonce/deadline-bound verdict
  v
on ALLOW: release a pre-provisioned certificate credential to the
smart-card logon path -> LSA / Kerberos / KDC make the real decision
```

Two parts of that diagram are unproven and block Phase 3: whether a
third-party Session 0 service can open a camera before interactive logon
(**B1**), and whether pre-logon latency is acceptable (**B2**). The IPC layer
in the middle is what `native/` implements, inertly.
