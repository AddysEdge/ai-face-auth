# Final Acceptance Audit

Maps every requirement from the project goal to the exact file, test, doc
section, or execution result that proves it. Compiled after the final
verification pass (full test suite, lint, type-check, and live app launch)
documented at the bottom of this file.

**Phase 2 note.** This document covers the Phase 1 requirements. Phase 2's own
acceptance criteria, its Part C exclusion list, and the Phase 3 entry criteria
live in [`PHASE2_ACCEPTANCE_CRITERIA.md`](PHASE2_ACCEPTANCE_CRITERIA.md); a
summary of what changed is in the ["Phase 2 delta"](#phase-2-delta) section at
the end of this file. Every Phase 1 row below was re-verified after the Phase 2
work and still holds - **no file under `src/`, `tests/`, or `scripts/` was
modified in Phase 2.**

## Phase 1 requirements (1-18)

| # | Requirement | Proof |
|---|---|---|
| 1 | Webcam capture | `src/faceauth/camera/opencv_camera.py` (`OpenCvCameraProvider`); `tests/test_camera.py`; live-verified against the real `USB2.0 FHD UVC WebCam` during `enroll`/`demo` runs this session |
| 2 | Reliable face detection | `src/faceauth/detection/yunet_detector.py` (YuNet via `cv2.FaceDetectorYN`); `tests/test_real_models.py`; live logs show detection state transitioning from "no face" to challenge-specific outcomes on real video |
| 3 | Face quality checks | `src/faceauth/quality/heuristic_quality.py`; `tests/test_quality.py` (6 cases) |
| 4 | Multi-sample enrollment | `src/faceauth/enrollment.py` (`EnrollmentService`, `EnrollmentConfig.num_samples >= 3` enforced); `tests/test_enrollment.py` |
| 5 | Normalized face embeddings | `src/faceauth/embedding/sface_embedding.py`; `Embedding.__post_init__` enforces L2-norm (`pipeline_types.py`); `tests/test_real_models.py::test_sface_embedder_matches_opencv_reference_implementation` (cosine 0.9999998 vs. OpenCV's own reference) |
| 6 | Multi-sample aggregation per research | `enrollment.py::_centroid` (mean-then-renormalize, per `RESEARCH.md` §8); individual samples also retained for `MaxSampleCosineSimilarityEngine` |
| 7 | No raw photos retained by default | `EnrollmentConfig.retain_raw_frames` defaults `False`; `tests/test_enrollment.py::test_enrollment_does_not_write_raw_frames_by_default` and the opt-in counterpart test |
| 8 | Templates protected locally (strongest practical mechanism) | `src/faceauth/storage/dpapi_template_store.py` (real `win32crypt.CryptProtectData`/`CryptUnprotectData`); `tests/test_storage_dpapi_backend.py` (6 real-DPAPI tests); TPM hardening path designed, not implemented - `RESEARCH.md` §11, `THREAT_MODEL.md` §1 |
| 9 | Documented dev fallback | `src/faceauth/storage/file_template_store.py` (loud DEV-ONLY warning every construction); `config.py StorageConfig.backend`; README "Troubleshooting" |
| 10 | Full authentication pipeline | `src/faceauth/authentication.py`; `tests/test_authentication.py` (14 tests); live-verified CLI run |
| 11 | Similarity scores | `SimilarityEngine.compare` returns float; `AuthResult.similarity`; `tests/test_similarity.py` |
| 12 | Configurable threshold | `PolicyConfig.similarity_threshold`; `tests/test_config.py`, `tests/test_policy.py` |
| 13 | Threshold not guessed | 0.363 = OpenCV's own published SFace operating point, confirmed directly against `docs.opencv.org`'s tutorial during research; `faceauth evaluate` recalibrates from real data |
| 14 | Modular liveness, RGB limits documented | `interfaces/liveness.py`, `challenge_response.py`, `passive_onnx.py`, `composite.py`; `THREAT_MODEL.md` §2-4; README "Liveness limitations" |
| 15 | Rate limiting | `rate_limiting/cooldown_rate_limiter.py`; `tests/test_rate_limiter.py` (7 tests) + integration tests |
| 16 | Fail closed | `authentication.py`'s single try/except → DENY structure; `THREAT_MODEL.md` "Fail-closed behavior"; `tests/test_authentication.py::test_camera_unavailable_fails_closed` etc. |
| 17 | Privacy-conscious logging | `logging_utils.py` (type-contract + redaction filter); `tests/test_logging_utils.py` (10 tests, incl. a regression test for a real over-broad-filter bug found and fixed live this session) |
| 18 | Demo lock-screen, not impersonating LogonUI | `demo_ui.py` (explicit "DEMO ONLY" banner/title); live-verified startup in both modes this session |

## Architectural modularity

All 11 named abstractions exist as real interfaces with ≥1 concrete
implementation each: `CameraProvider`, `FaceDetector`,
`FaceQualityChecker`, `FaceEmbeddingModel`, `LivenessProvider`,
`TemplateStore`, `SimilarityEngine`, `AuthenticationPolicy`, `RateLimiter`
(all in `src/faceauth/interfaces/`), `SecurityLogger` (`logging_utils.py`),
`ConfigSource`/`AppConfig` (`config.py`). `pipeline_factory.py` is the sole
place that maps config to concrete classes - see `docs/ARCHITECTURE.md`.

## Testing (all 23 listed categories)

| Category | Test(s) |
|---|---|
| Enrollment | `test_enrollment.py` |
| Embedding normalization | `test_pipeline_types.py` |
| Similarity calculations | `test_similarity.py` |
| Authentication acceptance | `test_authentication.py::test_matching_face_is_granted` |
| Authentication rejection | `::test_non_matching_face_is_denied` |
| Threshold boundaries | `test_policy.py` (parametrized boundary cases) |
| Unknown users | `test_authentication.py::test_unknown_user_is_denied` |
| No-face condition | `::test_no_face_detected_is_denied` |
| Multiple-face condition | `::test_multiple_faces_detected_is_denied` |
| Failed liveness | `::test_failed_liveness_denies_even_with_perfect_match` |
| Unavailable camera | `::test_camera_unavailable_fails_closed`, `test_camera.py` |
| Corrupt biometric template | `::test_corrupted_template_fails_closed`, `test_storage_*_backend.py` |
| Missing template | `test_storage_file_backend.py::test_load_missing_user_raises_template_not_found` |
| Rate limiting | `test_rate_limiter.py`, `test_authentication.py::test_repeated_failures_trigger_rate_limiting` |
| Cooldown expiration | `test_rate_limiter.py::test_cooldown_expires_after_the_configured_duration` |
| Configuration parsing | `test_config.py` |
| Malformed configuration | `test_config.py` (5 malformed-input cases) |
| Security-sensitive exception handling | `authentication.py`'s `deny()` paths; `test_authentication.py` |
| Fail-closed behavior | (see above) |
| Mocked model outputs | `conftest.py::FakeEmbedder`, `FakeDetector` |
| Mocked camera inputs | `conftest.py::FakeCamera`, `ArrayFeedCameraProvider` |
| Mocked liveness results | `conftest.py::FakeLiveness`, `NeverObservesLiveness` |

## Evaluation tooling

`src/faceauth/evaluate.py` + `tests/test_evaluate.py` (7 tests) + `faceauth
evaluate` CLI command, live-verified against a synthetic score file this
session (EER/threshold/ROC output confirmed correct).

## Documentation

README (all required sections present - see the file's table of contents-
equivalent headings), `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` (all
13 listed threats + fail-closed section), `docs/PHASE2_CREDENTIAL_PROVIDER.md`
(all 7 listed subtopics), `docs/MODEL_LICENSES.md`, `docs/RESEARCH.md`.

## Security restrictions

Grep-verified across `src/`: the only occurrences of "LogonUI"/"Winlogon"/
"LSA" are two disclaiming comments/docstrings and one UI label explicitly
stating this app does *not* touch them (`__init__.py`, `demo_ui.py`) - no
integration code exists. No Windows-password-handling code exists anywhere
(zero matches for password-related patterns). No lock-screen-injection code
exists. The application is a fully standalone Python process with no hooks
into any real Windows authentication surface.

## Quality requirements

Type hints throughout (`from __future__ import annotations` + full
annotations, mypy-clean); no file exceeds ~250 lines; shared logic
factored into `capture_utils.py`/`pipeline_factory.py` rather than
duplicated; dependencies exactly pinned in `pyproject.toml` against the
versions actually installed and tested; camera release verified even on
exception (`test_camera.py`); model init failures raise a specific
exception type everywhere; DPAPI unavailability raises a clear `RuntimeError`
with an actionable message; templates serialize as JSON, never pickle; no
bare `except: pass` anywhere in `src/` (grep-verified); no test was deleted
or weakened to make the suite pass - the two real bugs found during live
testing (see below) were fixed at the root cause, with a regression test
added for the logging one and the live re-run itself serving as the
regression check for the other.

## Completion conditions (1-33)

1. **App runs on its intended environment** - Python 3.12 venv built and
   installed for real (`uv venv` + `uv pip install -e ".[dev]"`); `faceauth
   enroll`/`authenticate`/`demo`/`list-users`/`evaluate` all executed for
   real against this machine during development; 107 automated tests pass.
2. **Webcam integration exists** - `camera/opencv_camera.py`; real webcam
   opened and read from during live testing.
3. **Enrollment works** - real CLI run executed (see "Real-hardware
   verification" below); 6 automated tests cover the full success/failure
   space with deterministic fakes.
4. **Embeddings via the selected pretrained model** - SFace via ONNX
   Runtime, cross-verified against OpenCV's own reference implementation
   (cosine similarity 0.9999998 on a synthetic probe).
5. **Templates protected locally** - real DPAPI round-trip tests, 6/6
   passing.
6. **Authentication works** - real CLI run executed; 14 automated tests.
7. **Unknown users rejected** - `test_unknown_user_is_denied`; live CLI run
   against a never-enrolled user id.
8. **Liveness implemented** - real MediaPipe Face Landmarker inference on
   live video (see below); not a stub.
9. **Liveness failures reject authentication** -
   `test_failed_liveness_denies_even_with_perfect_match`; live-verified
   (a real `authenticate` run was denied specifically because the
   requested challenge wasn't satisfied).
10. **Authentication fails closed** - `test_camera_unavailable_fails_closed`,
    `test_corrupted_template_fails_closed`, `THREAT_MODEL.md`.
11. **Threshold configuration works** - `test_config.py`, `test_policy.py`.
12. **Rate limiting works** - `test_rate_limiter.py` (7 tests).
13. **No sensitive biometric material in logs** - `test_logging_utils.py`
    (10 tests); the real log file produced during live testing was read
    and manually confirmed to contain only structured event names/reasons,
    no vectors/images.
14. **Raw enrollment images not retained by default** - dedicated test,
    passing.
15. **Fake lock-screen demo works** - both `--mode enroll` and `--mode
    authenticate` launched live this session; process stayed alive (no
    crash) through the verification window in both cases.
16. **Model backend replaceable** - `FaceEmbeddingModel` interface;
    InsightFace documented as a concrete, ready-to-wire alternative.
17. **Liveness backend replaceable** - `LivenessProvider` interface;
    `PassiveOnnxSpoofLiveness` is a second, real (non-stub) implementation.
18. **Template storage backend replaceable** - `TemplateStore` interface;
    two real, tested implementations (DPAPI, file-dev).
19. **Tests cover security-critical behavior** - 107 tests, see table above.
20. **Full test suite exits successfully** - confirmed: `107 passed`.
21. **Static/lint/type checks succeed** - `ruff check .` → "All checks
    passed!"; `mypy src/faceauth` → "Success: no issues found in 45 source
    files."
22. **Application startup actually attempted and verified** - see "Real-
    hardware verification" below; this was not assumed.
23. **README accurately reflects actual behavior** - written from and
    cross-checked against the actual implemented CLI/config surface.
24. **Threat model exists** - `docs/THREAT_MODEL.md`.
25. **Evaluation tooling exists** - `evaluate.py` + CLI, live-verified.
26. **Model/license info documented** - `docs/MODEL_LICENSES.md`.
27. **RGB webcam limitations documented** - README, RESEARCH.md,
    THREAT_MODEL.md (deliberately repeated in each).
28. **Phase 2 documented via legitimate mechanisms** -
    `docs/PHASE2_CREDENTIAL_PROVIDER.md`.
29. **No Windows authentication bypass** - grep-verified; standalone
    process only.
30. **No Windows password stored/extracted** - grep-verified; no such
    code exists anywhere in the repository.
31. **No unfinished critical TODOs** - grep-verified: zero matches for
    TODO/FIXME/XXX/`NotImplementedError`/bare `pass` in `src/`.
32. **No secrets or accidental biometric artifacts in the repo** - grep-
    verified no secrets; the `data/` directory (containing only structured
    logs from live testing, no images/embeddings) was deleted before
    delivery; `.gitignore` excludes it and the model binaries going
    forward.
33. **This document.**

## Real-hardware verification performed this session

This was not skipped or assumed - the following were actually executed
against this machine's real webcam, real Windows DPAPI, and the real
downloaded model files:

- `faceauth enroll --user-id smoketest` - ran the full capture→detect→
  quality→liveness loop against the live webcam. Real face detection
  occurred (logs show `no_face_observed_during_challenge` giving way to
  `no_transient_head_turn_detected` / `no_transient_blink_detected` as a
  real face came in and out of frame), and the attempt-budget-exhaustion
  path was genuinely exercised and handled cleanly (`EnrollmentFailedError`,
  exit code 1, no crash).
- `faceauth authenticate --user-id nobody-enrolled-yet` - same real capture
  path; correctly denied with reason `liveness_failed:...` before ever
  reaching the (also-tested) `unknown_user` path.
- **A real bug was found and fixed via this live run**: a keyword-argument
  collision in `AuthenticationService`'s internal `deny()` helper (`reason`
  passed both positionally and via `**fields`) that only manifested when
  the liveness-failed branch actually fired - something none of the mocked
  unit tests happened to trigger because their fakes don't produce the same
  code path shape. Fixed and re-verified live.
- **A second real bug was found via the automated suite** (not live
  hardware, but real code, not a hypothetical): the privacy log filter's
  substring match for `"template"` also blocked the harmless
  `template_id` field. Fixed, with a regression test added
  (`test_log_event_allows_opaque_id_fields_despite_substring_match`).
- `faceauth demo --user-id launchtest --mode authenticate` and `--mode
  enroll` - both launched for real; the process remained alive (no
  exception, no crash) through an 8-second/6-second verification window
  each, confirming the full pipeline construction (camera, YuNet, SFace,
  MediaPipe Face Landmarker, DPAPI store, rate limiter, Tkinter UI) - not
  just imports - succeeds end to end.
- `faceauth evaluate --scores <synthetic file> --target-far 0.05` - real
  run, correct EER/threshold/ROC output.
- `faceauth list-users` - real run against the real DPAPI-backed store
  (empty result, no crash).

The one gap noted at the end of the prior session ("no human present to
perform the liveness gesture") was closed in a follow-up supervised
session with a real person at the keyboard. Full results below.

## Supervised live verification session (real human, real face)

Every item was executed for real against this machine's webcam, a real
enrolled face, real Windows DPAPI, and real corrupted data - not simulated,
not assumed:

- **Enrollment**: `faceauth enroll --user-id primary` completed with 5/5
  real samples collected and a real template written.
- **Template storage/reload**: the on-disk `.dpapi` file was inspected
  directly - real DPAPI ciphertext (recognizable standard DPAPI blob
  header), no plaintext user_id, not JSON. Decrypted and inspected
  programmatically: 5 real 128-d sample embeddings + centroid, all
  correctly L2-normalized. `list-users` round-tripped the real decrypt.
- **Authentication (success)**: real `authenticate` runs granted access
  multiple times with real similarity scores (0.70-0.87 range against a
  0.363 threshold), both blink and head-turn challenges succeeding live at
  various points during testing.
- **Liveness with a real human**: both BLINK and (pre-mitigation)
  TURN_HEAD challenges were completed live by a real person on cue,
  multiple times, including a deliberate-failure test (denied correctly
  when the requested gesture was withheld).
- **Photo/phone-screen spoof attempts**: tested for real with an actual
  phone screen. **Found two real, live-confirmed vulnerabilities and fixed
  both** (see "Real bugs found and fixed this session" below) - after the
  fixes, two independent live spoof re-attempts were both correctly
  DENIED, immediately followed by a real face re-authenticating
  successfully (proving the fix didn't break the legitimate path).
- **No-face / camera-blocked**: live-tested by stepping out of frame -
  clean `ACCESS DENIED (liveness_failed:no_face_observed_during_challenge)`,
  no crash.
- **Corrupted template**: the real enrolled template file was deliberately
  byte-corrupted, then a real authentication attempt (real face, real
  blink) reached the template-decrypt stage and received a genuine
  `CryptUnprotectData` failure ("The data is invalid"), correctly
  converted to `TemplateCorruptedError` and denied as
  `security_critical_failure`. Template restored from backup and
  re-verified intact (5 samples) afterward.
- **Rate limiting**: live-tested via repeated real CLI invocations (each a
  separate OS process). Confirmed accumulation of failures across process
  boundaries, a real `COOLDOWN ACTIVE - retry in Ns` block that prevented
  the camera from even opening on the blocked attempt, and natural
  cooldown expiry - all matching the automated test suite's predictions
  exactly (cooldown duration matched configured `base_cooldown_seconds`
  precisely).

### Real bugs found and fixed this session

1. **Challenge window was silently ~1.0s instead of the intended ~4s**,
   because the loop was bounded by a fixed frame count sized for an
   assumed frame rate that didn't match this hardware's actual throughput.
   Fixed by switching to a wall-clock deadline
   (`capture_utils.run_liveness_challenge`), with frame count demoted to a
   safety cap. Also found: the CLI never announced which challenge was
   active, and even after adding that, stdout buffering delayed the
   announcement until process exit when not attached to a real terminal.
   Both fixed; regression tests added (`test_capture_utils.py`).
2. **Head-turn liveness threshold was initially miscalibrated** (0/12 real
   attempts passed) from an unverified degrees-to-ratio heuristic. Recalibrated
   from real measured data via a new diagnostic tool
   (`scripts/calibrate_liveness.py`), then **redesigned** from an
   absolute-baseline check to a swing-based check after a second live trial
   showed the absolute-zero requirement was itself unusable (real resting
   baseline is never near zero on this camera setup).
3. **Security-critical: head-turn liveness was spoofable by a static
   photo.** Live spoof testing found a genuinely stationary (propped, not
   hand-held) photo could still cross the head-turn swing threshold from
   ordinary camera/environmental jitter alone - confirmed in a controlled
   trial where the same photo's blink signal stayed safely bounded the
   entire time. Root cause is structural (2D landmarks can't distinguish
   real head rotation from any 2D shift of a flat image), not a
   mistunable number. Fixed by excluding head-turn from the default
   challenge pool (`DEFAULT_ENABLED_CHALLENGES` = BLINK-only); head-turn
   remains implemented/selectable, not deleted. A secondary
   `min_face_continuity` mitigation was also added after an earlier spoof
   attempt showed severe detection dropouts from a hand-waved phone.
   Verified fixed: 2/2 live spoof re-attempts denied post-fix.
4. **Blink threshold's low-end gate was an unreliable bottleneck for
   legitimate users** - real deliberate blinks reliably peaked far above
   the high threshold, but the required "must also dip below 0.15" rarely
   triggered against a real ~0.20-0.30 open-eye baseline. Raised to 0.20,
   grounded in real data; verified this does not weaken spoof resistance
   (governed entirely by the high threshold, which the real spoof trial
   never approached).
5. **Rate limiting provided no real protection across separate CLI
   invocations** - each `faceauth authenticate` process built a fresh
   in-memory limiter, so repeated shell invocations never accumulated
   failures. Fixed with `PersistentCooldownRateLimiter`, a file-backed
   limiter keyed to wall-clock time so state survives process restarts;
   made the default. Verified live (see above) and with 8 new automated
   tests (`test_persistent_rate_limiter.py`).

All fixes are grounded in real measured data (not guessed), have
regression tests, and were re-verified live after the fix, not just
by the automated suite. Full test count after this session: **137
passing**, ruff clean, mypy clean (up from 111 at the start of this
session).

---

## Phase 2 delta

Phase 2 added a security and feasibility review, four ADRs, an inert native IPC
scaffold, CI, and community files. It changed **no Phase 1 source code**.

### Phase 1 preservation, re-verified after Phase 2

| Requirement | Still true? | Evidence |
|---|---|---|
| Biometric data stays on the machine | Yes | No frame, template, or embedding is transmitted anywhere; `native/` has no networking and its transports are in-process or a local pipe |
| ~~Works fully offline~~ | **No - claim retracted** | The bundled MediaPipe binary uploads usage telemetry to `play.googleapis.com` on session teardown. Pre-existing, not added by Phase 2, and not disableable upstream. See `docs/PRIVACY_NETWORK_AUDIT.md` and ADR-0005 |
| Unexpected errors fail closed | Yes | `authentication.py`'s single try/except is untouched; the native layer adopts the same rule structurally (ADR-0003 section 5.7) |
| Raw enrollment images not retained by default | Yes | `EnrollmentConfig.retain_raw_frames` unchanged |
| Templates protected locally | Yes | `DpapiTemplateStore` unchanged |
| Privacy-safe logging restrictions intact | Yes | `logging_utils.py` unchanged; `native/` mirrors the discipline in `DiagnosticEvent` |
| Rate limiting persistent | Yes | `PersistentCooldownRateLimiter` unchanged, still the default |
| CLI and demo behaviour compatible | Yes | `cli.py`, `demo_ui.py` unchanged |
| States clearly that it does not integrate with Windows sign-in | Yes, and more explicitly | README "Current status"; `docs/ARCHITECTURE.md` "What exists, and what does not" |
| RGB-camera and liveness limitations prominently documented | Yes | README, `THREAT_MODEL.md` sections 2-4, `SECURITY.md` "Known limitations" |

Verify the no-source-change claim directly:

```
git diff --stat main...phase-2-security-foundation -- src tests scripts
```

### Phase 2 requirements

| Requirement | Proof |
|---|---|
| Complete architecture and security review | `docs/PHASE2_SECURITY_REVIEW.md` |
| Credential strategy GO / CONDITIONAL GO / NO-GO | `docs/adr/0001-...` section 10 - **CONDITIONAL GO overall; NO-GO for local accounts and MSA** |
| Supported and unsupported account types explicit | `docs/adr/0001-...` section 5.1 |
| Certificate/smart-card feasibility, and what it requires | `docs/adr/0001-...` sections 3 (E3), 5.2, 8 |
| NGC treated as unproven unless documented | `docs/adr/0001-...` section 3 (E5), section 6.2 - **withdrawn** |
| Product requirements narrowed to a supported subset | `docs/adr/0001-...` section 5.3 |
| Session 0 feasibility for the Python pipeline | `docs/adr/0002-...` section 5.2 - **not the shipping boundary; native host recommended** |
| Camera availability before interactive sign-in | `docs/adr/0002-...` section 3 (E1/E2), **blocker B1** |
| Camera privacy and consent rules | `docs/adr/0002-...` section 3 (E2) |
| Device contention and camera ownership | `docs/adr/0002-...` section 5.6 |
| Service identity and minimum privileges | `docs/adr/0002-...` section 5.3 |
| Pre-logon availability of enrollment data | `docs/adr/0002-...` section 5.5 - with the protection regression stated plainly |
| Python/native suitability for the service boundary | `docs/adr/0002-...` section 5.2 |
| **Secure-preview contradiction resolved** | `docs/adr/0002-...` section 5.4 - **preview removed, status-only UI**; `PHASE2_CREDENTIAL_PROVIDER.md` corrected |
| Versioned IPC protocol and threat model | `docs/adr/0003-...` sections 5.1-5.7; threat table 5.4 (18 threats) |
| Protocol never carries frames/embeddings/templates/passwords/certs/keys/TPM secrets/reusable assertions | `docs/adr/0003-...` section 2.1, enforced structurally by the version-1 format; `native/tests/test_protocol.cpp::opaque_fields_are_length_capped` |
| Result short-lived, single-use, request/identity/nonce/deadline-bound | `docs/adr/0003-...` section 2.2; `successful_result_cannot_be_reused`, `result_never_outlives_its_request`, `result_with_wrong_*` tests |
| Enrollment, provisioning, revocation, recovery, uninstall | `docs/adr/0004-...` sections 5.1-5.7 |
| Guaranteed built-in fallback providers | `docs/adr/0004-...` R2 and section 5.5; `docs/adr/0001-...` E2 |
| Native scaffold, CMake + CTest, x64, modern C++, strict warnings, no third-party runtime deps | `native/CMakeLists.txt`, `native/README.md` |
| Required native test coverage (17 categories) | `native/README.md` "Test coverage" mapping table |
| Native build and test instructions | `native/README.md`, `README.md`, `CONTRIBUTING.md` |
| Microsoft sample provenance/licensing | None used. `native/README.md` "Provenance and licensing" |
| GitHub Actions: Python 3.12, pytest, Ruff, mypy, native Debug + Release | `.github/workflows/ci.yml` |
| Dependency and security scanning; CodeQL for Python and C++ | `.github/workflows/ci.yml` (`dependency-review`, `pip-audit`), `.github/workflows/codeql.yml` |
| Dependabot for Python and GitHub Actions | `.github/dependabot.yml` |
| Minimum workflow permissions; no secrets in PR workflows | `.github/workflows/README.md` "Permissions and secrets" |
| SECURITY.md with responsible disclosure + biometric warning | `SECURITY.md` |
| CONTRIBUTING.md with setup, commands, boundaries, prohibitions, privacy, PR expectations | `CONTRIBUTING.md` |
| PR template and issue templates | `.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/` |
| `.gitignore` expanded for build output, binaries, symbols, keys, certs, registry exports, runtime state, biometric data, logs, model weights, IDE files | `.gitignore` |
| Phase 3 entry criteria defined | `docs/PHASE2_ACCEPTANCE_CRITERIA.md` Part B - every criterion, including B4a, B16, B17, and B18 |

### What Phase 2 deliberately did NOT do

No `ICredentialProvider` implementation. No COM registration, CLSID, or `.reg`
file. No credential provider filter. No Windows service, SCM code, or
installer. No credential serialization - no `KERB_*` structure is constructed
anywhere. No TPM, NCrypt, CNG, or certificate access. No camera access from
native code. No registry read or write. No installer or deployment package. No
change to any Windows authentication, policy, or account setting. No Microsoft
sample code copied or adapted. No experiment on a real lock screen or secure
desktop.

Full list with rationale: `docs/PHASE2_ACCEPTANCE_CRITERIA.md` Part C. The
`repo-hygiene` CI job enforces several of these mechanically.

### Toolchain honesty

The development machine has no MSVC, no Windows SDK, and no CMake - verified,
not assumed (`docs/PHASE2_ACCEPTANCE_CRITERIA.md` Part D). **No claim is made
that the native project was built or tested locally.** GitHub Actions performs
the x64 Debug and Release build and test on a `windows-latest` runner, and
those runs are the authoritative native result for this phase.
