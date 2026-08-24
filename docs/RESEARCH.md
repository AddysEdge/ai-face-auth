# Research Synthesis — Local Windows Face Authentication (Source of Truth)

Status: complete for Phase 1 decisions. This document is the technical basis for every
architectural choice made in this repository. Where a claim is load-bearing for a security
or licensing decision, a primary source is cited. Dates below reflect the current session
(August 2026); re-verify licensing and Microsoft API status before any commercial release,
since both can change.

## 0. Executive summary of decisions

| Layer | Decision | Why |
|---|---|---|
| Face detector | **YuNet** (`face_detection_yunet_2023mar.onnx`, OpenCV Zoo) | MIT license, tiny (~230KB), actively maintained by OpenCV, ships with a reference-correct wrapper (`cv2.FaceDetectorYN`). |
| Face embedding | **SFace** (`face_recognition_sface_2021dec.onnx`, OpenCV Zoo) | Apache-2.0 license (commercial-safe), ONNX, maintained by OpenCV, ~99.60% LFW. Avoids InsightFace's non-commercial model-weights restriction. |
| Landmarks / quality signal | **MediaPipe Face Landmarker** | Apache-2.0, actively maintained by Google, ships blink blendshapes directly (no need for a non-commercial landmark model). |
| Liveness (primary) | **Active challenge-response** (blink + head-turn, driven by MediaPipe blendshapes/pose) | Deterministic, testable, license-clean, honest about RGB limits — does not depend on a stale pretrained spoof classifier. |
| Liveness (optional secondary) | Pluggable passive-CNN backend (architecture compatible with Silent-Face-Anti-Spoofing/MiniFASNet, Apache-2.0) | Real and legitimate, but the reference weights are effectively unmaintained since 2020 — shipped as an optional, clearly-labeled backend, not the default. |
| Inference runtime | **ONNX Runtime**, CPU execution provider by default | Portable, deterministic, no NVIDIA GPU present on this machine anyway. DirectML EP available as an opt-in for GPU acceleration. |
| Template protection | **Windows DPAPI** (`CryptProtectData`/`CryptUnprotectData` via `pywin32`) | Concrete, working, Windows-native, reachable from Python today. TPM-backed NCrypt hardening is designed for but deferred (see §11). |
| Similarity | **Cosine similarity** on L2-normalized embeddings | Standard for ArcFace-family/SFace embeddings; equivalent to normalized Euclidean distance, numerically stable. |

## 1. Recommended pretrained face embedding model

**Primary: SFace** (`opencv/opencv_zoo/models/face_recognition_sface`), Apache-2.0 license
(confirmed by fetching the model directory's `LICENSE` file directly — full permissive
grant, commercial use allowed). ONNX export, 128-d output, input `[1,3,112,112]` (BGR,
mean-subtracted per OpenCV's `FaceRecognizerSF`), reported ~99.60% accuracy on LFW.
Maintained as part of OpenCV's own model zoo.

**Documented alternative (non-commercial only): InsightFace `buffalo_l` / ArcFace.**
InsightFace's GitHub README explicitly separates code and model licensing: *code* is MIT,
but *"the training data containing the annotation (and the models trained with these data)
are available for non-commercial research purposes only."* `buffalo_l` bundles a
512-d ArcFace recognition model plus a RetinaFace/SCRFD detector and reports higher
accuracy (~99.83% LFW) than SFace. Commercial use requires contacting
`recognition-oss-pack@insightface.ai` for a license. This repo treats `buffalo_l` as an
**optional, opt-in, clearly-labeled swap** for research/personal use — never the default —
because the goal is to keep the default path clean for an eventual Phase 2 that must not
carry an undisclosed licensing liability.

**Rejected for Phase 1 default:** training a model from scratch (see §Comparison below —
no labeled dataset, no justification for the effort at this stage); a cloud/API-key
recognizer (violates the "must work fully offline" requirement and adds a third-party
trust dependency incompatible with a local authentication control).

## 2. Recommended face detector

**YuNet** (`face_detection_yunet_2023mar.onnx`), MIT license (confirmed — every file in
`opencv_zoo/models/face_detection_yunet/` carries an MIT `LICENSE`). Anchor-free,
multi-scale (strides 8/16/32) detector with 5-point landmark output (eyes, nose, mouth
corners) needed for alignment. ~230KB, sub-10ms on CPU for VGA frames. Used through
OpenCV's own `cv2.FaceDetectorYN` wrapper rather than a hand-rolled raw-ONNX decode —
the raw graph outputs are pre-NMS multi-scale anchor scores/boxes/keypoints (verified by
inspecting the model's I/O signature directly: 12 output tensors across 3 strides), and
reimplementing that decode independently risks a subtly-wrong-but-plausible
implementation. OpenCV's own C++ decode is the model author's reference implementation.

## 3. Recommended liveness / anti-spoofing approach

Two-tier, both real (no placeholders):

1. **Active challenge-response (default, required).** The system requests a randomized
   action — a deliberate blink or a small head turn — and verifies it occurred using
   MediaPipe Face Landmarker's blink blendshape scores (`eyeBlinkLeft`/`eyeBlinkRight`)
   and head-pose landmarks, within a bounded time window. This defeats a **static printed
   photo** outright (it cannot blink or turn on command) and raises the bar against a
   **static phone/display image**. It does **not** reliably defeat a **video replay** of
   a person performing the same actions — this limitation is stated explicitly in the
   README and threat model, not hidden.
2. **Passive texture/frequency backend (optional, pluggable, off by default).** The
   `LivenessProvider` interface accepts a second, independent implementation that scores
   a single frame for spoof artifacts (moiré/screen-reflection patterns, texture
   flatness). The architecture is compatible with the Silent-Face-Anti-Spoofing /
   MiniFASNet family (Apache-2.0 license, confirmed via the project's `LICENSE` file), but
   that project's last substantive commit is from 2020 — it is documented as
   "available, license-clean, but not actively maintained" rather than shipped as the
   trusted default.

**ISO/IEC 30107-3** defines the standard PAD metrics for this space — APCER (Attack
Presentation Classification Error Rate) and BPCER (Bona fide Presentation Classification
Error Rate) — used as the vocabulary for any future liveness benchmarking, referenced in
the evaluation tooling design (§16).

## 4. Recommended inference runtime

**ONNX Runtime**, `CPUExecutionProvider` by default. This machine has no NVIDIA GPU
(confirmed: AMD Radeon 860M iGPU, no CUDA-capable device), so the CUDA EP is not
applicable. **DirectML EP** is compatible with any DirectX12 GPU including this AMD iGPU,
but Microsoft's own `microsoft/DirectML` repository currently carries a maintenance-mode
banner: *"DirectML is in maintenance mode"*, with WinML positioned as the forward path for
new Windows ML projects (`learn.microsoft.com/windows/ai/directml/dml`). Given the small
model sizes here (YuNet ~230KB, SFace ~38MB) CPU inference is already sub-frame-budget, so
CPU EP is the correct default; DirectML is exposed as an **opt-in** config value, not
required, and documented with this caveat rather than presented as a performance
guarantee.

Both models were downloaded from OpenCV Zoo's Git-LFS storage, checksum-verified against
the LFS pointer's declared SHA-256, loaded with `onnxruntime.InferenceSession`, and their
I/O signatures inspected directly (see `models/` and the loader code) — this is not a
theoretical recommendation, the exact files this repo ships against were run.

## 5. Model licensing considerations (full table)

| Component | License | Commercial use | Source |
|---|---|---|---|
| YuNet detector | MIT | Yes | `opencv_zoo/models/face_detection_yunet/LICENSE` |
| SFace embedder | Apache-2.0 | Yes | `opencv_zoo/models/face_recognition_sface/LICENSE` |
| MediaPipe Face Landmarker | Apache-2.0 | Yes | Google AI Edge / MediaPipe docs |
| InsightFace code | MIT | Yes | `deepinsight/insightface` README |
| InsightFace `buffalo_l`/ArcFace **weights** | Non-commercial research only | **No** (requires separate commercial license) | `deepinsight/insightface` README |
| dlib 68-point landmark model | Non-commercial (iBUG 300-W dataset restriction) | **No** | dlib-models project discussion; not used in this repo |
| Silent-Face-Anti-Spoofing | Apache-2.0 | Yes, but effectively unmaintained since 2020 | `minivision-ai/Silent-Face-Anti-Spoofing` LICENSE + commit history |

Net effect: the **default Phase 1 stack (YuNet + SFace + MediaPipe) is fully
commercial-license-clean**, which matters because the stated long-term goal includes a
possible Phase 2 product. InsightFace remains available as an explicitly-flagged opt-in
for users who accept its research-only terms.

## 6. Complete architecture

```
Webcam (RGB, and optionally the machine's IR sensor as a future input)
   -> CameraProvider (OpenCV VideoCapture)
   -> FaceDetector (YuNet via cv2.FaceDetectorYN)
   -> FaceQualityChecker (sharpness / brightness / pose / size / single-face heuristics)
   -> LivenessProvider (challenge-response, optional passive backend)
   -> FaceEmbeddingModel (SFace via ONNX Runtime, fed an OpenCV-aligned crop)
   -> SimilarityEngine (cosine similarity vs. stored template(s))
   -> AuthenticationPolicy (threshold + fail-closed decision)
   -> RateLimiter (cooldown/backoff on repeated failures)
   -> ACCESS GRANTED / ACCESS DENIED
```

Enrollment reuses detector/quality/embedding stages, capturing multiple valid samples and
aggregating them (see §8) before writing an encrypted template via `TemplateStore`
(DPAPI-backed).

Every stage is a swappable interface (`src/faceauth/interfaces/`) — no stage is coupled to
its concrete Phase-1 implementation.

## 7. Threat model

See `docs/THREAT_MODEL.md` for the full document. Summary of what Phase 1 defends against
and what it explicitly does not:

- **Defends against:** static printed-photo attacks (challenge-response), casual
  impostor attempts (embedding distance), repeated brute-force guessing (rate limiter +
  cooldown), template theft from disk in isolation (DPAPI ties decryption to the Windows
  user/machine), accidental biometric data leakage via logs (redacted logger), silent
  failure turning into false access (fail-closed policy).
- **Does not defend against, and says so:** a high-quality video replay of the legitimate
  user performing the requested challenge; a determined attacker with access to the
  unlocked Windows user account (DPAPI decrypts under that account by design); physical
  compromise of the machine while unlocked; anything requiring IR/depth hardware that a
  plain RGB webcam cannot provide.

## 8. Enrollment pipeline

1. Capture N (default 5) frames that each independently pass detection + quality checks
   (single face, adequate sharpness/brightness, frontal-enough pose, minimum face size).
2. Reject frames that fail liveness challenge to prevent silently enrolling a spoofed
   sample.
3. Compute an embedding per accepted sample.
4. **Aggregate via mean embedding, then re-normalize to unit L2 norm.** This is the
   standard approach for ArcFace-family/SFace embeddings (the embedding space is trained
   under a normalized-angular-margin loss, so the class centroid direction — not the raw
   mean magnitude — is the meaningful signal). Storing the individual per-sample
   embeddings alongside the centroid (rather than only the centroid) is also supported by
   the `TemplateStore` schema, enabling a max-similarity matching strategy later without a
   re-enrollment, and enabling outlier-sample rejection at enrollment time (a sample whose
   embedding is an outlier vs. the running centroid is dropped and re-captured).
5. Discard raw frames immediately after embedding extraction — never persisted by
   default (configurable, off, with a loud warning if a developer enables raw-frame
   retention for debugging).
6. Encrypt and persist the resulting template via `TemplateStore`.

## 9. Authentication pipeline

`capture -> detect -> quality-gate -> liveness-gate -> embed -> compare -> policy decide`,
implemented so that **any stage raising or returning "uncertain" causes a DENY**, never an
implicit ALLOW (fail-closed, §"Security restrictions" in the goal).

## 10. Similarity / threshold strategy

Cosine similarity on L2-normalized embeddings (mathematically: for unit vectors,
`cosine_similarity = 1 - 0.5 * squared_euclidean_distance`, so this is equivalent to
threshold-on-Euclidean-distance but avoids a sqrt and is the convention used by the
model's own authors/demos). SFace's own OpenCV demo documents a reference cosine-similarity
threshold of **0.363** for its default operating point (also documents an alternate
L2-norm-distance threshold of 1.128) — this repo uses **0.363 cosine similarity as the
documented model-default threshold**, exposed as a configurable value, not hardcoded, with
explicit support for later recalibration against the evaluation tool's ROC output (§16) once
real enrolled-user data exists. This satisfies "not simply guessed" — it is the value
published by the model's own maintainers for this exact checkpoint, adjustable later from
measured data.

## 11. Template storage strategy

- **Primary (Windows):** `DpapiTemplateStore` — encrypts the serialized template (a
  fixed-size float32 vector, not an image) via `win32crypt.CryptProtectData`
  (`pywin32`'s binding to the real Win32 `CryptProtectData`/`CryptUnprotectData` DPAPI
  functions, confirmed present and importable in this environment), user scope by
  default. Decryption is only possible under the same Windows user account on the same
  machine — the OS-level guarantee DPAPI is designed to provide
  (`learn.microsoft.com/dotnet/api/system.security.cryptography.protecteddata`).
- **TPM hardening (designed, not implemented in Phase 1 — see §"Risks and limitations"):**
  Windows exposes TPM-backed key storage through CNG's Microsoft Platform Crypto
  Provider (`MS_PLATFORM_CRYPTO_PROVIDER`), reachable via the `NCryptOpenStorageProvider`
  / `NCryptCreatePersistedKey` Win32 API — keys are generated inside the TPM 2.0 chip and
  the private material never leaves it
  (`learn.microsoft.com/windows/win32/seccertenroll/cng-key-storage-providers`). There is
  no mature, maintained Python binding for this API surface; a correct implementation
  requires hand-written `ctypes` bindings against `ncrypt.dll`. Given the risk of shipping
  a subtly-incorrect security-critical `ctypes` binding without hardware-backed test
  coverage in this environment, **this repo does not fake that integration** — the
  `TemplateStore` interface is deliberately designed so a `TpmTemplateStore` can be added
  later without touching any calling code, and the exact API surface it would use is
  documented here and in `docs/ARCHITECTURE.md`.
- **Dev fallback (non-Windows / DPAPI unavailable):** `FileTemplateStore` using
  Fernet symmetric encryption (`cryptography` package) with a locally generated key file.
  Every code path that constructs this backend logs a loud, explicit
  "DEV-ONLY, NOT SECURE FOR PRODUCTION" warning; it exists only so the test suite and
  non-Windows contributors can exercise the pipeline.

## 12. Liveness strategy

See §3. Composite/AND-combinable via a `CompositeLivenessProvider` so a future passive
backend augments rather than replaces the active challenge.

## 13. Rate-limiting strategy

Exponential backoff cooldown keyed by a local identity (machine + OS user), not by
face — an unauthenticated impostor cannot be identified yet, so limiting has to key on
"this authentication surface," matching how Windows Hello itself throttles by device/
session rather than by claimed identity. Default: escalating cooldown after consecutive
failures (e.g., 5 failures -> 30s, then doubling, capped), reset on a success or after a
sufficiently long idle period. Configurable, tested at boundary conditions.

## 14. Logging / privacy strategy

Structured logging that logs **event types, timestamps, similarity-score buckets (not raw
scores adjacent to identity — configurable), and outcome**, with an explicit denylist of
fields that can never be logged: raw frames, embedding vectors, template bytes, passwords/
secrets. Enforced via a redacting log filter, not just convention, and covered by tests
that assert no float-vector-shaped or image-shaped payloads reach the log sink.

## 15. Testing strategy

All model/camera/liveness dependencies are injected through the interfaces in §"complete
architecture," so the full pipeline is unit-testable with mocks/fakes — no real camera or
GPU needed for CI. Real-model integration is exercised separately (see §"Phase 1 MVP
design") using the actual downloaded ONNX files, gated behind a marker so it can be skipped
in environments without them.

## 16. FAR/FRR/EER evaluation strategy

A standalone evaluation utility (`faceauth-evaluate`) that, given a directory of
already-collected, already-authorized genuine/impostor similarity-score pairs (the tool
does not collect or scrape any dataset itself — it only computes metrics from
scores the caller supplies), computes:
- Genuine and impostor score distributions
- FAR(t) and FRR(t) curves across the threshold range
- EER (the threshold where FAR(t) == FRR(t), found by interpolation)
- An ROC-style table (FAR vs. TAR at each threshold)
- A recommended operating threshold at a configurable target FAR (default target aligned
  conceptually with the Windows Hello facial-recognition bar of FAR < 0.001%, while
  explicitly documenting that this repo's RGB-only pipeline **cannot be certified to that
  bar** — see §"RGB vs. Windows Hello hardware" below).

## 17. Benchmarking strategy

A `scripts/benchmark.py` utility measures per-stage wall-clock latency (detect / align /
embed / compare) over N synthetic and/or captured frames on this machine's actual CPU EP,
reporting p50/p95, so future runtime or model swaps have a concrete before/after.

## 18. Recommended Python libraries

`opencv-contrib-python` (single OpenCV install — see note below), `onnxruntime`,
`mediapipe`, `numpy`, `pywin32` (Windows-only, DPAPI), `cryptography` (dev-fallback
storage), `pydantic` (configuration validation), `pytest` (tests). All version-pinned in
`pyproject.toml` against the actual resolved/installed versions in this environment.

**Note on OpenCV packaging:** `mediapipe` transitively depends on
`opencv-contrib-python`. Declaring `opencv-python` *and* `opencv-contrib-python` together
causes both to install into the same `cv2` namespace, which is undefined/fragile
behavior. This repo depends on `opencv-contrib-python` only (a superset of
`opencv-python`) and lets `mediapipe` pull it transitively, avoiding the conflict
entirely.

## 19. Recommended Windows/native technologies

`pywin32` for DPAPI today. For Phase 2: the Win32 Credential Provider COM interfaces
(`ICredentialProvider`, `ICredentialProviderCredential`, `ICredentialProviderCredential2`
for the recommended V2 surface) implemented in C++, per Microsoft's own
`Windows-classic-samples` reference
(`microsoft/Windows-classic-samples/Samples/Win7Samples/security/credentialproviders`);
CNG/NCrypt (`ncrypt.dll`, `MS_PLATFORM_CRYPTO_PROVIDER`) for TPM-backed key material. See
`docs/PHASE2_CREDENTIAL_PROVIDER.md`.

## 20. Project folder structure

```
ai-face-auth/
  pyproject.toml
  README.md
  models/                      real ONNX weights (fetched, checksum-recorded) + LICENSE copies
  docs/
    RESEARCH.md                 this file
    ARCHITECTURE.md
    THREAT_MODEL.md
    PHASE2_CREDENTIAL_PROVIDER.md
    MODEL_LICENSES.md
  src/faceauth/
    interfaces/                 abstract contracts for every swappable stage
    camera/  detection/  quality/  embedding/  liveness/  similarity/  storage/  policy/  rate_limiting/
    config.py  logging_utils.py  exceptions.py  pipeline_types.py
    enrollment.py  authentication.py  demo_ui.py  cli.py  evaluate.py  model_registry.py
  tests/
  scripts/                      benchmark.py, fetch_models.py
```

## 21. Phase 1 standalone MVP design

A local, offline, standalone Python application (webcam demo lock screen), described in
full in `docs/ARCHITECTURE.md`. No Windows login integration. Safe to run and iterate on
without any risk to the real logon path.

## 22. Phase 2 legitimate Windows Credential Provider design

> **Updated after the Phase 2 review (2026-08-24).** The constraint below still
> holds and was the starting point. What the review added is *which* credential
> is actually available, and the answer is much narrower than this section
> originally implied. See §22a.

Key constraint carried from research: a Credential Provider **packages and submits a
credential; it is not itself the trust boundary** — LSA and the relevant authentication
package make the actual decision
(`learn.microsoft.com/windows/win32/secauthn/credential-providers-in-windows`: *"Credential
providers are not enforcement mechanisms; they are used to gather and serialize
credentials, submitting them for authorization."*). This means a provider cannot simply
"say yes" — it must gate release/use of an already Windows-recognized credential.

## 22a. Phase 2 review outcome — the credential question, resolved

Full analysis with verbatim primary sources:
`docs/PHASE2_SECURITY_REVIEW.md` and `docs/adr/`.

**Result: CONDITIONAL GO overall, NO-GO for the local-account product goal.**

| Windows account type | Result | Why |
|---|---|---|
| Local Windows account | **NO-GO** | Certificate logon is Kerberos PKINIT and terminates at a KDC holding an AD DS account object; WHfB has no local-account deployment model; NGC gating has no public API. Only the password path remains, and that is forbidden. |
| Microsoft account (MSA) | **NO-GO** | Same exclusion; no documented third-party credential surface. |
| Active Directory domain account | **CONDITIONAL GO** | `KERB_CERTIFICATE_LOGON` / smart-card-class logon, inside a deployment with a KDC, an enterprise PKI, certificate enrolment, account mapping, and CRL/OCSP reachable before sign-in. |
| Microsoft Entra ID account | **DEFERRED — unproven** | No documented third-party surface producing an Entra-recognized credential was found. Not claimed either way. |

Three research claims from the Phase 1 era were **withdrawn or narrowed** by
the review, and are recorded here so this document is not left overstating
what is possible:

1. **NGC container gating is withdrawn.** `KeyCredentialManager` is documented
   as operating "for the current user and application" — it needs a signed-in
   user, is app-scoped, and returns nothing `LsaLogonUser` consumes. No public
   API lets a third party gate the Windows Hello NGC container for sign-in.
   Recorded as **unproven** and excluded.
2. **Certificate logon does not cover the local-machine use case.** The
   documented flow packages a `KERB_CERTIFICATE_LOGON`, and `LsaLogonUser`
   "attempts to authenticate against the domain to which the computer is
   joined". There is no documented local-SAM variant.
3. **A custom LSA authentication package is not a route.** Registering one
   means writing to `HKLM\System\CurrentControlSet\Control\Lsa\Security Packages`
   — prohibited here — and under LSA protection, on by default for new
   Windows 11 22H2+ enterprise installs, "Any plug-ins that are unsigned or
   aren't signed with a Microsoft signature fail to load in LSA."

**Additional sources consulted for the review**, beyond the list at the end of
this document:

- `learn.microsoft.com/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration`
- `learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon`
- `learn.microsoft.com/uwp/api/windows.security.credentials.keycredentialmanager`
- `learn.microsoft.com/windows/security/identity-protection/hello-for-business/deploy/`
- `learn.microsoft.com/windows-hardware/design/device-experiences/windows-hello-face-authentication`
- `learn.microsoft.com/windows/win32/secauthn/registering-ssp-ap-dlls`
- `learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection`
- `learn.microsoft.com/windows-hardware/drivers/stream/frame-server-custom-media-source`
- `learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_sid_info`
- `learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createnamedpipea`
- `support.microsoft.com/windows/privacy/manage-app-permissions-for-a-camera-in-windows`

## 23. Risks and limitations

- RGB-only liveness is fundamentally weaker than the IR-based liveness Windows Hello
  requires; this is stated everywhere applicable, not just once.
- TPM-backed template hardening is designed but not implemented in Phase 1 (§11) —
  explicitly flagged, not silently skipped.
- SFace (~99.6% LFW) trades a little accuracy vs. InsightFace's ArcFace (~99.83% LFW) for
  a commercial-clean license; documented as a deliberate tradeoff.
- The passive liveness backend's reference weights are stale (2020); shipped disabled by
  default with that caveat visible in config and docs.
- This machine has an IR webcam present (`USB2.0 IR UVC WebCam`), but Phase 1 intentionally
  only uses the RGB sensor, since building genuine IR-based liveness/anti-spoof logic is a
  substantially larger effort or requires a Windows Hello-integrated capture pipeline
  outside Phase 1 scope — noted as a natural next step rather than implemented and
  mis-described as more capable than it is.

## 24. Future fine-tuning strategy

Because SFace/YuNet are ONNX end to end, and the `FaceEmbeddingModel`/`FaceDetector`
interfaces only require "given input, produce output of contract shape," a future
fine-tuned or distilled model (e.g., fine-tuned on the deployment population, or quantized
via ONNX Runtime's built-in dynamic/static quantization tooling for faster CPU inference)
plugs in by adding one new concrete class and a config value — no pipeline changes. The
embedding comparison logic is threshold-based and re-calibratable via the evaluation tool
(§16) whenever the embedding model changes, rather than assuming the SFace-specific 0.363
threshold carries over.

## 25. Step-by-step implementation roadmap

1. Scaffold interfaces + config + logging (this repo, next step).
2. Concrete camera/detector/quality/embedder/similarity/policy/rate-limiter/storage
   implementations against the real downloaded models.
3. Enrollment + authentication orchestration services.
4. Demo lock-screen UI.
5. Test suite (mocked) + real-model smoke test + live webcam manual verification.
6. Evaluation + benchmarking tooling.
7. Documentation (README, architecture, threat model, Phase 2 design, licenses).
8. Full verification pass: tests, lint, app launch, repo hygiene sweep, acceptance audit.

## RGB webcam vs. Windows Hello-grade hardware

Microsoft's own hardware requirements
(`learn.microsoft.com/windows-hardware/design/device-experiences/windows-hello-biometric-requirements`)
specify, for facial recognition: **FAR < 0.001% (1 in 100,000) and TAR > 95% (i.e., FRR <
5%)**, achieved using a **dedicated IR camera** with presentation-attack defenses, not a
plain visible-light sensor — Windows Hello's own docs state the IR sensor "allows [it] to
distinguish between a photo and a living person." These numbers are certified through
large-scale, standardized testing (the same Microsoft page's appendix shows ~2.5 million
comparisons needed just to statistically substantiate a 1-in-100,000 FAR claim at 96%
confidence) that no hobbyist pretrained-model pipeline in this repository has undergone or
could credibly claim. **This project must never describe its RGB-webcam authentication as
Windows Hello-equivalent security** — it is a local convenience/demo authentication
control with a materially different (and weaker, quantifiably so against presentation
attacks) threat-resistance profile. This sentence, or an equivalent, appears in the
README, the threat model, and the in-app UI copy.

Depth/IR hardware (a Windows Hello-class sensor, e.g., the IR camera present on this dev
machine) would close much of this gap — an IR stream defeats ordinary printed-photo and
phone-screen attacks structurally (no NIR return from paper/an LCD panel the way skin
reflects it), which is *why* Windows Hello requires it. Using this machine's actual IR
sensor is documented as a concrete, buildable Phase 1.5 enhancement (the `CameraProvider`
interface is not RGB-specific), but is out of scope for the initial MVP pass.

## Comparison: cloud API vs. local pretrained vs. train-from-scratch vs. pretrained+fine-tune-later

| Option | Verdict |
|---|---|
| A. Cloud/API-key recognition | Rejected — violates the offline requirement outright, and introduces a third-party trust dependency for a local security control. |
| B. Local pretrained inference | **Selected for Phase 1** — mature, license-clean options exist (SFace/YuNet) with known accuracy figures, no training data or infrastructure needed. |
| C. Train from scratch | Rejected for now — no labeled face dataset in scope, months of effort, and would land at or below existing pretrained accuracy without a very large data/compute investment; not justified for an MVP. |
| D. Pretrained now, fine-tune later | **This is the actual selected strategy** — Option B today, with the interface design (§24) keeping fine-tuning/replacement/quantization as a drop-in later step rather than a rewrite. |

## Primary sources consulted

- learn.microsoft.com/windows-hardware/design/device-experiences/windows-hello-biometric-requirements
- learn.microsoft.com/windows/win32/secauthn/credential-providers-in-windows
- learn.microsoft.com/windows/win32/api/credentialprovider/nn-credentialprovider-icredentialprovidercredential
- learn.microsoft.com/windows/win32/seccertenroll/cng-key-storage-providers
- learn.microsoft.com/dotnet/api/system.security.cryptography.protecteddata
- learn.microsoft.com/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
- learn.microsoft.com/windows/ai/directml/dml
- github.com/microsoft/DirectML (maintenance-mode notice)
- github.com/microsoft/Windows-classic-samples (credential provider samples)
- github.com/deepinsight/insightface (README, licensing)
- github.com/opencv/opencv_zoo (YuNet + SFace model files, READMEs, LICENSE files — fetched and verified directly, weights downloaded and loaded)
- github.com/minivision-ai/Silent-Face-Anti-Spoofing (LICENSE, commit history)
- developers.google.com/mediapipe (Face Landmarker docs)
- onnxruntime.ai/docs/execution-providers (DirectML EP docs)
- ISO/IEC 30107-3 terminology (APCER/BPCER), summarized via secondary sources — not directly fetched as it sits behind a paywall.
