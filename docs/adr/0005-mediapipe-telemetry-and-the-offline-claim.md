# ADR-0005: MediaPipe telemetry and the offline claim

- **Status:** **Proposed - decision OPEN.** Nothing here is chosen yet. This ADR
  exists to record the problem, the evidence, and the viable options, so the
  choice is made deliberately rather than by default.
- **Date:** 2026-08-25
- **Phase:** Phase 1 correction, and a **Phase 3 entry gate**.
- **Blocker:** **B17** - see section 8.
- **Supersedes nothing.** Phase 3's "no network access" requirement
  (`docs/PHASE2_SECURITY_REVIEW.md` section 3.4, ADR-0002 section 5.3) is
  **not** weakened by this ADR.

---

## 1. Context

This repository stated in seven places that it runs "entirely offline" with
"no network access required at runtime".

It does not. `mediapipe`, used here only for the passive-liveness / blendshape
path, links Google's Clearcut telemetry client into `libmediapipe.dll` and
uploads usage metrics to `https://play.googleapis.com/log` when a MediaPipe
session is torn down.

The full investigation - destination, trigger, timing, frequency, exact
transmitted schema, retry behaviour, and the opt-out search - is in
[`docs/PRIVACY_NETWORK_AUDIT.md`](../PRIVACY_NETWORK_AUDIT.md). This ADR does
not repeat it; it decides what to do about it.

The three facts that constrain every option:

1. **The behaviour is intended and documented by Google**, in the MediaPipe
   Terms of Service. It is not a compromise, and no incident response is
   warranted.
2. **No image, frame, landmark, embedding, or template is transmitted.** The
   payload schema has no field capable of carrying one, and Google states
   input data is never sent. What leaves the machine is usage and latency
   metadata: platform, host environment, MediaPipe version, `app_id`, solution
   name, graph name, init latency, invocation counts, latency statistics.
3. **There is no supported way to turn it off.** Upstream refused to add one,
   explicitly and on the record
   ([mediapipe#6291](https://github.com/google-ai-edge/mediapipe/issues/6291),
   closed 2026-07-06).

## 2. The problem, stated precisely

Two different requirements were being conflated under the single word
"offline", and only one of them was ever actually violated.

| Requirement | Status |
|---|---|
| **R-A. Biometric data never leaves the machine.** No frame, template, or embedding is transmitted anywhere, ever. | **Held, and still holds.** Never violated. Verified against the transmitted schema. |
| **R-B. The process makes no outbound network connections at all.** | **Violated**, and has been since MediaPipe 0.10.35. |

R-A is the security-relevant property, and it is intact. R-B is the property
the README claimed, and it is false.

Phase 3 requires **both**. A Session 0 verifier service specified with no
network access cannot host a dependency that opens a TLS connection on session
teardown - that is not a documentation problem, it is a design conflict.

## 3. Requirements for any resolution

| # | Requirement |
|---|---|
| R1 | Every claim in the repository must match observable behaviour. Retraction is mandatory and is **not** contingent on choosing an option below. |
| R2 | Whatever is chosen must not weaken R-A. |
| R3 | The remedy must be a property of this software, not a per-machine configuration step the user is expected to perform. |
| R4 | Phase 3's "no outbound networking" requirement must survive the decision unweakened. |
| R5 | No undocumented environment variable, no reliance on IP or hostname blocking, no patched or repackaged upstream binary presented as if it were upstream. |

## 4. Options

### Option A - Replace MediaPipe

Drop `mediapipe` entirely and reimplement passive liveness / blink detection on
a dependency that is genuinely network-silent.

MediaPipe is used here for exactly one thing: face landmarks and blendshapes
feeding the liveness challenge. Detection (YuNet) and embedding (SFace) are
already ONNX Runtime and OpenCV, and neither of those opened any connection at
any stage of the audit.

- **Satisfies:** R1, R2, R3, R4, R5. The only option that makes "offline"
  literally true again with no asterisk.
- **Cost:** a real reimplementation. Candidate replacements - an ONNX face
  landmark model run directly on the existing ONNX Runtime CPU EP, or an
  eye-aspect-ratio blink detector over OpenCV landmarks - need their own
  accuracy and anti-spoofing evaluation. The liveness path is a security
  control, so "it roughly works" is not an acceptable bar; it needs the same
  FAR/FRR treatment the rest of the pipeline gets.
- **Risk:** liveness quality regresses, and that regression is security-
  relevant, not cosmetic.

### Option B - Build MediaPipe from source without telemetry

Upstream states that a source build does not include telemetry. Vendor a pinned
source build and consume that instead of the PyPI wheel.

- **Satisfies:** R1, R2, R4. Keeps the current liveness quality exactly.
- **Fails R3 in practice** and sits uncomfortably against R5: it makes this
  project responsible for building, pinning, verifying, and re-verifying a
  large Bazel C++ project on every upgrade, and for proving on each rebuild
  that telemetry is still absent. A build that silently regains telemetry after
  an upstream change is a worse position than today, because the claim would
  have been restored.
- **Cost:** high and recurring. Bazel toolchain, Windows build, MSVC, CI
  capacity, and a per-upgrade re-verification obligation.
- **Note:** if this is chosen, the check in
  `scripts/check_network_activity.py` becomes the gate that keeps it honest.

### Option C - Narrow the offline requirement to what is actually true

Keep MediaPipe for Phase 1. State plainly that Phase 1 is a research prototype
which processes all biometric data locally but is not network-silent, and name
the dependency and the endpoint. Retain the strict no-networking requirement
for Phase 3 as a hard gate, so the conflict must be resolved (by A or B) before
Phase 3 rather than being inherited silently.

- **Satisfies:** R1, R2, R4, R5.
- **Satisfies R3 only in the sense that it stops making the claim** rather than
  earning it. This is a truthful description, not a fix.
- **Cost:** none technically. The cost is that "offline" is no longer an
  unqualified property of Phase 1, and every downstream description has to
  carry the qualification.
- **Consequence:** the decision is deferred, not avoided. Phase 3 still needs
  A or B.

### Rejected without further consideration

| Rejected | Why |
|---|---|
| Set an undocumented environment variable | None exists. Inventing or guessing one would be fabricating a fix. Violates R5. |
| Block `play.googleapis.com` by firewall or hosts file | A per-machine change, not a property of this software. Violates R3 and R5. Upstream offers it; that does not make it a *product* answer. |
| Binary-patch the endpoint out of `libmediapipe.dll` | Fragile, redistribution-hostile, and would present a modified binary as upstream. Violates R5. |
| Leave the claims as they were | Not an option. R1 is unconditional. |

## 5. Decision

**Open.** No option is selected in this change.

What *is* decided, and is already implemented here:

1. **Every inaccurate claim is retracted now**, independent of which option is
   eventually chosen (R1). This is not deferred pending the decision.
2. **An OS-level network regression check is in place**
   (`scripts/check_network_activity.py`), so the current state is pinned and
   any new or additional outbound destination fails rather than passing
   unnoticed.
3. **Phase 3's no-networking requirement stands unchanged**, and this conflict
   becomes blocker **B17** against Phase 3 entry.

The choice between A, B, and C is a product decision about how much liveness
quality is worth trading for a literal offline guarantee, and it belongs to the
repository owner rather than to this correction.

## 6. Recommendation, offered but not applied

**Option C now, Option A before Phase 3.**

C is the only honest description of the software as it stands today, and it
costs nothing to adopt immediately. A is the only option that satisfies Phase
3's requirement without taking on a permanent build-and-re-verify obligation.
B keeps liveness quality unchanged and is the right answer if the liveness
model turns out to be hard to replace at equivalent accuracy - but it should be
chosen with the recurring cost understood, not as the path of least resistance.

This is a recommendation. It is deliberately not recorded as the decision.

## 7. Consequences

- Phase 1 is documented as locally-processing but **not** network-silent. Users
  reading the README learn this before installing, not after packet-capturing.
- The security-relevant property (R-A: biometric data never leaves the machine)
  is stated separately from the network property, so the two stop being
  conflated - which is what allowed the false claim to survive review.
- Phase 3 gains a hard blocker it cannot start without clearing.
- Any future dependency that adds a phone-home is caught by the regression
  check rather than discovered by accident during an unrelated review, which is
  how this one was found.

## 8. Phase 3 entry criterion

**B17 - MediaPipe telemetry conflicts with the Phase 3 no-networking
requirement.** Before Phase 3 may begin, ADR-0005 must be moved from *Proposed*
to *Accepted* with Option A or Option B selected and implemented, and
`scripts/check_network_activity.py` must show the verification path making zero
outbound connections. Option C does **not** clear B17; it only makes Phase 1's
documentation truthful while the conflict remains open.

This joins the existing Part B entry criteria in
`docs/PHASE2_ACCEPTANCE_CRITERIA.md`; it does not replace or relax any of them.

## 9. Evidence

| # | Evidence | Source |
|---|---|---|
| E1 | Endpoint `https://play.googleapis.com/log`, adjacent to `clearcut_logger.cc` / `portable_clearcut_uploader.cc` | String literals in `mediapipe/tasks/c/libmediapipe.dll` |
| E2 | All observed IPs are A records of `play.googleapis.com` | Live `Get-DnsClientCache` capture (read-only) |
| E3 | Trigger is session teardown, not `detect()`; fires with zero inference calls | `Get-NetTCPConnection -OwningProcess <pid>`, polled per step |
| E4 | Complete transmitted schema; no field can carry biometric content | Embedded protobuf descriptors for `mediapipe_log_extension.proto` |
| E5 | Metrics collection is documented and intended | [MediaPipe Terms of Service](https://developers.google.com/edge/mediapipe/legal/tos), *Privacy*, last modified 2026-04-07 |
| E6 | No opt-out API will be provided; source build or host blocking are the only upstream-offered workarounds | [mediapipe#6291](https://github.com/google-ai-edge/mediapipe/issues/6291), maintainer response 2026-07-06 |
| E7 | Behaviour is pre-existing, not introduced by any bump in this repository | Identical behaviour under `mediapipe==1.0.0` / `onnxruntime==1.28.0` and `1.0.1` / `1.29.0` |
| E8 | Python socket interception cannot observe it | Zero Python-level `connect` attempts recorded in every run |
