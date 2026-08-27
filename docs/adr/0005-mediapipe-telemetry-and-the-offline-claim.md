# ADR-0005: MediaPipe telemetry and the offline claim

- **Status:** **Proposed - decision OPEN.** Nothing here is chosen yet. This ADR
  exists to record the problem, the evidence, and the viable options, so the
  choice is made deliberately rather than by default.
- **Tracked in:** [issue #6](https://github.com/AddysEdge/ai-face-auth/issues/6).
- **Date:** 2026-08-25
- **Phase:** Phase 1 correction, and a **Phase 3 entry gate**.
- **Blocker:** **B17** - see section 9.
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
2. **The MediaPipe telemetry extension carries no biometric field.** The
   complete *MediaPipe telemetry extension schema*, extracted from the
   descriptors in the shipped binary, has no field capable of carrying an
   image, frame, landmark, embedding, or template. What that schema does carry
   is usage and latency metadata: platform, host environment, MediaPipe
   version, `app_id`, solution name, graph name, init latency, invocation
   counts, latency statistics.

   The broader claim that input data is not sent to Google rests on Google's
   own statements - the
   [maintainer's reply](https://github.com/google-ai-edge/mediapipe/issues/6291#issuecomment-4896121772)
   and the [MediaPipe Terms of Service](https://developers.google.com/edge/mediapipe/legal/tos) -
   not on binary inspection. The extension travels inside a Clearcut envelope
   that was **not** decrypted, so envelope identifiers and contents were not
   characterised. Nothing here establishes that the telemetry is anonymous.
3. **There is no supported way to turn it off.** Upstream refused to add one,
   explicitly and on the record
   ([mediapipe#6291](https://github.com/google-ai-edge/mediapipe/issues/6291),
   closed 2026-07-06).

## 2. The problem, stated precisely

Two different requirements were being conflated under the single word
"offline", and only one of them was ever actually violated.

| Requirement | Status |
|---|---|
| **R-A. Biometric data never leaves the machine.** No frame, template, or embedding is transmitted anywhere, ever. | **Held, and still holds.** Never violated. The MediaPipe telemetry extension schema has no field that could carry any of it, and Google states input data is never sent (section 1, fact 2). |
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

## 4. Two separable things

Conflating these is what makes this decision hard to talk about, so they are
kept apart throughout.

| | |
|---|---|
| **The mandatory interim state** - disclose accurately, retract every false claim | **Already applied.** Unconditional (R1), not contingent on anything below, and **not a solution**. It makes the documentation true; it does not change what the software does. It does **not** clear B17. |
| **The Phase 3 resolution** - make the verification path genuinely network-silent | **Unresolved.** Requires Option A or Option B, selected, implemented, and verified. |

Narrowed Phase 1 wording is therefore not an "option" competing with A and B.
It is the floor: the honest description of the software while the real decision
is open. Nothing below is a reason to defer it, and it has already been done.

## 5. The options for the Phase 3 resolution

Both A and B can make the verification path network-silent. Neither is
disqualified in principle; they differ in what they cost and in what has to
keep being true afterwards.

MediaPipe is used here for exactly one thing: face landmarks and blendshapes
feeding the liveness challenge. Detection (YuNet) and embedding (SFace) are
already ONNX Runtime and OpenCV, and neither opened any connection at any stage
of the audit.

### Option A - Replace MediaPipe

Drop `mediapipe` and reimplement passive liveness / blink detection on a
dependency that is network-silent - for example an ONNX face-landmark model on
the existing ONNX Runtime CPU EP, or an eye-aspect-ratio blink detector over
OpenCV landmarks.

- **Satisfies:** R1-R5.
- **Cost:** a real reimplementation, and a security-relevant evaluation.
  Liveness is an anti-spoofing control, so "it roughly works" is not the bar; a
  replacement needs the same FAR/FRR and spoof-resistance treatment the rest of
  the pipeline gets.
- **Risk:** liveness quality regresses. That regression would be
  security-relevant, not cosmetic.
- **What must stay true afterwards:** only that no replacement dependency
  introduces its own phone-home, which the regression check already covers.

### Option B - Build MediaPipe from source without telemetry

Upstream states that a source build does not include telemetry. Build, pin,
own, and verify that artifact instead of consuming the PyPI wheel.

- **Satisfies:** R1-R5, provided the artifact is built transparently, pinned by
  digest, identified as a project-built artifact rather than passed off as
  upstream, and verified for telemetry absence on every rebuild. Done that way
  it is a property of the software, so it does **not** fall foul of R3, and it
  is not a repackaged upstream binary presented as upstream, so it does not
  fall foul of R5.
- **Cost:** build complexity (a large Bazel C++ project on Windows with MSVC),
  provenance and reproducibility work to make the artifact identifiable and
  re-derivable, ongoing maintenance across upstream releases, and a **recurring
  regression-verification obligation** on every rebuild.
- **Risk:** the recurring cost is the risk. A rebuild that silently regains
  telemetry would restore a false claim, which is worse than the current state
  where the claim is already retracted. `scripts/check_network_activity.py` is
  what would keep that honest, and under Option B it stops being a backstop and
  becomes load-bearing.
- **Advantage:** liveness quality is unchanged, because the model and graph are
  identical.

### Rejected without further consideration

| Rejected | Why |
|---|---|
| Set an undocumented environment variable | None exists. Inventing or guessing one would be fabricating a fix. Violates R5. |
| Block `play.googleapis.com` by firewall or hosts file | A per-machine change, not a property of this software. Violates R3. Upstream offers it; that does not make it a *product* answer. |
| Binary-patch the endpoint out of a wheel-shipped `libmediapipe.dll` | Fragile, redistribution-hostile, and would present a modified binary as upstream. Violates R5. Distinct from Option B, which builds from source and says so. |
| Leave the claims as they were | Not an option. R1 is unconditional, and it is already done. |

## 6. Decision

**The Phase 3 resolution is open: neither Option A nor Option B has been
selected.** That is the decision this ADR is waiting on, and it is tracked in
[issue #6](https://github.com/AddysEdge/ai-face-auth/issues/6).

Three things are already settled and implemented, and none of them is a
substitute for that choice:

1. **Every inaccurate claim has been retracted**, and the actual behaviour is
   documented (R1). Unconditional, and not deferred pending the decision.
2. **An OS-level network regression check is in place**
   (`scripts/check_network_activity.py`), so the current state is pinned and
   any new or additional outbound destination fails rather than passing
   unnoticed. It fails closed: it cannot report success unless it has proven it
   can observe.
3. **Phase 3's no-networking requirement stands unchanged**, and this conflict
   is blocker **B17**.

## 7. Recommendation, offered but not applied

**Option A**, unless replacing the liveness model turns out to cost more
accuracy than the project can accept - in which case **Option B**.

The reasoning is about where the ongoing burden sits. A pays once, in
reimplementation and evaluation work, and then the dependency is simply gone. B
pays less up front and keeps paying: every upstream release has to be rebuilt,
re-pinned, and re-verified, and the day that lapses the project is claiming
something it is no longer checking. B is the right answer when the liveness
model cannot be matched at acceptable accuracy, and it is a defensible answer
generally - but it should be chosen with the recurring obligation understood,
not because it looks cheaper this quarter.

This is a recommendation. It is deliberately not recorded as the decision.

## 8. Consequences

- Phase 1 is documented as locally-processing but **not** network-silent. Users
  reading the README learn this before installing, not after packet-capturing.
- The security-relevant property - biometric data never leaves the machine - is
  stated separately from the network property, so the two stop being conflated.
  That conflation is what allowed the false claim to survive review.
- Phase 3 gains a blocker it cannot start without clearing.
- Any future dependency that adds a phone-home is caught by the regression
  check rather than discovered by accident during an unrelated review, which is
  how this one was found.

## 9. Phase 3 entry criterion

**B17 - MediaPipe telemetry conflicts with the Phase 3 no-networking
requirement.** Before Phase 3 may begin, this ADR must move from *Proposed* to
*Accepted* with **Option A or Option B selected, implemented, and verified**,
and `scripts/check_network_activity.py` must show the verification path making
zero outbound connections against an empty `scripts/network_allowlist.json`.

**The interim disclosure state does not clear B17.** It makes Phase 1's
documentation truthful while the conflict remains open, which is a different
thing. Neither a firewall rule nor a hosts-file entry clears it either: the
requirement is a property of the software, not of the machine it runs on.

This joins the existing Part B entry criteria in
`docs/PHASE2_ACCEPTANCE_CRITERIA.md`; it does not replace or relax any of them.

## 10. Evidence

| # | Evidence | Source |
|---|---|---|
| E1 | Endpoint `https://play.googleapis.com/log`, adjacent to `clearcut_logger.cc` / `portable_clearcut_uploader.cc` | String literals in `mediapipe/tasks/c/libmediapipe.dll` |
| E2 | All observed IPs are A records of `play.googleapis.com` | Live `Get-DnsClientCache` capture (read-only) |
| E3 | Trigger is session teardown, not `detect()`; fires with zero inference calls | `Get-NetTCPConnection -OwningProcess <pid>`, polled per step |
| E4 | Complete **MediaPipe telemetry extension** schema; no field in it can carry biometric content. Says nothing about the surrounding Clearcut envelope, which was not decrypted | Embedded protobuf descriptors for `mediapipe_log_extension.proto` |
| E5 | Metrics collection is documented and intended, and Google states input data is not sent | [MediaPipe Terms of Service](https://developers.google.com/edge/mediapipe/legal/tos), *Privacy*, last modified 2026-04-07 |
| E6 | No opt-out API will be provided; a source build or host blocking are the upstream-offered workarounds, and Google states input data is never sent | [mediapipe#6291 maintainer response](https://github.com/google-ai-edge/mediapipe/issues/6291#issuecomment-4896121772), 2026-07-06 |
| E7 | Behaviour is pre-existing, not introduced by any bump in this repository | Identical behaviour under `mediapipe==1.0.0` / `onnxruntime==1.28.0` and `1.0.1` / `1.29.0` |
| E8 | Python socket interception cannot observe it | Zero Python-level `connect` attempts recorded in every run |
| E9 | Clearcut envelope identifiers and contents were **not** determined | Out of scope: would require decrypting TLS, which would need a certificate to be installed |
