# ADR-0002: Process, service, and camera boundaries

- **Status:** Accepted (Phase 2 review).
- **Date:** 2026-08-24
- **Phase:** 2. **Nothing in this ADR is implemented.** No Windows service is
  installed, started, stopped, or configured. No camera is opened outside the
  existing Phase 1 interactive application.
- **Decision status:** **CONDITIONAL GO**, with two hard blockers (B1, B2) that
  must be cleared in a VM before Phase 3 may begin.

---

## 1. Context

ADR-0001 narrows the credential question to a smart-card-class certificate
logon on AD domain machines. This ADR answers the orthogonal question: *where
does the code run, and can it see a camera at the moment it needs to?*

`docs/PHASE2_CREDENTIAL_PROVIDER.md` proposed:

- a thin credential provider DLL in LogonUI that "renders the tile, shows
  camera preview/status";
- the Phase 1 Python/OpenCV/MediaPipe/ONNX pipeline "effectively unchanged"
  inside a Session 0 Windows service;
- IPC that "never sends raw frames or embeddings back to the credential
  provider".

Those three statements are not simultaneously satisfiable. A camera preview in
the LogonUI process requires frames in the LogonUI process; the IPC rule
forbids sending them. **This ADR resolves that contradiction (section 5.4) and
re-examines the other two claims.**

## 2. Requirements

| # | Requirement |
|---|---|
| R1 | No ML inference, model loading, or camera handling inside LogonUI's process. |
| R2 | The verification component runs at least privilege; never LocalSystem if a lower identity suffices. |
| R3 | The IPC channel never carries raw frames, embeddings, or templates (ADR-0003). |
| R4 | Enrollment data created in a user session must be usable pre-logon **without** making it readable by every local process. |
| R5 | Any camera or Session 0 claim must be evidence-backed or listed as a blocker. |
| R6 | Failure at any point falls back to another credential tile immediately; never a hung or blocked logon screen. |
| R7 | The proposed architecture must be justified by evidence, not by reuse convenience. |

## 3. Evidence from official sources

Retrieved 2026-08-24.

### E1 - The camera pipeline itself does live in Session 0

Microsoft's Frame Server documentation states, for a Frame Server Custom Media
Source:

> "Frame Server Custom Media Source runs as Local Service (not to be confused
> with Local System; Local Service is a low privileged account on Windows
> machines)."

> "Frame Server Custom Media Source runs in Session 0 (System Service session)
> and can't interact with the user desktop."

*Source:* `learn.microsoft.com/windows-hardware/drivers/stream/frame-server-custom-media-source`

**Reading.** Capture-device plumbing demonstrably operates in Session 0 under a
low-privilege service account. This makes "a service in Session 0 touching a
camera" architecturally plausible - it does **not** establish that a
*third-party* service may open a capture device there, and especially not
before any interactive user exists. That is blocker B1.

### E2 - Camera consent is a per-user setting layered over a machine setting

Windows gates camera access through the Capability Access Manager consent
store, with a machine-level (`HKLM`) setting and a per-user (`HKCU`) setting,
plus a separate `NonPackaged` sub-key governing classic Win32 desktop
applications. The per-user value takes precedence for that user.

*Sources:* `support.microsoft.com/windows/privacy/manage-app-permissions-for-a-camera-in-windows`,
`learn.microsoft.com/windows/uwp/audio-video-camera/camera-privacy-setting`

**Reading.** The consent model is written around *a signed-in user granting an
app permission*. Before interactive logon there is no signed-in user and no
`HKCU` hive loaded for one. No Microsoft documentation was found stating how -
or whether - the consent model applies to a service opening a camera in
Session 0 pre-logon. That is blocker B1's second half.

### E3 - Windows Hello's own face capture is a Microsoft component

Windows Hello face is "integrated into the Windows Biometric Framework (WBF) as
a core Microsoft Windows component" (ADR-0001 E4). Its pre-logon camera access
therefore runs through Microsoft's own biometric stack, not through a
third-party Media Foundation client. **The existence of Windows Hello face is
not evidence that a third-party service can do the same thing.**

### E4 - Per-service SIDs are the documented least-privilege identity mechanism

> "This enables developers to control access to the objects a service uses,
> instead of relying on the use of the LocalSystem account to obtain access."

> "Use the LookupAccountName and LookupAccountSid functions to convert between
> a service name and a service SID. The account name is of the following form:
> NT SERVICE\\*SvcName*"

`SERVICE_SID_TYPE_RESTRICTED` additionally "includes
SERVICE_SID_TYPE_UNRESTRICTED. The service SID is also added to the restricted
SID list of the process token", along with the World SID, the service logon
SID, and the write-restricted SID `S-1-5-33`.

*Source:* `learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_sid_info`

**Reading.** This gives a concrete, documented least-privilege identity to name
in ACLs and in the IPC endpoint's SDDL (ADR-0003) without inventing anything.

### E5 - DPAPI user scope is, by design, unusable before that user logs on

Phase 1 protects templates with `CryptProtectData` in user scope; decryption is
only possible under the same Windows user account on the same machine
(`docs/RESEARCH.md` section 11). That property is the whole point - and it is
also exactly why a pre-logon service cannot read those templates. This is a
design consequence, not a bug.

## 4. Considered alternatives

### 4.1 Where does verification run?

| # | Alternative | Verdict |
|---|---|---|
| P1 | ML pipeline inside LogonUI (the provider DLL) | **Rejected.** Loads OpenCV + ONNX Runtime + MediaPipe and their transitive native dependencies into the secure-desktop process. Violates R1. Not seriously considered. |
| P2 | Phase 1 Python pipeline, unchanged, hosted in a Session 0 service | **Rejected as the long-term boundary.** See section 5.2. |
| P3 | Native C++ service hosting ONNX Runtime directly; Python retained for research/enrollment tooling | **Selected.** See section 5.2. |
| P4 | No service at all; verification in a user-session process | **Rejected.** No user session exists at logon. Structurally impossible for the sign-in scenario. |

### 4.2 What does the tile show?

| # | Alternative | Verdict |
|---|---|---|
| U1 | Live camera preview inside the tile | **Rejected.** See section 5.4. |
| U2 | Low-resolution / blurred preview over IPC | **Rejected.** A downscaled face image is still a raw frame and still biometric data; it merely makes the violation harder to notice. |
| U3 | Status-only UI (state text, progress, countdown, explicit failure reason) | **Selected.** |

### 4.3 How does the service reach enrollment data?

| # | Alternative | Verdict |
|---|---|---|
| T1 | Reuse Phase 1's user-scope DPAPI templates | **Rejected.** Structurally impossible pre-logon (E5). |
| T2 | Machine-scope DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`) with no further control | **Rejected.** Any process on the machine that can read the file can decrypt it. Strictly weaker than Phase 1. |
| T3 | Machine-scope DPAPI **plus** a file ACL granting only the per-service SID (E4), plus an additional entropy value held in an ACL-protected location | **Selected as the minimum.** See section 5.5. |
| T4 | TPM-sealed template key via CNG Platform Crypto Provider | **Preferred long-term target; deferred.** No mature binding exists in the current stack and the project will not ship a hand-rolled security-critical binding untested against hardware (`docs/RESEARCH.md` section 11). |

## 5. Decision

### 5.1 Process topology (proposed, not implemented)

```
LogonUI.exe  (secure desktop, SYSTEM)
  |
  |  Credential Provider DLL - THIN
  |    - renders a tile
  |    - status-only UI (no video, no images)
  |    - no ML, no model files, no camera handle
  |    - IPC client only
  |
  |  named pipe, restrictive SDDL (ADR-0003)
  v
FaceAuth verification service  (Session 0, no desktop)
  |    - identity: dedicated service, LOCAL SERVICE base account,
  |      SERVICE_SID_TYPE_RESTRICTED, per-service SID NT SERVICE\FaceAuthVerifier
  |    - opens the camera, runs detection/quality/liveness/embedding/compare
  |    - reads machine-scope, service-SID-ACL'd templates
  |    - returns ONLY a short-lived, single-use, request-bound verdict
  v
(on ALLOW) the provider releases the pre-provisioned certificate credential
handle to the smart-card logon path -> LSA/Kerberos/KDC decide (ADR-0001)
```

### 5.2 The Python pipeline is **not** the long-term service boundary

Recommendation: **P3 - a native C++ service.** Phase 1's Python code is not
rewritten, redesigned, or weakened; it stays exactly as it is and remains the
research, enrollment-tooling, and evaluation implementation. What changes is
the claim in `docs/PHASE2_CREDENTIAL_PROVIDER.md` that it would be reused
"effectively unchanged" inside the service.

Reasons, in order of weight:

1. **Attack surface at a pre-logon boundary.** A Python host in a pre-logon
   service pulls in the interpreter, its module search path, `site-packages`,
   and the transitive native dependency graph of OpenCV, MediaPipe, and ONNX
   Runtime. Every one of those is a code-loading surface that must be
   integrity-controlled at a moment when the machine has no user context. A
   native host that links ONNX Runtime and loads two checksum-pinned model
   files has a dramatically smaller graph.
2. **No supported-configuration statement exists.** None of OpenCV, MediaPipe,
   or ONNX Runtime documents "runs correctly in a Windows service in Session 0
   before interactive logon" as a supported configuration. Shipping a
   security-critical pre-logon component on an undocumented configuration is
   the kind of claim requirement R5 exists to prevent.
3. **Update coupling.** A pre-logon component that breaks makes the machine
   harder to log into. Coupling that component's availability to a Python
   dependency graph that moves on its own release cadence is a poor trade.
4. **Model integrity.** Phase 1 verifies model hashes at *download* time only
   (`docs/THREAT_MODEL.md` section 10). A pre-logon service must verify at
   *load* time. That is easier to guarantee, and easier to audit, in the native
   host.

**Consequence:** Phase 3 would need a native re-implementation of the
detect/quality/liveness/embed/compare path against the same ONNX models, with
Phase 1 retained as the reference implementation and as the differential-test
oracle. That is a significant cost, and it is stated here rather than
discovered later.

### 5.3 Service identity and privileges (proposed)

| Property | Value | Rationale |
|---|---|---|
| Account | `NT AUTHORITY\LOCAL SERVICE` | Lowest built-in service account with the needed local access; explicitly *not* LocalSystem (E1 uses the same account for the frame-server source). |
| Service SID | `SERVICE_SID_TYPE_RESTRICTED`, `NT SERVICE\FaceAuthVerifier` | Nameable in ACLs and in the pipe SDDL; adds the write-restricted SID to the token (E4). |
| Start type | Manual, triggered / demand start | No reason to run when nobody is signing in. |
| Desktop interaction | None. Never `SERVICE_INTERACTIVE_PROCESS`. | Session 0 isolation. |
| Network | None. Deny all outbound. | Verification is entirely local; the KDC/CRL traffic belongs to LSA, not to this service. |
| Privileges | `SeChangeNotifyPrivilege` only, unless a specific need is demonstrated and documented. All others removed via a required-privileges list. | Least privilege. |
| Filesystem | Read: model files, template store. Write: its own state/log directory only. | Enforced by ACL, not convention. |
| Recovery | No automatic restart loop that could mask a failure; failures surface as an immediate DENY to the client (R6). | Fail closed and fail visibly. |

### 5.4 The secure-preview contradiction: **RESOLVED by removing the preview**

**Decision: the credential provider tile shows status only. No live camera
preview. No still frames. No thumbnails. No blurred or downscaled images.**

Reasoning:

1. Rendering a preview inside LogonUI requires frame data inside LogonUI's
   process, which directly contradicts the IPC rule in R3 - and the IPC rule is
   the more important of the two, because it is what keeps biometric data off
   the channel and out of the secure-desktop process.
2. A "preview" that is downscaled or blurred is still an image of a person's
   face crossing a process boundary into the most security-sensitive process on
   the machine. Softening it is not a mitigation, it is a disguise (U2).
3. A preview provides no security value. It is purely an affordance, and the
   affordance can be met with text.

**What the tile shows instead**, driven entirely by the state machine in
ADR-0003 - the same states the Phase 1 demo UI already exposes:

`CAMERA READY` -> `LOOKING FOR A FACE` -> `HOLD STILL / <challenge prompt>` ->
`VERIFYING` -> `VERIFIED` / `NOT VERIFIED - <reason>` / `TIMED OUT` /
`UNAVAILABLE - use another sign-in option`,
plus a visible countdown to the request deadline.

`docs/PHASE2_CREDENTIAL_PROVIDER.md` has been corrected accordingly; the phrase
"shows camera preview/status" no longer stands.

### 5.5 Pre-logon template availability (proposed)

Two distinct stores, deliberately not shared:

| Store | Scope | Protection | Reader |
|---|---|---|---|
| Phase 1 interactive store (exists today) | Per-user | DPAPI **user** scope | The signed-in user's own process. Unchanged. |
| Phase 3 pre-logon store (proposed) | Per machine, one record per enrolled Windows identity | DPAPI **machine** scope + additional entropy + NTFS ACL granting read only to `NT SERVICE\FaceAuthVerifier` and Administrators | The verification service only. |

Enrollment for the pre-logon store is a separate, explicitly authorized
operation (ADR-0004) - the interactive Phase 1 template is **not** copied or
promoted into it. Two reasons: the interactive template was created under a
different authorization story, and silently widening the readership of
biometric data is exactly the kind of change that must be an explicit user
decision.

**Stated honestly:** machine-scope DPAPI is weaker than user-scope DPAPI. The
ACL, not the encryption, is doing most of the work. An attacker with SYSTEM or
Administrator rights on the machine can read the pre-logon store. That is a
real regression relative to Phase 1's protection level and is the price of
pre-logon availability. T4 (TPM sealing) is the intended fix and is not
available yet.

### 5.6 Camera ownership and contention (proposed)

- The service opens the capture device only for the duration of one verification
  request, and releases it immediately afterwards - including on cancel,
  timeout, and error paths.
- If the device is already in use (a user-session application, another verifier
  instance, a virtual-camera filter), the request **fails closed immediately**
  with `CameraUnavailable`. It does not wait, retry in a loop, or block the
  logon screen (R6).
- Only one verification request may be in flight per machine at a time; a
  second concurrent request is rejected with `Busy` rather than queued behind a
  camera lock (ADR-0003).
- The service must not attempt to force-release a device held by another
  process.

## 6. Security implications

1. **LogonUI stays thin.** No ML, no model files, no camera handle, no image
   data. The blast radius of a bug in this project's provider code is a broken
   tile, not a compromised secure desktop.
2. **The pre-logon store is the new soft spot.** section 5.5 states this
   plainly. It, plus whatever credential handle the ALLOW releases (ADR-0001
   section 7.2), are the two highest-value local targets in the whole design.
3. **A pre-logon camera is a privacy-relevant capability.** A service that can
   open the camera before anyone signs in is exactly the capability a user
   would want to be able to see, disable, and uninstall. ADR-0004 must make
   that possible; a hidden always-on pre-logon camera consumer would be
   unacceptable regardless of intent.
4. **Session 0 isolation is preserved.** The service never creates a window,
   never marks itself interactive, and never touches the secure desktop.
5. **Contention is a denial-of-service vector, and is handled by failing over
   to another tile** rather than by fighting for the device.

## 7. Deployment limitations

- Requires an OEM/attached camera that the verification service can actually
  open pre-logon. **Unverified** - blocker B1.
- Requires a native re-implementation of the Phase 1 pipeline (section 5.2).
  Phase 1's Python implementation is not shippable as the pre-logon service.
- Requires per-machine enrollment; templates are not portable between machines
  (ADR-0004).
- Machine-scope template protection is weaker than Phase 1's user-scope DPAPI
  and stays that way until TPM sealing (T4) exists.
- No camera preview at the logon screen. This is a deliberate, permanent design
  constraint, not a temporary simplification.

## 8. Blockers (must be cleared in a VM before Phase 3)

| # | Blocker | How to clear |
|---|---|---|
| **B1** | **Unproven: can a third-party Session 0 service open a capture device before any interactive logon, and how does Capability Access Manager consent apply with no user hive loaded?** No Microsoft documentation was found that answers this. E1 shows Microsoft's own frame-server component does operate in Session 0 as LOCAL SERVICE, which makes it plausible, and E3 shows Windows Hello does it through a component we cannot use. **Neither is evidence for a third party.** | Build a throwaway VM. Install a minimal, do-nothing service that attempts to enumerate and open a capture device at various points relative to logon. Record exactly what succeeds, what fails, and with which error, under each consent-setting combination. If it cannot be done, ADR-0002 becomes a NO-GO and Phase 3 cannot proceed as designed. |
| **B2** | **Unproven: acceptable pre-logon latency and reliability for the native pipeline** (camera warm-up + detection + liveness challenge + embedding on a cold, pre-logon Session 0 service). | Measure in the same VM once B1 clears. A logon tile that takes many seconds or fails intermittently is worse than no tile. Set a hard budget before measuring, not after. |

Two further items are tracked as risks rather than blockers: the native
re-implementation effort (section 5.2), and the machine-scope template
protection regression (section 5.5).

## 9. Unresolved questions

| # | Question | Owner phase |
|---|---|---|
| Q1 | Which capture API should the native service use pre-logon - Media Foundation, or a lower-level device interface - and which is documented as usable from a service? | 3 (with B1) |
| Q2 | Can the IR sensor already present on typical hardware be opened by the same path, which would materially improve liveness? | 3 |
| Q3 | What is the correct behaviour when several Windows identities are enrolled on one machine - identify-1:N, or verify-1:1 against a user-selected tile? (1:1 is the safer default and is assumed.) | 3 |
| Q4 | Does the service need a watchdog, and if so how does it avoid masking a persistent failure that should surface as UNAVAILABLE? | 3 |

## 10. Status

**CONDITIONAL GO.** The architecture is defined and the preview contradiction
is resolved. B1 and B2 are open and are hard gates: if B1 cannot be cleared in
a VM using documented APIs, this ADR flips to **NO-GO** and no Credential
Provider work may begin.
