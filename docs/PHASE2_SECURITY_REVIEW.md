# Phase 2 Security and Feasibility Review

**Date:** 2026-08-24
**Scope:** architecture and security review of the proposed Windows Credential
Provider direction, plus safe native foundations. **No Credential Provider is
registered. No Windows service is installed. No Windows authentication,
registry, LSA, Winlogon, LogonUI, Credential Guard, or Windows Hello state was
read or changed by this work. No Windows password is handled anywhere in this
repository.**

**Phase 3 is not implemented.**

---

## 0. Headline result

> **CONDITIONAL GO**, and the condition is severe enough that it changes the
> product.
>
> The originally intended use case - **face unlock for a local Windows account
> on a personal machine** - is a **NO-GO**. There is no documented, publicly
> supported Windows credential mechanism by which a third-party credential
> provider can authenticate a *local* account without handling that account's
> password, which this project forbids.
>
> The only route to a real Credential Provider that survives review is
> **certificate / smart-card-class logon for Active Directory domain
> accounts**, and only inside a deployment that already has a domain
> controller, an enterprise PKI, certificate enrolment, account mapping, and
> reachable CRL/OCSP endpoints at sign-in time.
>
> Three hard blockers remain unproven and must be cleared before Phase 3 may
> begin: camera access in Session 0 pre-logon (B1), pre-logon latency and
> reliability (B2), and a password-free way to authorize enrollment at all
> (B15).

| Account type | Result |
|---|---|
| Local Windows account | **NO-GO** |
| Microsoft account (MSA) | **NO-GO** |
| Active Directory domain account | **CONDITIONAL GO** |
| Microsoft Entra ID account | **DEFERRED - unproven** |

Full reasoning and primary sources: [ADR-0001](adr/0001-windows-account-and-credential-strategy.md).

## 1. What was reviewed, and how

Four questions, each resolved in its own ADR:

| ADR | Question | Result |
|---|---|---|
| [0001](adr/0001-windows-account-and-credential-strategy.md) | Which accounts can be supported, and what exact credential is submitted? | CONDITIONAL GO (AD only) |
| [0002](adr/0002-process-service-and-camera-boundaries.md) | Where does the code run, and can it see a camera pre-logon? | CONDITIONAL GO, 2 blockers |
| [0003](adr/0003-ipc-security-protocol.md) | How do the two halves talk without becoming the weak link? | GO (design + inert scaffold) |
| [0004](adr/0004-enrollment-provisioning-and-recovery.md) | Who enrolls, how is it provisioned, and how does a user recover? | CONDITIONAL GO (AD only) |

Method: every load-bearing claim about Windows behaviour is quoted verbatim
from current Microsoft Learn documentation and cited in the relevant ADR.
Claims that could not be sourced are labelled **unproven** and excluded from
the decision rather than assumed favourable. Nothing was tested against a real
lock screen, secure desktop, service, or registry key.

### Confidence labelling used throughout

| Label | Meaning |
|---|---|
| **Verified** | Quoted from current official Microsoft documentation. |
| **Inference** | A conclusion drawn from verified facts; the reasoning is shown so it can be challenged. |
| **Unproven** | No supporting official documentation was found. Never used as a basis for a GO. |
| **Blocker** | An unproven item that must be experimentally resolved before Phase 3. |

## 2. Credential and account strategy

### 2.1 The question that decides everything

A credential provider does not decide anything. **Verified:**

> "It's important to note that credential providers are not enforcement
> mechanisms. They are used to gather and serialize credentials, submitting
> them for authorization. The local authority and authentication packages will
> handle and any necessary security enforcement."
> - `learn.microsoft.com/windows/win32/secauthn/credential-providers-in-windows`

So the only question that matters is: after a face match, **what exact
Windows-recognized credential is submitted?** Everything else is UI.

### 2.2 Certificate logon is a domain mechanism (Verified)

The documented smart-card sign-in flow packages a `KERB_CERTIFICATE_LOGON`,
hands it to LSA, which calls the Kerberos SSP to build a PKINIT `KRB_AS_REQ`
sent to "the Key Distribution Center (KDC) service that runs on a domain
controller", where "The KDC finds the user's account object in Active Directory
Domain Services (AD DS)". The structure's own reference confirms it: an empty
`DomainName` means "authenticate against the domain to which the computer is
joined".

**Inference:** certificate logon cannot authenticate a local SAM account.
There is no KDC and no AD DS account object for one. This is the finding that
turns the local-account goal into a NO-GO.

**Deployment cost, stated up front rather than buried:** a KDC certificate, an
enterprise CA in the NTAuth store, smart-card-logon-EKU certificates, a
**strong** certificate-to-account binding (section 2.2a), and HTTP CRL
distribution points that are published and reachable *before* interactive
logon.

### 2.2a Account mapping must be STRONG - a correction (Verified)

An earlier revision of this review listed "UPN in `subjectAltName`, or via
`altSecurityIdentities`" as sufficient. **That is wrong under current
enforcement.** KB5014754 divides mappings into strong and weak:

| Strong | Weak |
|---|---|
| SID security extension, OID `1.3.6.1.4.1.311.25.2` | UPN / name-based mapping |
| `X509IssuerSerialNumber` | `X509IssuerSubject` |
| `X509SKI` | `X509SubjectOnly` |
| `X509SHA1PublicKey` | `X509RFC822` |

Domain controllers entered **Full Enforcement on 11 February 2025**, and the
`StrongCertificateBindingEnforcement` rollback key became **unsupported on
9 September 2025**. Under Full Enforcement, if "a certificate cannot be strongly
mapped, authentication will be denied" (Event ID 39).

*Source:* `support.microsoft.com/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16`

**Consequence:** a deployment must issue certificates carrying the SID extension
or an explicitly strong `altSecurityIdentities` value. An existing PKI issuing
UPN-mapped certificates needs template and re-issuance work first, which is a
real added cost. **Weakening domain-controller enforcement to avoid that is not
an option this project will propose**, and verifying against a Full Enforcement
DC is now criterion B4a.

### 2.3 NGC / Windows Hello container gating is unproven - and the earlier claim is withdrawn

Phase 1's `docs/PHASE2_CREDENTIAL_PROVIDER.md` suggested a provider "could, in
principle, sit in front of the same class of container using the same supported
provisioning APIs Windows Hello uses." **That claim is withdrawn.**

The nearest public API, `KeyCredentialManager`, is documented as operating "for
the current user and application" - it needs a signed-in user, it is
app-scoped, and it produces nothing `LsaLogonUser` consumes. No documentation
was found describing a supported third-party gating path for the NGC container.
Per the project's own rule ("treat the NGC approach as unproven unless official
Microsoft documentation demonstrates that it is supported"), it is excluded.

### 2.4 Other mechanisms, and why each was rejected

| Mechanism | Verdict | One-line reason |
|---|---|---|
| Password replay | Rejected | Forbidden absolutely; would make the face the real decision while pretending Windows made it. |
| Custom LSA authentication package (SSP/AP) | Rejected | Requires writing to `HKLM\...\Control\Lsa\Security Packages` (prohibited here), and **Verified:** under LSA protection "Any plug-ins that are unsigned or aren't signed with a Microsoft signature fail to load in LSA." |
| Third-party WBF face engine adapter | Rejected, unproven | **Verified:** Windows Hello face is "a core Microsoft Windows component"; the third-party contribution is a certified IR *sensor*, not a matcher. |
| Wrapping the system password provider | Rejected | **Verified:** Microsoft discourages it - "can lead to problematic behavior... or even preventing the user from accessing their device." |
| Windows Hello for Business | Not available | **Verified:** every documented deployment model requires Entra ID and/or AD. None exists for a local account. |

### 2.5 Must the product requirements be narrowed? Yes.

**Yes, materially.** The supported subset is: *AD domain accounts, on
domain-joined machines, with an enterprise PKI.* The personal-machine local
account use case that motivated the project is out of scope for Windows
integration and stays where Phase 1 already put it - an application-level
authentication control that does not touch Windows sign-in.

## 3. Process, identity, and camera architecture

Full detail in [ADR-0002](adr/0002-process-service-and-camera-boundaries.md).

### 3.1 Can the Phase 1 Python pipeline run in Session 0? Not as the shipping boundary.

**Recommendation: no** - and the recommendation is based on the boundary's
requirements, not on the inconvenience of rewriting.

A pre-logon service written in Python drags in the interpreter, its module
search path, `site-packages`, and the transitive native dependency graphs of
OpenCV, MediaPipe, and ONNX Runtime - every one a code-loading surface, at a
moment when the machine has no user context. None of those projects documents
"Windows service, Session 0, before interactive logon" as a supported
configuration, so shipping there would be exactly the kind of unevidenced claim
this review exists to prevent. And a pre-logon component that breaks makes the
machine harder to sign into, which is a bad thing to couple to an independently
moving dependency graph.

**Decision: a native C++ service host for the pre-logon path**, with model
integrity verified at *load* time rather than only at download time. **Phase 1's
Python code is not rewritten, redesigned, or weakened by this** - it stays as
the research, enrollment-tooling, evaluation implementation, and as the
differential-test oracle for any native re-implementation. The cost of that
re-implementation is real and is stated here rather than discovered in Phase 3.

### 3.2 Camera availability before sign-in - **BLOCKER B1**

**Verified:** Microsoft's Frame Server Custom Media Source "runs as Local
Service" and "runs in Session 0 (System Service session) and can't interact with
the user desktop." So capture plumbing demonstrably operates in Session 0 under
a low-privilege service account.

**Verified:** camera consent is a per-user setting (`HKCU`) layered over a
machine setting (`HKLM`), with a separate `NonPackaged` sub-key for classic
Win32 desktop applications.

**Unproven, and this is the blocker:** whether a *third-party* service may
enumerate and open a capture device in Session 0 **before any interactive user
exists**, and how the per-user consent model applies when no user hive is
loaded. Windows Hello does this - but through a Microsoft component this
project cannot use, so its existence is not evidence for a third party.

**How B1 gets cleared:** in a throwaway VM, install a minimal do-nothing
service that attempts to enumerate and open a capture device at defined points
relative to logon, and record exactly what succeeds and fails under each
consent-setting combination. **If it cannot be done with documented APIs,
ADR-0002 flips to NO-GO and Phase 3 cannot proceed as designed.**

### 3.3 Device contention and ownership

The camera is opened only for the duration of one request and released on every
path including cancel, timeout, and error. If another process holds it, the
request **fails closed immediately** - no waiting, no retry loop, no blocking
the logon screen, and no attempt to force-release a device held by someone
else. One verification in flight per machine; a second is rejected rather than
queued behind a camera lock.

### 3.4 Service identity and minimum privileges

`NT AUTHORITY\LOCAL SERVICE` (explicitly not LocalSystem), with a per-service
SID `NT SERVICE\FaceAuthVerifier` at `SERVICE_SID_TYPE_RESTRICTED` - the
documented mechanism "to control access to the objects a service uses, instead
of relying on the use of the LocalSystem account." Demand-start, no desktop
interaction, no network access, `SeChangeNotifyPrivilege` only, write access
limited to its own state directory. Full table in ADR-0002 section 5.3.

**"No network access" is unchanged and unweakened - and it is now a blocker.**
The Phase 1 dependency set cannot meet it today: the bundled MediaPipe binary
uploads usage telemetry to `play.googleapis.com` with no supported opt-out
(`docs/PRIVACY_NETWORK_AUDIT.md`). That conflict is tracked as Phase 3 entry
criterion **B17** and decided in ADR-0005; it must be resolved by replacing or
rebuilding the dependency, not by relaxing this requirement.

### 3.5 Making enrollment data available pre-logon, without weakening it

Phase 1's user-scope DPAPI templates are, by design, unreadable before that
user logs on. That property is the point - and it is also why they cannot be
reused.

The proposal is a **separate** pre-logon store: machine-scope DPAPI, plus
additional entropy, plus an NTFS ACL granting read only to the service SID and
Administrators. The Phase 1 interactive template is never copied or promoted
into it; pre-logon enrollment is a separate act with separate consent.

**Stated without softening:** machine-scope DPAPI is weaker than user-scope
DPAPI. The ACL is doing most of the work. A SYSTEM or Administrator attacker on
the machine can read the pre-logon store. That is a genuine regression relative
to Phase 1 and is the price of pre-logon availability. TPM sealing is the
intended fix and does not exist yet.

### 3.6 The secure-preview contradiction - **RESOLVED, preview removed**

The Phase 1-era design simultaneously required the tile to "show camera
preview/status" and required the IPC channel never to carry frames. Those are
not compatible.

**Resolution: the tile shows status only.** No live preview, no stills, no
thumbnails, no blurred or downscaled images. A softened preview is still an
image of a person's face crossing into the most security-sensitive process on
the machine; softening it is a disguise, not a mitigation. The preview has no
security value - it is an affordance, and the affordance is met with text plus
a countdown:

`CAMERA READY` -> `LOOKING FOR A FACE` -> `HOLD STILL / <challenge>` ->
`VERIFYING` -> `VERIFIED` / `NOT VERIFIED - <reason>` / `TIMED OUT` /
`UNAVAILABLE - use another sign-in option`.

`docs/PHASE2_CREDENTIAL_PROVIDER.md` has been corrected; the "camera preview"
wording no longer stands anywhere in this repository.

## 4. IPC security

Full specification and threat table in
[ADR-0003](adr/0003-ipc-security-protocol.md); the contract, parser, state
machines, replay detection, and fail-closed rules are **implemented** as an
inert normal-desktop library in `native/`.

### 4.1 What the channel may never carry

Raw frames, embeddings, templates, passwords, certificates, private keys, TPM
secrets, reusable assertions. **This is enforced structurally, not by policy:**
the version-1 wire format has no free-form field, no blob, and no
unbounded-length value. The largest opaque field is 128 bytes. Requirement
compliance is checkable by reading one header.

### 4.2 Result binding

A result is short-lived, single-use, and bound to its originating request ID,
nonce, account binding, and deadline. Any mismatch is a hard DENY. Consuming a
result once moves the client state machine to a terminal `Consumed` state; a
second consume fails.

### 4.3 Endpoint identity

**Verified, and this is the most important implementation rule in the whole
design:** a named pipe created with a NULL security descriptor grants "read
access to members of the Everyone group and the anonymous account." The
endpoint must therefore be created with an explicit SDDL naming only SYSTEM and
the per-service SID, with `FILE_FLAG_FIRST_PIPE_INSTANCE` against squatting and
`PIPE_REJECT_REMOTE_CLIENTS` against remote peers.

### 4.4 Two residual risks that are recorded rather than papered over

1. **A pipe ACL that admits SYSTEM admits every SYSTEM process**, not just
   LogonUI. An attacker already running as SYSTEM can speak this protocol. This
   is accepted: such an attacker already owns the machine and does not need to
   defeat a logon tile. Recorded rather than mitigated with a scheme that would
   only look stronger.
2. **TOCTOU between verification and credential submission is irreducible.** A
   gap always exists between "the face matched" and "the credential was
   submitted". Short expiry narrows it; nothing closes it.

### 4.5 Covered in the design and in the native tests

Endpoint identity, SDDL, service SID, client and server authentication, request
IDs, cryptographically random nonces, replay rejection, request-to-result
binding, user/account binding, session and desktop binding, deadlines, timeouts,
duplicate requests, malformed and oversized messages, length limits, invalid
state transitions, client and server disconnect, service restart, concurrency,
denial of service, confused deputy, TOCTOU, logging restrictions, and
fail-closed behaviour.

**Two scope corrections, made rather than glossed over:**

- **In-flight cancellation is NOT implemented and is explicitly deferred.** A
  version-1 server calls its verification backend synchronously, so it cannot
  read a cancellation while verifying - a `CancelRequest` message could only
  ever have been handled *between* requests, which is not cancellation. The
  message type was removed, type 3 is permanently reserved in v1, and real
  cancellation is a Phase 3 requirement needing an asynchronous server and a
  protocol version bump (ADR-0003 section 5.8, criterion B16).

  What version 1 provides instead is local client abandonment. **Client
  abandonment is local and sends nothing. The server remains unaware. A
  synchronous in-flight backend continues holding its worker and concurrency
  gate until it returns. The post-verification deadline check prevents a late
  decision from producing an `Allow`, but it does not bound or interrupt the
  backend call. B16 requires the Phase 3 design to make the call itself
  genuinely bounded and cancellable.** What actually stops the provider tile
  hanging is the *client's* own bounded deadline and bounded transport reads -
  a property of the client alone, not evidence that the server side is
  bounded.
- **No wall clock participates in any security decision.** An earlier draft
  serialized Unix timestamps for deadlines and result expiry. System time can
  jump backwards or forwards, which would silently extend a "short-lived"
  result. The protocol now carries only bounded *relative* durations, and each
  side derives its own deadline from its own monotonic clock; a result can only
  shorten the client's window, never extend it (ADR-0003 section 5.1a).

## 5. Enrollment, provisioning, and recovery

Full detail in
[ADR-0004](adr/0004-enrollment-provisioning-and-recovery.md).

- **Who enrolls:** only the holder of the identity, interactively, on that
  machine. Administrators may remove an enrollment; they may not create one for
  someone else.
- **Authorization: UNRESOLVED - blocker B15.** An earlier revision of this
  review claimed `CredUIPromptForWindowsCredentials` provided a fresh OS-issued
  re-authentication without exposing the password. **That claim is withdrawn.**
  Microsoft documents that the API returns the credential BLOB to the caller
  ("For Kerberos, NTLM, or Negotiate credentials, call the
  **CredUnPackAuthenticationBuffer** function to convert this BLOB to string
  representations of the credentials"), makes the caller responsible for
  scrubbing it ("clear it from memory by calling the **SecureZeroMemory**
  function, and free it by calling the **CoTaskMemFree** function"), and does
  not itself validate anything - `dwAuthError` exists to relay a *previous*
  validator's failure. Using it would put this project in direct contact with a
  Windows password, which is permanently prohibited. **No replacement is
  proposed**, because guessing at another API would repeat the error. See
  ADR-0004 section 5.1a.
- **Association:** a random opaque handle crosses the wire; the handle-to-SID
  map stays in the ACL-protected store.
- **Protection at rest:** machine-scope DPAPI + entropy + service-SID ACL, with
  the regression stated plainly (section 3.5). TPM sealing is the target.
- **Provisioning:** through the domain's existing PKI only, and the certificate
  must carry a **strong** account binding - the SID security extension (OID
  `1.3.6.1.4.1.311.25.2`) or a strong `altSecurityIdentities` value
  (`X509IssuerSerialNumber`, `X509SKI`, `X509SHA1PublicKey`). Per KB5014754,
  UPN and other name-based mappings are **weak** and are denied under Full
  Enforcement, which domain controllers entered on 11 February 2025; the
  `StrongCertificateBindingEnforcement` rollback key became unsupported on
  9 September 2025. This project never becomes a CA, never issues a
  certificate, and never proposes weakening enforcement.
- **Renewal:** the domain's autoenrollment. The tile hides itself before an
  expired certificate can fail at submission.
- **Revocation:** two independent halves - removing the enrollment stops the
  tile, PKI revocation stops the credential. Confusing them would create a
  false sense of revocation.
- **Deletion:** actually deletes, verified by a subsequent read.
- **Machine replacement:** templates are machine-bound and do not transfer. No
  export, no backup, no roaming - deliberately.
- **Every failure** (camera, privacy setting, service, IPC, template,
  certificate, KDC) resolves to "use another sign-in option".
- **Uninstall** is ordered, with "the logon screen still enumerates the password
  provider" as a hard gate before proceeding, and must succeed even from a
  already-broken state.
- **Fallback guarantee:** the password provider stays enabled at all times, and
  the `Exclude` mechanism is never populated. Microsoft's own guidance is the
  authority here: "there should always be at least one system credential
  provider available for every user on the device."

## 6. Native scaffolding built in this phase

Justified because the review reached CONDITIONAL GO rather than NO-GO. See
`native/README.md` for build and test instructions.

**What it is:** a Windows x64, MSVC-compatible, C++20 CMake/CTest project with
strict warnings-as-errors and no third-party runtime dependencies, containing
the versioned IPC contract, a strict parser, both protocol state machines,
bounded message handling, cryptographically random IDs and nonces, replay
detection, monotonic deadline and timeout handling, local client abandonment
(there is no cancellation message - see above), privacy-safe diagnostics, a
thread-safe concurrency gate a server session really holds across its
verification, inert boundary interfaces, and a fake client/server pair that runs
on the normal desktop over an in-process transport and over a user-owned
loopback named pipe with genuinely bounded I/O.

**What it is not:** it does not build or register a Credential Provider DLL, does
not implement any COM interface, does not install or interact with a service,
does not construct any `KERB_*` credential structure, does not touch the TPM,
NCrypt, certificates, or the registry, does not open a camera, and does not call
any undocumented API. The fake client and server use **opaque test identities and
simulated outcomes only**, and every outcome they print is labelled
`PROTOCOL-TEST RESULT (NOT A WINDOWS AUTHENTICATION DECISION)`.

**Provenance:** no Microsoft sample code was copied or adapted. The protocol,
parser, state machines, and tests are original work for this repository. Where
Microsoft documentation is relied on for a factual claim, it is cited inline in
the relevant ADR.

## 7. Phase 1 preservation

Phase 1 was not redesigned, weakened, or rewritten. Verified after this phase's
changes:

- No network calls were **added** by Phase 2, and no biometric data is
  transmitted. The original wording here claimed Phase 1 "works fully
  offline"; that was inaccurate and is retracted. The bundled MediaPipe
  binary uploads usage telemetry to `play.googleapis.com` and always did.
  See `docs/PRIVACY_NETWORK_AUDIT.md` and ADR-0005 (Phase 3 blocker B17).
- Unexpected errors still fail closed.
- Raw enrollment images still not retained by default.
- Templates still protected locally by user-scope DPAPI.
- Privacy-safe logging restrictions intact.
- Rate limiting still persistent across process invocations.
- CLI and demo behaviour unchanged and compatible.
- The application still states clearly that it does not integrate with Windows
  sign-in.
- RGB-camera and liveness limitations remain prominently documented, including
  the live-tested head-turn spoof finding.

No file under `src/`, `tests/`, or `scripts/` was modified in Phase 2.

## 8. Consolidated blockers and risks

### Blockers - must be cleared before Phase 3

| # | Blocker | Owner |
|---|---|---|
| **B1** | Unproven: can a third-party Session 0 service open a capture device before interactive logon, and how does camera consent apply with no user hive loaded? Must be settled in a VM. If not, ADR-0002 is NO-GO. | ADR-0002 |
| **B2** | Unproven: acceptable pre-logon latency and reliability for a cold Session 0 verification (camera warm-up + detect + liveness + embed). Budget must be set before measuring. | ADR-0002 |
| **B3** | Unresolved: whether a TPM-backed CNG KSP key without a virtual smart card can be consumed by the `KERB_CERTIFICATE_LOGON` path, or whether a VSC is mandatory - and whether VSCs remain supported. | ADR-0001 Q1/Q2 |
| **B4** | Missing: an AD domain + enterprise PKI lab (KDC certificate, NTAuth CA, enrolment, CRL/OCSP). Without it, nothing in ADR-0001 section 5.2 is testable. | ADR-0001 |
| **B5** | Not yet done: every install/uninstall test runs on a disposable VM with a written snapshot/rollback policy. No physical or primary machine, ever. | ADR-0004 |
| **B11** | Not yet done: an independent security review of the *implementation plan* by someone with prior Windows credential-provider or LSA-adjacent experience, before any provider code is written. | all |
| **B15** | **Unresolved: no password-free, OS-mediated enrollment-authorization mechanism has been proven.** The previously claimed one does not qualify. Without it, pre-logon enrollment cannot be authorized safely and Phase 3 cannot proceed. | ADR-0004 5.1a |
| **B4a** | Not yet done: strong certificate binding verified against a **Full Enforcement** domain controller, including observing a weak-mapped certificate fail with Event ID 39. | ADR-0001 E8 |
| **B16** | Deferred by design: in-flight cancellation requires a genuinely bounded/cancellable backend and an asynchronous or otherwise interruptible service. Version 1 has neither. | ADR-0003 5.8/5.9 |

**This table lists the architecture-critical blockers, not the whole gate.** The
canonical list is `docs/PHASE2_ACCEPTANCE_CRITERIA.md` Part B, and **every**
criterion in it must pass - B1, B2, B3, B4, B4a, B5-B14, B15, and B16. The
identifiers are not a contiguous range.

### Accepted risks

| # | Risk | Why accepted |
|---|---|---|
| A1 | A pipe ACL admitting SYSTEM admits all SYSTEM processes. | Such an attacker has already won; a bespoke scheme would only look stronger. |
| A2 | TOCTOU between verification and credential submission. | Irreducible; narrowed by short expiry. |
| A3 | Machine-scope pre-logon template protection is weaker than Phase 1's user scope. | The price of pre-logon availability; TPM sealing is the intended fix. |
| A4 | Whatever the ALLOW releases becomes the highest-value local target. | Inherent to the "biometric gate in front of a credential" pattern. |
| A5 | Native re-implementation of the pipeline is a significant cost. | Stated now rather than discovered later. |
| A6 | RGB liveness is materially weaker than the Windows Hello IR bar. | Documented everywhere; never claimed otherwise. |

## 9. Standing constraints - confirmed unchanged

- No Credential Provider registered; no CLSID or provider registry entry created
  or modified.
- No Windows service installed, started, stopped, or configured.
- No modification of LogonUI, Winlogon, LSA, Credential Guard, Windows Hello,
  provider filters, authentication policies, or account settings.
- This provider is never the sole sign-in option; the password provider and
  Windows Hello are never disabled or hidden.
- No Windows password requested, read, extracted, derived, stored, serialized,
  transmitted, or auto-typed - anywhere, at any layer.
- No undocumented NGC or Windows Hello internals used.
- No claim of a supported API or integration path without a current official
  Microsoft citation.
- No path that reports successful Windows authentication based only on a face
  match.
- No experiments on the real lock screen or secure desktop.
- No certificates, TPM keys, NGC containers, or production credentials
  provisioned.
- No biometric data, templates, raw images, model weights, runtime logs, private
  keys, certificates, secrets, registry exports, or generated binaries committed.
- This project is **not** described as equivalent to Windows Hello.

## 10. Recommendation

**Phase 3 may not begin yet.**

The review reached CONDITIONAL GO, which is enough to justify the documentation
and the inert native scaffold delivered here - but **every Part B entry
criterion remains open**, and B1 or B15 could each still turn the whole
architecture into a NO-GO. The blockers listed below are the
architecture-critical ones; they are not the whole gate. The canonical list is
`docs/PHASE2_ACCEPTANCE_CRITERIA.md` Part B, and it includes B4a and B16 - it
is not a contiguous numeric range. Writing
credential-provider code before B1 is settled would be building on an
unverified assumption.

**The recommended next step is not Phase 3. It is a VM-only feasibility spike**
that answers B1 and B2 with measurements, a documentation search that either
closes B15 or confirms there is no safe way to authorize enrollment, and a
decision by the project owner on whether the AD-domain-only scope in ADR-0001 is
a product they actually want.
If the answer to that second question is no, the honest outcome is to keep
Phase 1 as an application-level control and stop - which is a legitimate result,
not a failure.

Exact entry criteria: [`docs/PHASE2_ACCEPTANCE_CRITERIA.md`](PHASE2_ACCEPTANCE_CRITERIA.md).
