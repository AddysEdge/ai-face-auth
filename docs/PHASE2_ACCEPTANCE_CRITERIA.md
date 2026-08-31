# Phase 2 Acceptance Criteria and Phase 3 Entry Criteria

**Date:** 2026-08-24

Part A lists what Phase 2 had to deliver and whether it did. Part B lists the
exact, checkable conditions that must all be true before any Phase 3
(Credential Provider) work may begin. Part C states explicitly what Phase 2 did
*not* do.

---

## Part A - Phase 2 completion criteria

| # | Criterion | Status | Proof |
|---|---|---|---|
| A1 | Architecture and security review complete | **Met** | [`PHASE2_SECURITY_REVIEW.md`](PHASE2_SECURITY_REVIEW.md) |
| A2 | Credential strategy has a documented GO / CONDITIONAL GO / NO-GO | **Met** | [ADR-0001](adr/0001-windows-account-and-credential-strategy.md) section 10 - CONDITIONAL GO overall, NO-GO for local/MSA |
| A3 | Supported and unsupported account types explicit | **Met** | ADR-0001 section 5.1 matrix |
| A4 | Session 0 camera and process-boundary assumptions resolved **or listed as blockers** | **Met (listed as blockers)** | ADR-0002 section 8, blockers B1/B2 |
| A5 | Secure-preview contradiction resolved | **Met** | ADR-0002 section 5.4 - preview removed, status-only UI |
| A6 | IPC protocol and threat model documented | **Met** | [ADR-0003](adr/0003-ipc-security-protocol.md) sections 5.1-5.7, threat table 5.4 |
| A7 | Enrollment, provisioning, revocation, recovery, uninstall documented | **Met** | [ADR-0004](adr/0004-enrollment-provisioning-and-recovery.md) |
| A8 | All 137 pre-existing Python tests still pass | **Met** | see the PR description for the run |
| A9 | Any newly added tests pass | **Met** | native CTest suite: 70 named protocol tests + 8 named-pipe tests + 1 aggregate + 3 fake-peer entries = **82 CTest entries on Windows**, Debug and Release |
| A10 | Ruff passes | **Met** | `ruff check --no-cache src tests scripts` |
| A11 | mypy passes | **Met** | `mypy --no-incremental src` - 47 source files |
| A12 | Native Debug and Release build and test pass where the toolchain is available | **Met in CI** | No MSVC/CMake on the development machine; GitHub Actions `windows-latest` performs both configurations. See Part D. |
| A13 | GitHub Actions pass, or limitations documented honestly | **Met** | `.github/workflows/ci.yml`, `.github/workflows/codeql.yml`; toolchain gap documented in Part D. `dependency-review` currently neither runs (Dependency graph is off) nor blocks (`continue-on-error`); enabling the repository setting would fix only the first, and both are stated plainly in the workflow and its README. `pip-audit` runs and is enforcing. |
| A14 | No Windows authentication or registry state changed | **Met** | No registry write exists anywhere in the repository; no installer; no `sc`/`regsvr32`/`reg` invocation |
| A15 | No Credential Provider registered | **Met** | No COM interface implemented, no CLSID, no `DllRegisterServer` |
| A16 | No Windows service installed | **Met** | No SCM code, no service binary, no installer |
| A17 | No Windows password accessed or stored | **Met** | No password-handling code exists in Python or native sources |
| A18 | No unsupported authentication mechanism introduced | **Met** | ADR-0001 section 6 - every rejected mechanism listed with reasons |
| A19 | No binaries, biometric data, templates, secrets, credentials, keys, certificates, model weights, or runtime state committed | **Met** | `.gitignore` expanded; verified against the PR diff |
| A20 | Documentation reflects the real implementation state | **Met** | README, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `RESEARCH.md`, `PHASE2_CREDENTIAL_PROVIDER.md`, `ACCEPTANCE_AUDIT.md` all updated |
| A21 | Phase 3 not implemented | **Met** | Part C |

## Part B - Phase 3 entry criteria

**Every criterion in this Part must be true. Any single failure blocks Phase 3.**

The identifiers are **not a contiguous numeric range**: the list is B1, B2, B3,
B4, **B4a**, B5-B14, B15, **B16**, and **B17**. Writing "B1-B15" silently omits
B4a, B16, and B17, so refer to it as *"every Part B entry criterion, including
B4a, B16, and B17"*.
Identifiers are stable - existing ones are never renumbered when a criterion is
added.

### Feasibility gates (must be settled experimentally, in a VM)

| # | Criterion | How it is proved |
|---|---|---|
| **B1** | A third-party Session 0 service can enumerate and open a capture device **before any interactive logon**, using documented APIs. | A written VM experiment report recording what succeeded, what failed, and with which error, under each camera-consent combination. **If this fails, ADR-0002 becomes NO-GO and Phase 3 does not start.** |
| **B2** | Pre-logon end-to-end verification latency and reliability meet a budget **set before measuring**. | Measured p50/p95 on a cold Session 0 service in the same VM, against the pre-agreed budget. |
| **B3** | The key-container question is resolved: either a TPM-backed CNG KSP key is consumable by the `KERB_CERTIFICATE_LOGON` path, or a virtual smart card is required and is confirmed still supported. | A documented answer with a current Microsoft citation, plus a working VM provisioning walkthrough. |
| **B15** | **A password-free, OS-mediated enrollment-authorization mechanism exists and is documented.** It must prove the human at the keyboard holds the Windows identity being enrolled, while returning **no** password, PIN, certificate secret, key, or reusable credential to this project's process - only a pass/fail signal. `CredUIPromptForWindowsCredentials` does **not** qualify: it returns the credential BLOB to the caller and does not validate it (ADR-0004 E5). | A current official Microsoft citation showing the OS performs the check and no credential material reaches the caller, plus a VM demonstration. **If no such mechanism exists, pre-logon enrollment cannot be authorized and Phase 3 does not proceed.** |

### Environment gates

| # | Criterion | How it is proved |
|---|---|---|
| **B4** | An AD domain lab exists: domain controller, KDC certificate, enterprise CA in the NTAuth store, certificate template with smart-card-logon EKU, working autoenrollment, published and reachable CRL/OCSP. | Lab build document plus a successful *system*-smart-card logon in that lab, with no third-party provider involved. |
| **B4a** | **Strong certificate binding is verified against a Full Enforcement domain controller.** Certificates must carry the SID security extension (OID `1.3.6.1.4.1.311.25.2`) or an explicitly strong `altSecurityIdentities` value (`X509IssuerSerialNumber`, `X509SKI`, `X509SHA1PublicKey`). A UPN or other name-based mapping is weak and is denied (ADR-0001 E8). | A successful system-smart-card logon in the lab with the DC in Full Enforcement and **no** `StrongCertificateBindingEnforcement` compatibility setting - that key has been unsupported since 9 September 2025. A weak-mapped certificate must be observed to FAIL with Event ID 39, proving enforcement is genuinely on. |
| **B5** | Every machine used for install/uninstall testing is a disposable VM with snapshot rollback. No physical or primary machine is used, ever. | Written test procedure naming the snapshot policy. |
| **B6** | A rollback and recovery runbook exists and has been rehearsed: Safe Mode removal, second-admin removal, WinRE removal. | Rehearsal record in the lab. |

### Design and scope gates

| # | Criterion | How it is proved |
|---|---|---|
| **B7** | The project owner has explicitly accepted the AD-domain-only scope, and accepted that local Windows accounts and Microsoft accounts are permanently out of scope for Windows sign-in integration. | A recorded decision. This is a product decision, not a technical one, and Phase 3 must not proceed by default. |
| **B8** | ADR-0003 Q1/Q2 answered: how `account_binding` is derived, and how `session_id`/`desktop_binding` are obtained in LogonUI. | Updated ADR-0003 with the answers and a citation or experiment. |
| **B9** | ADR-0004 Q2 answered: whether the credential handle released after an ALLOW needs its own per-use protection rather than being a stored PIN. | Updated ADR-0004. |
| **B10** | A written decision on the native re-implementation of the pipeline: scope, differential-testing plan against Phase 1 as oracle, and model load-time integrity verification. | A design document plus a test plan. |

### Process gates

| # | Criterion | How it is proved |
|---|---|---|
| **B11** | A dedicated security review of the *implementation plan* has been completed by someone with prior Windows credential-provider or LSA-adjacent experience. | Review record with findings and dispositions. |
| **B12** | Phase 2's Python suite, Ruff, mypy, and the native Debug and Release CTest suites are all green on `main`. | CI on the default branch. |
| **B13** | The fallback guarantee is written into the Phase 3 plan as a hard requirement: the password provider is never hidden, the `Exclude` list is never populated, and no policy makes this the sole sign-in method. | Phase 3 plan section. |
| **B14** | The privacy commitment is written into the Phase 3 plan as a hard requirement: no biometric data leaves the machine, no raw frames cross any process boundary, and the tile shows status only with no preview. | Phase 3 plan section. |

### Protocol gates carried from ADR-0003

| # | Criterion | How it is proved |
|---|---|---|
| **B16** | **The verification backend call is genuinely bounded and cancellable, and the service is asynchronous or otherwise interruptible.** Version 1 calls the backend synchronously: the post-verification deadline check refuses a late `Allow`, but nothing can bound or preempt the *call*, so a hung backend holds its worker thread and the concurrency gate until it returns (ADR-0003 sections 5.9 and 5.10). Phase 3 must fix the call, not just the decision. If in-flight cancellation is in scope it is introduced under a **new protocol version**; message type 3 stays reserved in v1 (ADR-0003 section 5.8). | A design document showing: (a) a hard upper bound on the backend call itself, including camera acquisition and inference; (b) cancellation points through the pipeline; (c) an event-loop or equivalent service that can read its transport while a verification runs; (d) a test proving a deliberately hung backend does not hold the worker or the gate past its bound. Plus a protocol version bump if a cancel message is added. |
| **B17** | **The verification path makes no outbound network connections.** Phase 3 specifies the verifier service as having no network access at all (section 3.4 of `docs/PHASE2_SECURITY_REVIEW.md`, ADR-0002 section 5.3). The current dependency set cannot satisfy that: the bundled MediaPipe binary opens a TLS connection to `play.googleapis.com` and uploads usage telemetry on session teardown, upstream provides no supported way to disable it, and the behaviour is documented and intended (`docs/PRIVACY_NETWORK_AUDIT.md`). **This is a design conflict, not a documentation problem.** ADR-0005 must move from *Proposed* to *Accepted* with **Option A** (replace MediaPipe) or **Option B** (transparently build and verify MediaPipe without telemetry) selected **and implemented**. Those are the only two resolutions. The mandatory interim disclosure already applied in Phase 1 - retracting the false offline claims and documenting the actual behaviour - makes the documentation truthful, but it is not a resolution and does **not** clear this criterion. | `scripts/check_network_activity.py` run against the Phase 3 verification path, showing **zero** outbound connections, with `scripts/network_allowlist.json` empty. Plus ADR-0005 recorded as Accepted with the chosen option and its evidence. Neither a firewall rule, a hosts-file entry, nor any other per-machine block counts: the requirement is a property of the software, not of the machine it happens to run on. **Status after Phase 2.5 (2026-08-30): CLEARED.** Option A was implemented: the liveness path drives the same pinned `face_landmarker.task` weights on `ai-edge-litert` through a reimplementation of MediaPipe's published pipeline, and the `mediapipe` dependency is removed. Against the 1.0.1 oracle across 45 synthetic cases it agrees to 0.0136 (blink), 0.0019 (landmarks), 0.0278 (blendshapes) and 0.0030 (head-turn ratio, against a 0.045 threshold), with detection agreeing on all 45. An earlier revision called Option A "contradicted by measurement"; that is withdrawn - the replica it rested on used `warpAffine` with a zero border rather than the published `warpPerspective`/`BORDER_REPLICATE` path, and fed the blendshape model normalized rather than image-denormalized landmarks. `scripts/network_allowlist.json` is now empty and 20 fresh-process FULL-mode runs of `scripts/check_network_activity.py` observed **zero** external endpoints, each with the loopback canary proven, 8-10 successful OS queries, zero failed queries and no expired deadline (`docs/b17/network_silence_20_runs.json`). ADR-0005 is Accepted. Thresholds were not changed and no firewall, hosts-file or per-machine block was used. **Two limitations are recorded rather than waived:** decision equivalence at the configured 0.40/0.20 blink thresholds is *not* demonstrated, because MediaPipe itself emits at most ~0.21 on procedurally drawn faces and a real face is excluded by this project's constraint against capturing biometric data; and the network check is a detector, not a proof of absence - a connection shorter than the poll interval could be missed, and it observes `IP:port`, never payload bytes. See `docs/PHASE2_5_B17_RESEARCH.md`. The criterion itself is unchanged. |

### Standing prohibitions that carry into Phase 3 unchanged

These are **permanent**, and remain in force no matter how many entry criteria
pass. Phase 3 must never: register the provider as the sole sign-in option;
populate the `Exclude` list; filter, disable, or hide the password provider or
Windows Hello; handle a Windows password in any form - including via an API
that returns a credential blob to this process; modify LogonUI, Winlogon, LSA,
Credential Guard, Windows Hello, authentication policies, or account settings
beyond the provider's own additive registration; use undocumented NGC or
Windows Hello internals; weaken domain-controller certificate-binding
enforcement; report a successful Windows authentication based only on a face
match; send biometric data off the machine; or run experiments on a real lock
screen or secure desktop outside a disposable VM.

### What is GATED rather than permanently prohibited

Implementing a Credential Provider, installing a service, serializing a
credential, and accessing the TPM, certificate store, or camera from native
code are **the substance of Phase 3**. They are blocked *today* by the Phase 2
gate, not banned forever. They become permissible only when every criterion
above passes **and** the owner records explicit written approval.

The `repo-hygiene` CI job enforces the current gate. It must not be weakened as
a side effect of a feature PR: relaxing it requires a separate, standalone
"Phase 3 enablement" pull request that changes nothing else, links the owner's
approval and the completed criteria, and states exactly which markers are being
unblocked and why. See CONTRIBUTING.md, "Proposing gated Phase 3 work".

## Part C - Explicitly not done in Phase 2

Every item below is a deliberate exclusion, not an oversight:

- No `ICredentialProvider`, `ICredentialProviderCredential`, or
  `ICredentialProviderCredential2` implementation.
- No COM registration, CLSID, `DllRegisterServer`, `DllGetClassObject`, or
  `.reg` file.
- No credential provider filter.
- No Windows service: no SCM code, no service binary, no installer, no
  `sc`/`New-Service`/`CreateService` call.
- No credential serialization: no `KERB_INTERACTIVE_LOGON`,
  `KERB_CERTIFICATE_LOGON`, `CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE`,
  or any other credential structure constructed anywhere.
- No in-flight cancellation in the IPC protocol. Message type 3 is reserved and
  unassigned; real cancellation needs an asynchronous server and a protocol
  version bump (ADR-0003 section 5.8, criterion B16).
- No enrollment-authorization mechanism, because none has been proven safe
  (criterion B15).
- No TPM, NCrypt, CNG, or certificate-store access.
- No camera access from any native code.
- No registry read or write of any kind.
- No installer, MSI, or deployment package.
- No changes to any Windows authentication, policy, or account setting.
- No Microsoft sample code copied or adapted.
- No experiment on a real lock screen or secure desktop.

## Part D - Toolchain honesty statement

The development machine for this phase has **no MSVC toolchain, no Windows SDK,
and no CMake** installed. This was verified rather than assumed:

- `cmake --version` - not found
- `cl.exe`, `msbuild.exe` - not on `PATH`
- `vswhere.exe` - not present at its standard location
- `C:\Program Files\Microsoft Visual Studio`, `C:\Program Files (x86)\Windows Kits\10\bin` - absent

Per the Phase 2 brief, no Visual Studio components or system-wide dependencies
were installed without explicit approval.

Consequently:

- **No claim is made that the native project was built or tested locally.**
- The generated CMake configuration was reviewed by inspection instead.
- GitHub Actions performs the real native work on a `windows-latest` runner:
  x64 Debug configure/build/test and x64 Release configure/build/test, both via
  CTest. Those runs are the authoritative native result for this phase.

If MSVC and CMake are installed later, `native/README.md` gives the exact local
commands, which are the same ones CI runs.
