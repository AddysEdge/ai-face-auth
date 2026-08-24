# Phase 2 Design: Legitimate Windows Credential Provider Integration

> ## SUPERSEDED IN PART - read the Phase 2 review first
>
> This document was written during Phase 1, before the security and
> feasibility review existed. **The review that followed contradicts two of
> its claims and narrows a third substantially.** It is kept because it is
> the historical record of the design that was reviewed, and because the
> review's findings are only meaningful next to what they replaced.
>
> **Read [`PHASE2_SECURITY_REVIEW.md`](PHASE2_SECURITY_REVIEW.md) and the
> ADRs in [`adr/`](adr/) for the current position.** Where they disagree with
> this file, they win.
>
> | Claim below | Current status |
> |---|---|
> | "NGC container gating" is a viable supported pattern | **WITHDRAWN.** No public API lets a third-party provider gate the Windows Hello NGC container. Recorded as unproven and excluded. [ADR-0001 section 6.2](adr/0001-windows-account-and-credential-strategy.md) |
> | The credential provider "shows camera preview/status" | **WITHDRAWN.** A preview contradicts the no-raw-frames IPC rule. The tile is **status-only**. [ADR-0002 section 5.4](adr/0002-process-service-and-camera-boundaries.md) |
> | Certificate logon works for the intended local-machine use case | **NARROWED to NO-GO for local accounts.** Certificate logon is Kerberos PKINIT and requires an AD DS domain, a KDC, and an enterprise PKI. [ADR-0001 section 5](adr/0001-windows-account-and-credential-strategy.md) |
> | The Phase 1 Python pipeline is reused "effectively unchanged" in the service | **NARROWED.** Not recommended as the pre-logon service boundary; a native host is. [ADR-0002 section 5.2](adr/0002-process-service-and-camera-boundaries.md) |
> | Camera availability in Session 0 before logon | **UNPROVEN - open blocker B1.** [ADR-0002 section 8](adr/0002-process-service-and-camera-boundaries.md) |

**Status: design document only. Nothing in this document is implemented.**
Phase 1 (this repository's actual code) is a standalone demo application
that never touches Windows sign-in. This document describes how a *future*
Phase 2 could legitimately integrate with Windows' own supported
authentication architecture, grounded in Microsoft's primary documentation
(`docs/RESEARCH.md` section 22 lists the exact sources). It exists so the
long-term direction is concrete, reviewable, and falsifiable - not so it
gets built without further design/security review first.

## Non-negotiable constraints (repeated from the top-level goal)

Phase 2 must never: bypass Windows authentication; patch LogonUI; disable
Windows Hello; extract or store a user's Windows password; automatically
type a password; bypass LSA; bypass Credential Guard; weaken TPM
protections; inject unsupported code into the lock screen; or replace
Windows' own authorization decision with an insecure workaround. Every
design choice below is filtered through those constraints.

## The central architectural fact

Microsoft's own documentation states it plainly
(`learn.microsoft.com/windows/win32/secauthn/credential-providers-in-windows`):

> "Credential providers are not enforcement mechanisms; they are used to
> gather and serialize credentials, submitting them for authorization."

A credential provider is **not** the trust boundary. LSA and the relevant
authentication package make the actual accept/reject decision. This means
Phase 2 cannot "just say yes" after a face match - it must gate the
release/use of a credential that **Windows itself already knows how to
authenticate**, provisioned through Windows' own supported mechanisms. The
face+liveness check is a *local convenience gate in front of* that
credential, not a replacement trust decision.

## Target flow

```
Windows LogonUI  (secure desktop, SYSTEM, loads our COM credential provider DLL)
      |
Custom Credential Provider (ICredentialProvider / ICredentialProviderCredential2)
      |  IPC (named pipe, strict SDDL ACL) - see "process boundaries" below
      v
Local Authentication Service (Session 0 Windows service, no desktop, least privilege)
      |
Face + Liveness Verification  (this repo's Phase 1 pipeline, reused as-is)
      |  on success, authorizes use of -
      v
Protected, device-bound credential (TPM-backed key/certificate, provisioned
      |  through Windows' own supported enrollment - not invented by us)
      v
Windows authentication (LSA / authentication package - Windows' own decision)
```

## Credential Provider API (the supported integration surface)

- `ICredentialProvider` and `ICredentialProviderCredential` are the core
  COM interfaces; `ICredentialProviderCredential2` is the recommended V2
  surface for a modern implementation
  (`learn.microsoft.com/windows/win32/api/credentialprovider/nn-credentialprovider-icredentialprovidercredential`).
- Microsoft ships a full reference implementation in
  `microsoft/Windows-classic-samples` (`Samples/Win7Samples/security/credentialproviders`)
  - any real Phase 2 implementation should start from and diff against that
  sample, not be written from scratch against the header files alone.
- Implementation language: **C++**. The provider is a COM in-process DLL
  registered under a CLSID (`HKLM\SOFTWARE\Classes\CLSID\{provider-GUID}`)
  and listed under
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{provider-GUID}`.
  This registration is **additive** - it adds a new tile/option to the
  logon screen, it does not replace or remove the built-in password
  provider.
- A `.NET`-hosted credential provider is possible (via COM interop -
  `syfuhs.net` documents this pattern) but is generally discouraged for a
  component this security-sensitive because of the extra runtime
  dependency loaded into LogonUI's process; a native C++ DLL with a minimal
  surface is the safer default.

## Process/service boundaries (why the ML pipeline does NOT run inside LogonUI)

LogonUI.exe runs on Winlogon's isolated **secure desktop**, as SYSTEM,
before any user session exists. It is one of the most security-sensitive
processes in Windows. Loading a large ML stack (OpenCV, ONNX Runtime,
MediaPipe, their transitive native dependencies) directly into that process
would substantially and unacceptably increase its attack surface.

The correct shape, consistent with how Windows Hello's own architecture
separates biometric capture/matching from LogonUI:

- The **credential provider DLL** stays thin: it renders the tile, shows
  ~~camera preview/status~~ **status only - no preview, no frames, no images
  (superseded by [ADR-0002 section 5.4](adr/0002-process-service-and-camera-boundaries.md))**,
  and talks to a separate service over IPC. It contains no ML inference code
  itself.
- The **face+liveness pipeline** (this repo's Phase 1 code, effectively
  unchanged) runs inside a **Windows service** running in Session 0, under
  a dedicated least-privilege service account - not SYSTEM, not the
  interactive user (who doesn't have a session yet at this point in logon).
- **IPC** between the credential provider (running in LogonUI's process,
  on the secure desktop) and the service uses a named pipe with an explicit
  SDDL ACL restricting connection to the specific service account and
  SYSTEM - never a world-writable pipe, never unauthenticated. The message
  contract is minimal: "start a challenge for enrolled user X" /
  "verified: yes/no" - the service never sends raw frames or embeddings
  back to the credential provider, and the credential provider never sends
  anything resembling a password.
- This mirrors the general principle behind Credential Guard's own design
  (isolate the sensitive secret-handling logic from the broader OS/session)
  without touching or weakening Credential Guard itself - Phase 2 does not
  modify, disable, or interact with Credential Guard's LSA isolation.

## The device-bound credential (what actually gets authenticated)

Two supported patterns, both keeping "the thing Windows actually verifies"
entirely inside Windows' own mechanisms:

1. **Certificate-based logon (PKINIT / smart-card-class logon).** A private
   key is generated inside the TPM via CNG's Microsoft Platform Crypto
   Provider (`NCryptOpenStorageProvider` with `MS_PLATFORM_CRYPTO_PROVIDER`,
   `NCryptCreatePersistedKey` -
   `learn.microsoft.com/windows/win32/seccertenroll/cng-key-storage-providers`),
   the private key never leaves the TPM, and a certificate is provisioned
   against it through Windows' own supported enrollment (mirroring how a
   virtual smart card or Windows Hello for Business certificate-trust
   deployment works). Our credential provider's job, after a successful
   face+liveness check, is to authorize *use* of that already-provisioned
   key for the logon - Windows' own PKINIT/smart-card logon path does the
   actual authentication.
2. ~~**NGC container gating.**~~ **WITHDRAWN by the Phase 2 review - see
   [ADR-0001 section 6.2](adr/0001-windows-account-and-credential-strategy.md).**
   The original text below claimed a Phase 2 provider "could, in principle,
   sit in front of the same class of container using the same supported
   provisioning APIs Windows Hello uses". No such public API surface exists.
   The nearest one, `Windows.Security.Credentials.KeyCredentialManager`, is
   documented as operating "for the current user and application" - it needs a
   signed-in user, it is app-scoped, and it returns nothing `LsaLogonUser`
   consumes. Implementing this would require undocumented NGC internals, which
   this project forbids. Recorded as **unproven** and excluded from the
   decision.

   > *Original text, retained for the record:* Windows Hello for Business
   > already stores a device-bound key/PIN container (NGC) that Windows itself
   > trusts; its own credential provider's entire job is to gate *use* of that
   > container behind a biometric/PIN check. A Phase 2 provider could, in
   > principle, sit in front of the same class of container using the same
   > supported provisioning APIs Windows Hello uses - not a bespoke mechanism
   > we invent.

In both patterns, **we never see, extract, store, or transmit the user's
Windows account password.** The face+liveness check only ever gates access
to a credential Windows already knows how to verify.

## Fallback, recovery, and lockout avoidance

- The built-in password credential provider (and Windows Hello, if
  configured) **must remain enabled at all times**. Phase 2's provider is
  registered as an *additional* tile, never as an exclusion of existing
  providers (Microsoft's provider registration supports an `Exclude` list
  for deliberately hiding other providers - Phase 2 must never populate
  it).
- If the local authentication service fails to start, times out, or the
  IPC channel is unavailable, the credential provider tile must fail
  visibly and immediately fall back to letting the user pick another tile
  (password) - never retry indefinitely, never block the logon screen.
- Installation/uninstallation must be tested on a non-production machine
  (ideally a VM with snapshot rollback) before ever being considered for a
  real machine, given a broken credential provider can affect the entire
  logon experience. Uninstall must cleanly unregister the COM DLL and
  remove its registry entries, leaving password/Windows Hello logon
  untouched.
- No policy change should ever make Phase 2's provider the *sole*
  authentication method for an account.

## What Phase 2 explicitly does not do

It does not patch or hook LogonUI's binary or process. It does not read,
derive, or cache the Windows account password anywhere, ever. It does not
touch Credential Guard's isolated LSA process. It does not weaken or bypass
TPM sealing/attestation - it *uses* the TPM through the same supported
CNG/NCrypt surface any other Windows credential mechanism uses. It does not
introduce a new, Windows-unaware trust decision - the only thing it ever
does is gate access to a credential Windows itself already trusts.

## Before any Phase 2 implementation work begins

This design should go through a dedicated security review (ideally by
someone with prior Windows credential-provider or LSA-adjacent development
experience) before a single line of the C++ provider or service is
written, and should be prototyped first against a disposable VM, never a
primary machine.

## What actually happened next

That review was carried out and is
[`PHASE2_SECURITY_REVIEW.md`](PHASE2_SECURITY_REVIEW.md). Its headline result:

> **CONDITIONAL GO overall.** The originally intended use case - face unlock
> for a **local** Windows account on a personal machine - is a **NO-GO**. The
> only surviving route to a real Credential Provider is certificate /
> smart-card-class logon for **Active Directory domain accounts**, inside a
> deployment that already has a domain controller and an enterprise PKI.

| Account type | Result |
|---|---|
| Local Windows account | **NO-GO** |
| Microsoft account (MSA) | **NO-GO** |
| Active Directory domain account | **CONDITIONAL GO** |
| Microsoft Entra ID account | **DEFERRED - unproven** |

Two blockers remain unproven and must be settled in a VM before any provider
code is written: whether a third-party Session 0 service can open a camera
before interactive logon (**B1**), and whether pre-logon latency and
reliability are acceptable (**B2**). If B1 cannot be cleared with documented
APIs, the architecture becomes a NO-GO outright.

Full detail, with primary sources:

- [ADR-0001 - Windows account and credential strategy](adr/0001-windows-account-and-credential-strategy.md)
- [ADR-0002 - Process, service, and camera boundaries](adr/0002-process-service-and-camera-boundaries.md)
- [ADR-0003 - IPC security protocol](adr/0003-ipc-security-protocol.md)
- [ADR-0004 - Enrollment, provisioning, and recovery](adr/0004-enrollment-provisioning-and-recovery.md)
- [Phase 3 entry criteria](PHASE2_ACCEPTANCE_CRITERIA.md)
