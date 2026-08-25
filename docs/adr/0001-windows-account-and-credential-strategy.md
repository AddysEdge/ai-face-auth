# ADR-0001: Windows account and credential strategy

- **Status:** Accepted (Phase 2 review). Supersedes the credential section of
  `docs/PHASE2_CREDENTIAL_PROVIDER.md`.
- **Date:** 2026-08-24
- **Phase:** 2 (security and feasibility foundation). **Nothing in this ADR is
  implemented.** No Credential Provider is registered; no Windows
  authentication state is touched.
- **Decision status:** **CONDITIONAL GO overall**, decomposed per account type:
  - **NO-GO** - local Windows accounts (the originally intended product goal)
  - **NO-GO** - Microsoft accounts (MSA)
  - **CONDITIONAL GO** - Active Directory domain accounts
  - **DEFERRED (unproven)** - Microsoft Entra ID accounts

---

## 1. Context

Phase 1 is a standalone Python application that decides "is this the enrolled
face?" and prints a result. It has no relationship to Windows sign-in.

The stated long-term goal is a legitimate Windows Credential Provider that
offers face authentication as an *additional* sign-in option. The project's
own non-negotiable constraints forbid ever requesting, reading, deriving,
storing, serializing, transmitting, or auto-typing a Windows password, and
forbid inventing a trust decision that Windows does not itself make.

Those two constraints together turn the whole feasibility question into one
concrete question:

> **After a successful local face+liveness check, what exact
> Windows-recognized credential does the provider hand to LSA?**

`docs/PHASE2_CREDENTIAL_PROVIDER.md` (Phase 1 era) answered this with two
candidate patterns - certificate/PKINIT logon, and "NGC container gating" -
and marked both as design-only. This ADR resolves them against current
official Microsoft documentation and reaches a materially narrower answer
than that document implied.

## 2. Requirements

| # | Requirement |
|---|---|
| R1 | The credential submitted must be one Windows already knows how to authenticate. No invented trust decision. |
| R2 | No Windows account password is ever requested, read, derived, stored, serialized, transmitted, or auto-typed. |
| R3 | Every claimed integration path must be backed by current official Microsoft documentation. Unproven paths are labelled unproven. |
| R4 | Built-in system credential providers (password, and Windows Hello where configured) remain enabled and reachable at all times. |
| R5 | The provider is additive only. The `Exclude`/filter mechanism is never used to hide other providers. |
| R6 | Deployment restrictions must be stated at the front of the conclusion, not buried. |
| R7 | The face+liveness check may only *gate* a credential. It may never *be* the credential. |

## 3. Evidence from official sources

All quotes below are verbatim from the cited Microsoft Learn pages, retrieved
2026-08-24.

### E1 - A credential provider is not the trust boundary

> "It's important to note that credential providers are not enforcement
> mechanisms. They are used to gather and serialize credentials, submitting
> them for authorization. The local authority and authentication packages will
> handle and any necessary security enforcement."

> "By combining credential providers with supported hardware, you can extend
> Windows to support logging on with biometric information, passwords, PINs,
> Smart Card certificates, or any custom authentication package you choose to
> create."

*Source:* `learn.microsoft.com/windows/win32/secauthn/credential-providers-in-windows`

**Reading.** The enumerated credential kinds are the constraint. A provider
does not get to define a new one; it must produce something an existing
authentication package accepts. "Or any custom authentication package you
choose to create" points at the SSP/AP route, addressed in section 6.3 and
rejected there.

### E2 - The same page requires a working system credential provider per user

> "It's strongly recommended that there always be at least one system
> credential provider available for every user on the device in addition to
> any third-party credential providers."

Its Scenario A (local account) and Scenario B (MSA / AD / Entra ID) both
describe a user permanently locked out of the machine when a third-party
provider breaks and no system provider is configured. Scenario B notes that
for MSA/AD/Entra ID accounts the user "can remotely request/reset the password
and use that to log into the machine"; **Scenario A offers no such recovery for
a local account** - "If not, the user has no way to recover the account on the
machine."

*Source:* same page.

**Reading.** This is a first-party Microsoft statement that directly supports
requirements R4/R5, and it makes the local-account case the *most* fragile,
not the least. See ADR-0004 for how this shapes recovery.

### E3 - Certificate logon is a Kerberos/PKINIT domain flow

The documented smart-card sign-in flow is: the credential provider packages
the data "in a `KERB_CERTIFICATE_LOGON` structure" -> `LogonUI.exe` sends it to
`Lsass.exe` -> "LSA calls the Kerberos authentication package (Kerberos SSP) to
create a Kerberos authentication service request (KRB_AS_REQ), which
containing a preauthenticator (as specified in RFC 4556: Public Key
Cryptography for Initial Authentication in Kerberos (PKINIT))" -> "The Kerberos
SSP sends an authentication request for a ticket-granting-ticket (TGT) (per RFC
4556) to the Key Distribution Center (KDC) service that runs on a domain
controller" -> "The KDC finds the user's account object in Active Directory
Domain Services (AD DS)".

*Source:* `learn.microsoft.com/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration`

The structure reference confirms the domain dependency at the API level. For
`KERB_CERTIFICATE_LOGON.DomainName`:

> "If the value is not empty, LsaLogonUser uses the value to locate the Key
> Distribution Center (KDC). If the value is empty, LsaLogonUser attempts to
> authenticate against the domain to which the computer is joined."

*Source:* `learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon`

**Reading - this is the load-bearing finding of the whole review.** Certificate
logon is not "logon with a certificate"; it is *Kerberos PKINIT against a
KDC*. Every path through it terminates at a domain controller holding an AD DS
account object. No documented variant authenticates a **local** SAM account
with a certificate. The same page's requirements list (KDC certificate, HTTP
CRL distribution point on both the KDC root and the sign-in certificate,
NTAuth store trust, certificate-to-account mapping) describes an enterprise PKI
deployment, not a single-machine feature. Note that this page's UPN-mapping
guidance is **superseded for enforcement purposes** by KB5014754 - see E8.

### E4 - Windows Hello face is a Microsoft component, not a third-party extension point

> "Microsoft face authentication in Windows 11 is an enterprise-grade identity
> verification mechanism that's integrated into the Windows Biometric Framework
> (WBF) as a core Microsoft Windows component called Windows Hello."

The page then describes the four-stage recognition engine ("Windows 11
Algorithm - Less than 0.001% or 1/100,000 FAR") as Microsoft's own, with the
OEM supplying a certified near-IR *sensor*.

*Source:* `learn.microsoft.com/windows-hardware/design/device-experiences/windows-hello-face-authentication`

*Bar:* `learn.microsoft.com/windows-hardware/design/device-experiences/windows-hello-biometric-requirements`
("Facial feature recognition requirements - FAR < 0.001%. TAR > 95%.")

**Reading.** The third-party extension point in Windows Hello face is the
camera, not the matcher. This project supplies a matcher and an ordinary RGB
camera - the opposite of the supported shape, and below the documented bar.

### E5 - No documented public API lets a third party gate the NGC container for Windows sign-in

The closest public surface,
`Windows.Security.Credentials.KeyCredentialManager`, is scoped per-user *and
per-application*: `DeleteAsync` "Deletes a previously provisioned user identity
key **for the current user and application**", `OpenAsync` "Retrieves a key
credential **for the current user and application**", `IsSupportedAsync`
"Determines if the current device and user is capable of provisioning a key
credential."

*Source:* `learn.microsoft.com/uwp/api/windows.security.credentials.keycredentialmanager`

**Reading.** This API produces an application-scoped assertion for a
*signed-in* user. It requires a user context that does not exist before
logon, and it returns nothing that `LsaLogonUser` consumes. No Microsoft
documentation was found describing any supported way for a third-party
credential provider to unlock, gate, or borrow the Windows Hello NGC
container. **Per requirement R3, the NGC path is recorded as UNPROVEN and is
not part of the decision.**

### E6 - Windows Hello for Business needs a directory identity

Every documented WHfB deployment model (cloud-only, hybrid key trust, hybrid
certificate trust, hybrid cloud Kerberos trust, on-premises key/certificate
trust) is defined in terms of Microsoft Entra ID and/or Active Directory, with
device registration against a directory. No deployment model is documented for
a purely local Windows account.

*Source:* `learn.microsoft.com/windows/security/identity-protection/hello-for-business/deploy/`

### E7 - A custom LSA authentication package cannot be loaded under LSA protection

Registering a custom SSP/AP means writing the DLL name into
`HKLM\System\CurrentControlSet\Control\Lsa\Security Packages`, after which
"Each time the system starts, the LSA loads the SSP/AP DLLs in this list."

*Source:* `learn.microsoft.com/windows/win32/secauthn/registering-ssp-ap-dlls`

But:

> "Protected mode requires any plug-in that's loaded into the LSA to be
> digitally signed with a Microsoft signature. Any plug-ins that are unsigned
> or aren't signed with a Microsoft signature fail to load in LSA."

and LSA protection "is enabled by default" on new Windows 11 22H2+ installs
that are enterprise-joined and HVCI-capable.

*Source:* `learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection`

### E8 - Certificate-to-account mapping must be STRONG, and UPN mapping is not

KB5014754 changed what domain controllers accept. It divides
`altSecurityIdentities` mappings into strong and weak:

| Mapping | Example | Strength |
|---|---|---|
| `X509IssuerSerialNumber` | `X509:<I>IssuerName<SR>SerialNumber` | **Strong** |
| `X509SKI` | `X509:<SKI>123456789abcdef` | **Strong** |
| `X509SHA1PublicKey` | `X509:<SHA1-PUKEY>123456789abcdef` | **Strong** |
| `X509IssuerSubject` | `X509:<I>IssuerName<S>SubjectName` | **Weak** |
| `X509SubjectOnly` | `X509:<S>SubjectName` | **Weak** |
| `X509RFC822` | `X509:<RFC822>user@contoso.com` | **Weak** |

Separately, a certificate may carry the SID security extension, OID
**`1.3.6.1.4.1.311.25.2`**, which lets the KDC confirm that "the certificate
SID matches the account SID". That is the preferred strong binding.

The timeline matters:

- **11 February 2025** - domain controllers moved to **Full Enforcement**.
- **9 September 2025** - the `StrongCertificateBindingEnforcement` registry
  key became **unsupported**; rollback to Compatibility mode is no longer
  available.

Under Full Enforcement, if "a certificate cannot be strongly mapped,
authentication will be denied" (Event ID 39).

*Source:* `support.microsoft.com/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16`

**Reading, and a correction.** An earlier revision of this ADR listed "UPN in
`subjectAltName`, or via `altSecurityIdentities`" as sufficient. **That is
wrong under current enforcement**: UPN/name-based mapping is exactly the weak
class that Full Enforcement rejects, and the compatibility escape hatch no
longer exists. A deployment must issue certificates carrying the SID extension,
or configure an explicitly strong `altSecurityIdentities` value. Weakening
domain-controller enforcement to make a name mapping work is **not** an
option this project will propose.

## 4. Considered alternatives

| # | Alternative | Verdict |
|---|---|---|
| A1 | Password replay - store the Windows password, release it after a face match | **Rejected outright.** Violates R2 unconditionally. Not evaluated further. |
| A2 | Certificate / smart-card-class logon (`KERB_CERTIFICATE_LOGON`, PKINIT) | **Selected, conditionally, for AD domain accounts only.** |
| A3 | Gate the Windows Hello NGC container | **Rejected as unproven.** See E5. |
| A4 | Custom LSA authentication package (SSP/AP) accepting a face assertion | **Rejected.** See E7 and section 6.3. |
| A5 | Third-party WBF engine adapter supplying face matching to Windows Hello | **Rejected as unproven and out of scope.** See E4 and section 6.4. |
| A6 | Wrap/subclass the system password provider | **Rejected.** Microsoft explicitly discourages it: "This isn't recommended because it can lead to problematic behavior... causing a poor user experience or even preventing the user from accessing their device." It would also place this code adjacent to the password (R2). |
| A7 | Do nothing at the Windows layer - keep face auth as an application-level control | **Retained as the honest fallback for local accounts.** See section 5.3. |

## 5. Decision

### 5.1 Account-type matrix

| Windows account type | Decision | Windows-recognized credential | Why |
|---|---|---|---|
| **Local Windows account** (SAM) | **NO-GO** | none available under R2 | Certificate logon terminates at a KDC/AD DS (E3) - unavailable. WHfB has no local-account deployment model (E6). NGC gating unproven (E5). That leaves only `MSV1_0` interactive password logon, forbidden by R2. |
| **Microsoft account (MSA)** | **NO-GO** | none available under R2 | An MSA signs in locally through a linked local profile using the password/PIN path. Same exclusion as above; no documented third-party credential surface. |
| **Active Directory domain account** | **CONDITIONAL GO** | `KERB_CERTIFICATE_LOGON` (smart-card-class / PKINIT) | Fully documented (E3), but only inside a deployment that satisfies section 5.2. |
| **Microsoft Entra ID account** | **DEFERRED - unproven** | unknown | Entra-joined sign-in is documented via WHfB / Web Account Manager. No documented third-party credential-provider surface producing an Entra-recognized credential was found. Not claimed either way. |

### 5.2 Conditions attached to the Active Directory CONDITIONAL GO

The AD path is a GO **only** where every one of the following holds. If any
one fails, the AD path is a NO-GO for that deployment.

1. The machine is joined to an AD DS domain with a reachable KDC at sign-in time.
2. An enterprise PKI (e.g. AD CS) issues client certificates carrying the smart
   card logon EKU, or the "Allow certificates with no extended key usage
   certificate attribute" policy is deliberately configured.
3. Domain controllers hold a valid KDC / Domain Controller Authentication /
   Kerberos Authentication certificate.
4. The issuing CA is present in the `NTAuth` store.
5. Certificates carry a **strong** binding to the account: either the SID
   security extension (OID `1.3.6.1.4.1.311.25.2`), or an explicitly strong
   `altSecurityIdentities` value - `X509IssuerSerialNumber`, `X509SKI`, or
   `X509SHA1PublicKey`. **A UPN or other name-based mapping is weak and is
   rejected under Full Enforcement** (E8). Disabling or weakening
   domain-controller enforcement to work around this is not permitted.
6. CRL distribution points (and, where used, OCSP responders) are published,
   reachable **before** interactive logon, and valid - the documentation calls
   out HTTP CRL DPs on both the KDC root certificate and the sign-in
   certificate as a hard requirement for domain sign-in.
7. A certificate enrolment, renewal, and revocation process exists (ADR-0004).
8. The private key lives in a key container the smart-card logon path can
   consume, reachable from LogonUI at logon time (see Q1/Q2).
9. Sign-in is verified against a domain controller in **Full Enforcement**
   mode, with no `StrongCertificateBindingEnforcement` compatibility setting in
   play - that key has been unsupported since 9 September 2025 (E8).
10. A rollback-capable VM lab exists for every install/uninstall test.
11. The built-in password provider stays enabled for every affected account
    (E2, R4).

### 5.3 Consequence for the original product goal - stated plainly

The originally intended use case - **face unlock for a local Windows account on
a single personal machine** - is a **NO-GO** under this project's own
constraints. There is no documented, publicly supported Windows credential
mechanism that lets a third-party credential provider authenticate a *local*
account without handling that account's password.

This is not a gap in effort or research. It is the direct consequence of two
first-party documented facts: certificate logon is a Kerberos PKINIT flow that
requires a KDC (E3), and Windows Hello's own device-bound credential has no
third-party gating API (E5). The honest options for the local-account case are
therefore:

- **A7** - keep face authentication as an application-level control (what
  Phase 1 already is), and do not integrate with Windows sign-in; or
- change the product scope to domain-joined machines (section 5.2); or
- wait for, and re-verify against, a future documented Microsoft surface.

**This project selects A7 for local accounts and records the AD path as the
only conditional route to a real Credential Provider.** Anything else would be
a workaround, which the Phase 2 brief explicitly forbids.

### 5.4 What the face check is, precisely

Under section 5.2 the face+liveness check is a **local convenience gate that
releases a pre-provisioned certificate credential's PIN/handle to the
smart-card logon path.** It is never the authentication decision. LSA and the
Kerberos SSP make that decision, against a KDC, using a certificate the domain
already trusts.

Stated as a risk rather than a feature: the strength of the whole arrangement
is bounded by whichever is weaker - the face match, or the local protection of
the credential handle the face match releases. See section 7.

## 6. Rejected approaches, with reasons

### 6.1 Password replay (A1)

Storing or auto-typing the Windows password would make the face match the sole
real authentication decision while pretending Windows made it. Forbidden by
R2 and by the project brief. Not designed, not prototyped, not scaffolded.

### 6.2 NGC / Windows Hello container gating (A3)

`docs/PHASE2_CREDENTIAL_PROVIDER.md` said a Phase 2 provider "could, in
principle, sit in front of the same class of container using the same
supported provisioning APIs Windows Hello uses." **That claim is withdrawn.**
No such public API surface was found (E5). `KeyCredentialManager` is
per-user/per-application, needs an interactive user, and yields nothing
`LsaLogonUser` accepts. Any implementation would require undocumented NGC
internals, which the brief forbids.

### 6.3 Custom LSA authentication package (A4)

Technically documented (E7), and technically what E1 alludes to. Rejected for
three independent reasons, any one of which is sufficient:

1. It requires writing to `HKLM\...\Control\Lsa\Security Packages` - an
   explicitly prohibited action in this project.
2. Under LSA protection - on by default for new Windows 11 22H2+ enterprise
   installs - an unsigned or non-Microsoft-signed plug-in **fails to load**.
   A Microsoft LSA file-signing signature is not available to this project.
3. Even if signed, it would place this project's code inside LSASS, the exact
   process the whole design is meant to stay outside of.

### 6.4 Third-party WBF face engine adapter (A5)

The Windows Biometric Framework does define third-party engine adapters
(`WINBIO_ENGINE_INTERFACE`) and a `FacialFeatures` capability in
`WINBIO_EXTENDED_ENGINE_INFO`. But Windows Hello face is documented as "a core
Microsoft Windows component" with Microsoft's own recognition engine (E4), the
third-party contribution being a certified near-IR sensor. No Microsoft
documentation was found stating that a third-party face engine adapter can
supply Windows Hello sign-in. This route would also mean shipping a biometric
*driver*, far outside Phase 2's safe scope. **Recorded as unproven; not
pursued.**

### 6.5 Wrapping a system credential provider (A6)

Rejected on Microsoft's own advice (quoted in section 4), and because a wrapper
around the password provider sits directly adjacent to the password.

## 7. Security implications

1. **The trust boundary does not move.** Under section 5.2, LSA/Kerberos/the
   KDC keep making the decision. The provider's only new power is deciding
   *when* to present an already-trusted credential.
2. **The face gate inherits the weakest link.** Whatever local secret the face
   match releases (a PIN, a key-use authorization) becomes the real target. An
   attacker who extracts it skips the camera entirely. Mitigations belong to
   ADR-0004 (protection at rest) and ADR-0002 (process isolation); the
   residual risk is real and stays documented.
3. **RGB liveness remains materially weaker than the Windows Hello bar.**
   FAR < 0.001% / TAR > 95% with a certified IR sensor (E4) is not a bar this
   pipeline has met or been tested against. Nothing in this ADR changes that,
   and no wording anywhere in this repository may imply Windows
   Hello-equivalence.
4. **Adding a tile adds logon-surface risk.** A third-party provider that
   misbehaves degrades the logon experience for every user on the machine -
   hence R4/R5 and the VM-only rule.
5. **Certificate logon centralises risk in the PKI.** A mis-issued or
   mis-mapped certificate is a domain-wide authentication problem, not a local
   one.

## 8. Deployment limitations (do not summarise these away)

- Requires an AD DS domain, a reachable KDC, and enterprise PKI. Not usable on
  a standalone home machine.
- Requires pre-logon network reachability for the KDC and CRL/OCSP endpoints.
- Requires a certificate lifecycle: enrolment, renewal, revocation, and
  machine-replacement handling (ADR-0004).
- Requires certificates with a **strong** account binding (SID extension or a
  strong `altSecurityIdentities` form). Existing UPN-mapped certificates are
  not usable under Full Enforcement, so an established PKI may need template
  and re-issuance work before this is possible at all (E8).
- Does not work for local accounts, Microsoft accounts, or - as far as this
  review can support - Entra ID accounts.
- Never becomes the sole sign-in method; the password provider stays enabled.
- Every install/uninstall cycle is VM-only until the actual implementation
  passes a separate, dedicated security review.

## 9. Unresolved questions

| # | Question | Why it matters | Owner phase |
|---|---|---|---|
| Q1 | Can a TPM-backed CNG KSP key (Microsoft Platform Crypto Provider), *without* a virtual smart card, be consumed by the `KERB_CERTIFICATE_LOGON` / `KERB_SMARTCARD_CSP_INFO` path? | Determines whether a TPM virtual smart card is mandatory. Not claimed either way here. | 3 |
| Q2 | Are TPM virtual smart cards still a supported provisioning route on current Windows, or superseded by WHfB? | Affects the whole provisioning design in ADR-0004. | 3 |
| Q3 | Is there any supported Entra ID credential surface for a third-party provider? | Would move Entra ID out of DEFERRED. | 3 |
| Q4 | What exactly must `GetSerialization` return for a smart-card-class credential authored by a third party, as opposed to the system smart card provider? | Implementation detail; requires the Microsoft sample plus VM testing. | 3 |
| Q5 | Does releasing a stored PIN behind a biometric gate meet the deploying organisation's own authentication policy? | Organisational, not technical; must be asked before any pilot. | 3 |
| Q6 | Can the deployment's existing PKI issue the SID security extension, and does its CA/template configuration support it without re-issuing every certificate? | Determines how much PKI work the AD path actually costs (E8). | 3 |

## 10. Status

**CONDITIONAL GO**, with the account-type matrix in section 5.1 as the
operative result and section 5.3 as the plain-language consequence: the
local-account product goal is a NO-GO, and Phase 1's application-level scope
remains the honest answer for that case.

Phase 3 entry criteria derived from this ADR are listed in
`docs/PHASE2_ACCEPTANCE_CRITERIA.md`.
