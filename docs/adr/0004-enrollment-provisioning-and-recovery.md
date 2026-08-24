# ADR-0004: Enrollment, provisioning, revocation, and recovery

- **Status:** Accepted (Phase 2 review).
- **Date:** 2026-08-24
- **Phase:** 2. **Nothing in this ADR is implemented.** No credential is
  provisioned, no certificate or TPM key is created, no service is installed,
  and no Windows account setting is changed.
- **Decision status:** **CONDITIONAL GO**, entirely dependent on ADR-0001
  section 5.2 (AD domain + enterprise PKI). For local and Microsoft accounts
  this ADR is **NO-GO**, because there is nothing to provision.

---

## 1. Context

ADR-0001 selects a smart-card-class certificate credential on AD domain
machines; ADR-0002 puts a verification service in Session 0 and a status-only
tile in LogonUI; ADR-0003 defines the channel between them. What is left is the
lifecycle: who is allowed to enroll a face, how a template becomes associated
with a Windows identity, how the credential is provisioned and renewed, and -
most importantly - how a user gets back into their machine when any of it
fails.

Microsoft's own credential-provider guidance leads with exactly this concern:

> "It's strongly recommended that there always be at least one system
> credential provider available for every user on the device in addition to any
> third-party credential providers."

and, for a local account with no system provider configured, "the user has no
way to recover the account on the machine."

*Source:* `learn.microsoft.com/windows/win32/secauthn/credential-providers-in-windows`

Recovery is therefore the first-class requirement here, not an appendix.

## 2. Requirements

| # | Requirement |
|---|---|
| R1 | Enrolling a face for pre-logon use requires an explicit, authenticated, interactive authorization by that Windows identity. It can never be silent, remote, or automatic. |
| R2 | The password provider (and Windows Hello, where configured) remains enabled and reachable for every affected account, at every point in the lifecycle. |
| R3 | Uninstall must be complete and must leave sign-in in a known-good state. |
| R4 | No biometric data leaves the machine. Ever. |
| R5 | Every failure mode - camera, service, template, certificate, network - resolves to "use another sign-in option", never to a blocked logon screen. |
| R6 | The Phase 1 interactive template is never silently promoted into pre-logon scope. |
| R7 | Deleting an enrollment must actually delete it, promptly and verifiably. |

## 3. Evidence from official sources

Retrieved 2026-08-24.

- **E1 - Recovery is Microsoft's stated concern.** Quoted in section 1. Scenario
  A (local account) has no remote password-reset escape hatch; Scenario B
  (MSA/AD/Entra ID) does.
  *Source:* `learn.microsoft.com/windows/win32/secauthn/credential-providers-in-windows`
- **E2 - Certificate logon requires live PKI validation at sign-in.** The KDC
  "validates the user's certificate (time, path, and revocation status)", and
  for domain sign-in "The smart card sign-in certificate must have the HTTP CRL
  distribution point listed in its certificate" and "The CRL distribution point
  must have a valid CRL published". Revocation is therefore a real, enforced
  control - and equally a real availability dependency.
  *Source:* `learn.microsoft.com/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration`
- **E3 - Account mapping is by UPN in `subjectAltName` or by
  `altSecurityIdentities`.** "Certificate mapping is based on the UPN that is
  contained in the subjectAltName (SAN) field of the certificate. Client
  certificates that don't contain information in the SAN field are also
  supported" via AltSecID.
  *Source:* same page.
- **E4 - Least-privilege service identity.** `NT SERVICE\SvcName` and
  `SERVICE_SID_TYPE_RESTRICTED` (quoted in ADR-0002 E4) give the ACL subject
  used throughout this ADR.
  *Source:* `learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_sid_info`

## 4. Considered alternatives

| # | Question | Alternatives | Decision |
|---|---|---|---|
| A1 | Who may enroll? | (a) any local admin, for anyone; (b) the account holder only, interactively; (c) admin-provisioned remotely | **(b)**, with a local admin able only to *remove* an enrollment, never to create one for someone else. Face data is the user's; an administrator enrolling someone else's face is both a security and a consent problem. |
| A2 | How is enrollment authorized? | (a) trust the interactive session; (b) require a fresh Windows credential prompt; (c) require the certificate PIN | **(b)** - a fresh interactive re-authentication via `CredUIPromptForWindowsCredentials`, so an unattended unlocked desktop cannot be used to add a face. The project never sees the password: the OS prompt validates it. |
| A3 | Template-to-identity association | (a) filename = username; (b) filename = SID; (c) random handle + an ACL-protected mapping | **(c)** - a random opaque handle is what crosses the IPC boundary (ADR-0003 Q1), with the handle-to-SID map held in the same service-SID-ACL'd store. Avoids putting an enumerable identity into the protocol. |
| A4 | Pre-logon template protection | (a) user DPAPI; (b) machine DPAPI; (c) machine DPAPI + entropy + service-SID ACL; (d) TPM-sealed | **(c) now, (d) as the target.** (a) is impossible pre-logon; (b) alone is too weak. See ADR-0002 section 5.5 for the honest statement of the regression. |
| A5 | Credential provisioning | (a) the project mints its own certificate; (b) enrol through the domain's existing PKI | **(b)** exclusively. This project never becomes a CA and never issues anything. |
| A6 | Uninstall order | (a) remove files then unregister; (b) unregister then remove files | **(b)** - unregister the provider first, verify the logon screen still enumerates the password provider, then remove state. Never leave a registered CLSID pointing at a deleted DLL. |

## 5. Decision

### 5.1 Enrollment

**Who.** Only the holder of the Windows identity being enrolled, in an
interactive session, on that machine. Administrators may *revoke* and *remove*
any enrollment on the machine; they may not create one for another user.

**Authorization.** Enrollment starts with a fresh OS credential prompt for the
enrolling identity. The prompt is Windows' own; this project never sees, and
never asks for, the password (R4 of ADR-0001). An unlocked-but-unattended
desktop is therefore not sufficient to add a face.

**Capture.** Reuses Phase 1's enrollment discipline unchanged: multiple
independently-verified samples, quality gating, a liveness challenge per
sample, outlier rejection, raw frames discarded immediately after embedding
extraction (`EnrollmentConfig.retain_raw_frames` defaults false).

**What is stored** in the pre-logon store, per enrollment:

| Field | Notes |
|---|---|
| `handle` | Random 16-byte opaque identifier. This is what appears in `account_binding` on the wire. |
| `sid` | The Windows SID this handle maps to. Never sent over IPC. |
| `centroid` + `sample_embeddings` | Fixed-size float vectors. Never images. |
| `created_at`, `template_version`, `model_id` | So a model change can invalidate templates rather than silently mis-comparing. |

**Protection.** Machine-scope DPAPI + additional entropy + an NTFS ACL granting
read only to `NT SERVICE\FaceAuthVerifier` (E4) and Administrators, in a
directory not writable by standard users. **This is weaker than Phase 1's
user-scope DPAPI**; see ADR-0002 section 5.5. TPM sealing is the intended
replacement.

**Separation from Phase 1 (R6).** The interactive Phase 1 template is never
copied, promoted, migrated, or reused. Pre-logon enrollment is a separate act
with separate consent, and the user is told plainly that they are granting a
pre-logon service the ability to open the camera before anyone signs in.

### 5.2 Credential provisioning

Applies only under ADR-0001 section 5.2 (AD domain + enterprise PKI).

1. The domain's existing PKI issues a client certificate with the smart card
   logon EKU, mapped to the account by UPN in `subjectAltName` or by
   `altSecurityIdentities` (E3). **This project never issues certificates.**
2. The private key lives in a key container the smart-card logon path can
   consume, reachable from LogonUI at logon time. Whether a plain TPM-backed
   CNG KSP key suffices, or whether a virtual smart card is required, is
   **ADR-0001 Q1/Q2 and is unresolved.**
3. Provisioning is an administrative act, separate from face enrollment, and
   subject to the domain's own approval process.
4. A face enrollment without a provisioned credential is inert: the tile is not
   offered. A provisioned credential without a face enrollment is likewise
   inert here - it remains usable through the system smart card provider, which
   this project does not touch.

### 5.3 Renewal

- Certificate renewal follows the domain's normal autoenrollment/renewal
  process. This project neither drives nor interferes with it.
- The provider must detect an expired or not-yet-valid certificate **before**
  offering the tile, and hide the tile rather than fail at submission time.
- Approaching expiry surfaces as a post-logon notification, never as a
  logon-screen prompt.
- Template freshness: re-enrollment is prompted when `model_id` changes or
  after a configurable age. A template captured under a different embedding
  model is rejected, never compared.

### 5.4 Revocation and deletion

| Trigger | Effect |
|---|---|
| User deletes their face enrollment | Template record erased from the pre-logon store; handle-to-SID mapping removed; tile stops being offered. Certificate untouched - it is the domain's, not ours. |
| Administrator revokes an enrollment | Same, and may be applied to any enrollment on the machine. |
| Certificate revoked in the PKI | The KDC rejects it at sign-in (E2). The provider must additionally check locally and stop offering the tile, so the user gets a clear message instead of a failed sign-in. |
| Windows account removed or disabled | Enrollment records for that SID are removed on the next service start and on account-deletion notification. An orphaned template must never be matchable. |
| Uninstall | See section 5.6. |

**Deletion means deletion (R7):** the record is overwritten and removed, not
tombstoned; the store is compacted so a deleted embedding is not recoverable
from slack space; and deletion is verified by a subsequent read returning
"not enrolled".

### 5.5 Failure modes and recovery

Every row resolves to "the user can still sign in" (R5).

| Failure | Behaviour | User sees |
|---|---|---|
| Camera missing, disabled, or in use by another process | Immediate DENY, tile marked unavailable, no retry loop (ADR-0002 5.6) | "Face sign-in unavailable - use another sign-in option" |
| Camera privacy setting blocks access | Same, with a distinct reason code | "Face sign-in is blocked by camera privacy settings" |
| Verification service not running / failed to start | Client cannot connect; tile is not offered at all | The tile simply is not there; password tile is |
| Service crashes mid-request | Client sees disconnect -> DENY (ADR-0003 T15) | "Face sign-in unavailable" |
| IPC timeout | DENY at the deadline; tile released | "Timed out - use another sign-in option" |
| Template missing for this identity | Tile not offered for that user | password tile only |
| Template corrupted | Fail closed, DENY, log a coarse event, mark for re-enrollment | "Face sign-in needs to be set up again" |
| Template from an older model | Rejected without comparison; re-enrollment prompted | as above |
| Certificate expired / revoked / not yet valid | Tile not offered | password tile only |
| KDC or CRL endpoint unreachable | Windows' own smart-card logon fails; not something this project can or should paper over | Windows' own message |
| Liveness repeatedly fails | Rate limiter engages (Phase 1 behaviour, persistent across attempts); tile shows cooldown | "Too many attempts - use another sign-in option" |
| **Anything unanticipated** | DENY | password tile |

**Emergency recovery, in escalating order:**

1. Use the password tile. It is always present (R2). This alone resolves nearly
   every case.
2. Boot to Safe Mode - third-party credential providers are not loaded - and
   uninstall.
3. From another admin account on the machine, uninstall per section 5.6.
4. Domain administrator resets the account credential (Scenario B in E1).
5. Windows Recovery Environment / offline removal of the registration, as a
   documented last resort in the operator runbook.

Because ADR-0001 rules out local accounts entirely, Scenario A's "no way to
recover" case does not arise for this design's supported scope - which is
another reason the local-account NO-GO is the right answer rather than a
disappointment.

### 5.6 Uninstall (R3)

Ordered, and each step verified before the next:

1. Stop and delete the verification service. Confirm the process is gone.
2. Remove the credential provider's registration entries. Confirm removal.
3. **Verify the logon screen still enumerates the password provider before
   proceeding.** This is a hard gate, not a courtesy check.
4. Unregister and remove the DLL.
5. Securely delete the pre-logon template store and the handle-to-SID map.
6. Remove the service's ACL'd directories.
7. Leave alone, explicitly: the user's certificate, the domain's PKI, Windows
   Hello, Credential Guard, LSA settings, account settings, and Phase 1's own
   user-scope data.
8. Emit an uninstall record so an operator can confirm what was removed.

Uninstall must succeed even if the service is already broken, the DLL is
already missing, or the store is already corrupt. A partially-failed uninstall
that leaves a registered CLSID pointing at a deleted DLL is the worst possible
end state and is what step ordering (A6) exists to prevent.

### 5.7 Machine replacement and portability

- Templates are machine-bound by construction (machine-scope DPAPI, and TPM
  sealing later). They **do not** transfer to a new machine, and no export
  path exists (R4).
- A new machine means: provision a certificate through the domain's normal
  process, then enroll a face locally on that machine.
- Decommissioning a machine means running the section 5.6 uninstall before
  disposal; the domain separately revokes the certificate.
- There is no cloud backup, no roaming profile support, and no sync. This is a
  deliberate limitation, not a missing feature.

## 6. Security implications

1. **Enrollment is the real privilege escalation point.** Anyone who can enroll
   a face can sign in as that user. That is why A2 requires a fresh
   authentication rather than trusting an already-unlocked session.
2. **The pre-logon store is a machine-wide biometric store.** A SYSTEM or
   Administrator attacker can read it. Stated plainly in ADR-0002 section 5.5
   and not softened here.
3. **Revocation has two independent halves.** Removing the face enrollment stops
   *this* tile; only PKI revocation stops the *credential*. Confusing the two
   would produce a false sense of having revoked access.
4. **Uninstall is a security control, not housekeeping.** A stale registration
   is a logon-screen liability.
5. **Fallback availability is a security property.** A design that can lock a
   user out has failed even if it never grants a wrong sign-in.

## 7. Deployment limitations

- Whole lifecycle depends on an AD domain and an enterprise PKI. Without them
  there is nothing to provision and this ADR is NO-GO.
- One enrollment per identity per machine; no portability, no backup, no roaming.
- Re-enrollment is required whenever the embedding model changes.
- Certificate renewal and revocation are the domain's responsibility and its
  latency is inherited.
- Uninstall requires administrative rights.
- Every install/uninstall cycle is VM-only until the implementation passes its
  own dedicated security review.

## 8. Unresolved questions

| # | Question | Owner phase |
|---|---|---|
| Q1 | What is the exact provisioning mechanism for the key container - TPM KSP directly, or a virtual smart card? (= ADR-0001 Q1/Q2.) | 3 |
| Q2 | Does the credential handle released after an ALLOW need its own per-use protection (e.g. TPM key-use authorization) rather than being a stored PIN? | 3 |
| Q3 | How is the pre-logon store migrated when the embedding model is upgraded - forced re-enrollment, or dual-template transition? | 3 |
| Q4 | Should pre-logon enrollment require a second factor (e.g. the certificate PIN) in addition to the fresh password prompt in A2? | 3 |
| Q5 | What operator-facing telemetry is needed to detect a machine where the tile is silently never offered? | 3 |

## 9. Status

**CONDITIONAL GO** for AD domain deployments meeting ADR-0001 section 5.2.
**NO-GO** for local and Microsoft accounts - there is no credential to
provision, so there is no lifecycle to manage.
