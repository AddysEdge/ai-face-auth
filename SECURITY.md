# Security Policy

## Read this first

**Do not open a public GitHub issue for a security vulnerability, and never
attach biometric data to anything you send us.**

This is a **research prototype** for face authentication. It is not a product,
it has not been through a professional security audit, and it must not be used
to protect anything real. See [Known limitations](#known-limitations) below -
several are serious, and all of them are documented deliberately rather than
minimised.

## Reporting a vulnerability

Please report privately, through either channel:

1. **GitHub private vulnerability reporting** (preferred) -
   [open a draft advisory](https://github.com/AddysEdge/ai-face-auth/security/advisories/new).
   This keeps the report invisible to the public until it is resolved.
2. **Email** the repository owner via the address on the
   [AddysEdge GitHub profile](https://github.com/AddysEdge). Put
   `SECURITY` in the subject line.

Please include:

- what you found, and which file or component it affects;
- how to reproduce it, with the smallest possible input;
- the impact you believe it has;
- your environment (Windows version, Python version, commit SHA).

**Please do not include:**

- face images, video, embeddings, or biometric templates - yours or anyone
  else's. If a reproduction seems to need one, describe the *shape* of the
  input (dimensions, dtype, how it was produced) and we will generate our own;
- Windows passwords, PINs, private keys, certificates, or registry exports;
- personal data belonging to anyone who did not consent to sharing it.

If a report accidentally contains any of the above, say so and we will delete
it and ask for a redacted version.

### What to expect

This is a personal research project maintained in spare time, so please treat
these as intentions rather than a service-level agreement:

| Stage | Target |
|---|---|
| Acknowledgement | within 5 working days |
| Initial assessment | within 14 days |
| Fix or documented mitigation | depends on severity; you will be kept informed |
| Public disclosure | coordinated with you, after a fix or a documented decision not to fix |

You will be credited in the advisory unless you prefer otherwise. There is no
bug bounty.

### Safe harbour

Testing against **your own** installation, on **your own** machine or VM, using
**your own** face, is welcome and will never be treated as hostile. Please do
not test against anyone else's machine, do not use anyone else's biometric data
without their informed consent, and do not access data that is not yours.

## Scope

**In scope**

- The Python pipeline under `src/faceauth/` - enrollment, authentication,
  liveness, template storage, rate limiting, logging.
- The native IPC scaffold under `native/`.
- Anything in the repository that leaks biometric data, weakens the fail-closed
  guarantee, or bypasses the liveness or rate-limiting controls.
- Documentation that materially misstates what the system does or how strong it
  is. A security claim we cannot support is a security bug in this repository,
  and we would rather hear about it.

**Out of scope**

- The known limitations listed below. They are documented, not hidden - a
  report that restates one is not a finding, though a report showing a
  limitation is *worse* than documented very much is.
- Attacks that require an attacker who already has Administrator or SYSTEM on
  the machine, or who is already signed in as the target user. Phase 1's
  protection is bounded by DPAPI's own threat model
  (`docs/THREAT_MODEL.md` section 6).
- Vulnerabilities in third-party dependencies, unless this project uses them in
  a way that makes the impact materially worse. Report those upstream; tell us
  too if we need to pin around it.
- Anything about a Windows Credential Provider. **There is no Credential
  Provider in this repository.** Nothing here registers one, installs a service,
  or touches Windows sign-in. See `docs/PHASE2_SECURITY_REVIEW.md`.

## Known limitations

These are real, they are stated everywhere they are relevant, and none of them
is a secret:

- **This is not Windows Hello and is not Windows Hello-equivalent.** Windows
  Hello face authentication requires a certified near-IR sensor and meets a
  documented FAR < 0.001% / TAR > 95% bar. This project uses an ordinary RGB
  webcam and has not been tested against, and does not claim, that bar.
- **Video replay defeats the liveness check.** A recording of the enrolled user
  performing the requested challenge can pass. There is no mitigation in
  Phase 1 (`docs/THREAT_MODEL.md` section 4).
- **Head-turn liveness was found spoofable by a stationary photo** during live
  testing and is therefore disabled by default. The finding, its numbers, and
  the root cause are in `docs/THREAT_MODEL.md` section 2.
- **The configuration file is validated, not integrity-protected.** A local
  attacker who can edit it can weaken the policy
  (`docs/THREAT_MODEL.md` section 8).
- **Model files are hash-verified at download time, not at load time**
  (`docs/THREAT_MODEL.md` section 10).
- **The rate-limit state file has no integrity protection**
  (`docs/THREAT_MODEL.md` section 12).
- **No Windows sign-in integration exists.** The Phase 2 review concluded that
  the local-account use case is a **NO-GO** under this project's constraints.
  See `docs/PHASE2_SECURITY_REVIEW.md`.
- **There is no proven safe way to authorize a pre-logon enrollment.** This is
  an open blocker (B15), not a solved problem. An earlier design claimed
  `CredUIPromptForWindowsCredentials` could re-authenticate a user without
  exposing credential material; that claim was wrong and has been withdrawn.

## What this project will never do

These are permanent commitments, not current limitations, and they hold in
every phase:

- Never request, read, derive, store, serialize, transmit, or automatically
  type a Windows account password. **This includes calling any API that returns
  a credential blob to this process** - see
  `docs/adr/0004-enrollment-provisioning-and-recovery.md` E5 for a specific
  claim that was withdrawn on exactly this ground.
- Never register itself as the sole sign-in option, populate a credential
  provider `Exclude` list, filter providers, or disable or hide the password
  provider or Windows Hello.
- Never modify LogonUI, Winlogon, LSA, Credential Guard, Windows Hello,
  Windows authentication policies, or account settings.
- Never bypass Windows' own authorization decision.
- Never use undocumented NGC or Windows Hello internals.
- Never report a successful Windows authentication on the basis of a face match
  alone.
- Never send biometric data off the machine.
- Never weaken domain-controller certificate-binding enforcement (for example
  via `StrongCertificateBindingEnforcement`) to make a weak certificate mapping
  work.

A pull request that does any of these will be rejected regardless of how well
it works.

### What is *gated*, as distinct from prohibited

Implementing a Credential Provider, installing a Windows service, serializing a
credential, and touching the TPM, certificate store, or camera from native code
are **not** on the list above. They are the substance of a future Phase 3, and
they are blocked **today** by the Phase 2 gate rather than banned forever.

They become permissible only when every entry criterion in
`docs/PHASE2_ACCEPTANCE_CRITERIA.md` Part B passes **and** the repository owner
records explicit written approval. Until then a PR containing them will be
closed. See CONTRIBUTING.md, "Proposing gated Phase 3 work".

## Supported versions

The project is pre-1.0 and only the default branch (`main`) is supported.
Security fixes land there; there are no backports.
