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

## What leaves this machine

Stated plainly, because the project previously claimed it "runs entirely
offline" and that was false.

**No biometric data is transmitted, ever.** No image, video frame, face
embedding, or enrolled template leaves the machine, in any phase. That
commitment is absolute and appears in the never-do list below.

**The process is nevertheless not network-silent.** The bundled MediaPipe
binary opens a TLS connection to `play.googleapis.com` and uploads usage
telemetry - MediaPipe version, platform, solution name, graph name, latency and
invocation counts - when a MediaPipe session is torn down. This is documented,
intended upstream behaviour with **no supported opt-out**; it is not something
this project chose. It predates any dependency bump here and was simply not
noticed.

What the evidence covers, stated precisely: the **MediaPipe telemetry extension
schema** was extracted from the shipped binary and contains no field that could
carry biometric content. The broader assurance that input data is never sent is
[Google's statement](https://github.com/google-ai-edge/mediapipe/issues/6291#issuecomment-4896121772), also in the [MediaPipe Terms of Service](https://developers.google.com/edge/mediapipe/legal/tos) - not something binary inspection can prove. The Clearcut envelope
carrying the extension was **not** decrypted, so any identifiers it may add are
uncharacterised, and nothing here establishes that the telemetry is anonymous.

The full measurement - destination, trigger, exact transmitted schema, retry
behaviour, and the opt-out search - is in
[`docs/PRIVACY_NETWORK_AUDIT.md`](docs/PRIVACY_NETWORK_AUDIT.md). The open
decision about whether to replace MediaPipe, rebuild it without telemetry, or
narrow the offline claim is
[ADR-0005](docs/adr/0005-mediapipe-telemetry-and-the-offline-claim.md).
`python scripts/check_network_activity.py` reproduces the measurement, and CI
fails if any destination outside
[`scripts/network_allowlist.json`](scripts/network_allowlist.json) appears.

**Please do report anything that does not match the audit.** The known,
documented telemetry described above is not currently being treated as a
compromise, so it does not need re-reporting on its own. But an unexpected
payload, an identifier or destination the audit does not describe, any
transmission of biometric data, or any behaviour inconsistent with
`docs/PRIVACY_NETWORK_AUDIT.md` should be reported through the process at the
top of this file. The envelope contents were never fully characterised, so
evidence about them is genuinely useful rather than a duplicate.

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
- Never send biometric data off the machine. This is unconditional, and is
  unaffected by the third-party telemetry described above - that telemetry
  carries no biometric content, and no schema in it is capable of carrying any.
- Never add an outbound network destination without investigating it and
  recording it in `scripts/network_allowlist.json` with its justification.
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
