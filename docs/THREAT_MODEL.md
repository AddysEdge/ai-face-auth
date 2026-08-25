# Threat Model

Scope: the Phase 1 standalone demo application in this repository. It does
**not** protect a Windows user account - it never touches LogonUI,
Winlogon, LSA, Credential Guard, or Windows Hello. Its "asset" is access to
its own demo state (a Tkinter window / CLI exit code).

**Two other threat models exist and are separate from this one:**

- The **IPC protocol threat model** for the (unbuilt) provider-to-service
  channel is in
  [`adr/0003-ipc-security-protocol.md`](adr/0003-ipc-security-protocol.md)
  section 5.4 - 18 threats covering endpoint identity, replay, result
  substitution and reuse, TOCTOU, confused deputy, disconnects, service
  restart, concurrency, and denial of service. The `native/` scaffold
  implements and tests those controls, inertly.
- The **system-level threat model** for a real Credential Provider is
  in [`PHASE2_SECURITY_REVIEW.md`](PHASE2_SECURITY_REVIEW.md) and the ADRs. It
  is a superset of this document, and its conclusion is that the local-account
  case is a **NO-GO**.

For every threat: **Attack**, **Mitigation actually implemented**,
**Residual risk / limitation stated plainly**.

## 1. Stolen biometric templates

**Attack:** an attacker with filesystem access reads the on-disk template
file.
**Mitigation:** templates are encrypted at rest. On Windows, via DPAPI
(`DpapiTemplateStore`, `win32crypt.CryptProtectData`/`CryptUnprotectData`) -
decryption is only possible under the same Windows user account, on the
same machine (`docs/RESEARCH.md` section 11). The file itself contains no
plaintext user_id or JSON structure (verified in
`tests/test_storage_dpapi_backend.py::test_dpapi_encrypted_file_is_not_plaintext_json`).
**Residual risk:** DPAPI protects the ciphertext, not the decrypted
in-memory template while the process runs, and not against an attacker who
has already compromised the same Windows user account (see §6). TPM-backed
hardening (binding the key to hardware, not just the account) is designed
but not implemented in Phase 1 - see `docs/RESEARCH.md` section 11 and
"Risks and limitations" below.

## 2. Photo spoofing (printed photograph / phone-screen photo)

**Attack:** an attacker holds up a printed photo or a phone displaying a
photo of the enrolled user.
**This was live-tested against a real spoof attempt, not just reasoned
about, and the result was mixed - reported honestly below rather than
oversold.**

**Blink challenge: holds up.** `decide_blink()` requires the blink
blendshape score to both rise above a high threshold (0.40) and dip below a
low threshold (0.15) within the window. Live-tested against a genuinely
stationary (propped, not hand-held) spoof photo for 10 continuous seconds:
the observed blink_score stayed strictly between 0.168 and 0.382 the entire
time - nowhere near either threshold (`tests/test_liveness_calibration.py::
test_blink_correctly_rejects_a_genuinely_stationary_spoof_photo` pins this
real data). A static image's appearance genuinely does not change the way a
real blink does.

**Head-turn challenge: does NOT reliably hold up, and was found broken by
live testing, not assumed safe.** The same 10-second stationary-photo trial
that blink safely rejected produced a `turn_ratio` swing of +0.123 at one
point - comfortably clearing the 0.045 head-turn threshold - from ordinary
camera/environmental jitter alone, with **no deliberate manipulation at
all** (`tests/test_liveness_calibration.py::
test_head_turn_incorrectly_accepts_the_same_stationary_spoof_photo` pins
this). Earlier live spoof attempts (hand-held phone) were granted access on
both a BLINK and a TURN_HEAD challenge before this was fully diagnosed. The
root cause is structural, not a tunable threshold: a purely-2D-landmark
head-yaw estimate cannot distinguish "a real 3D head rotation" from "any 2D
perturbation of a flat image's apparent position" - there is no depth
information available to an RGB webcam to tell these apart. **Mitigation
taken:** `DEFAULT_ENABLED_CHALLENGES` in `challenge_response.py` was
changed to BLINK-only as a direct result of this finding - head-turn
remains fully implemented and selectable (`LivenessConfig.enabled_
challenges`) for future hardening, but is not offered as a default security
boundary. A secondary mitigation (`min_face_continuity` in
`capture_utils.py`, added after the first spoof success showed severe
detection dropouts from a hand-waved phone) catches gross photo movement
but does not, by itself, close the head-turn gap - which is why the
challenge was disabled by default rather than relying on continuity alone.
**Residual risk, stated plainly:** with BLINK as the only default
challenge, the specific vulnerability above is closed by not exercising the
vulnerable code path, but a more sophisticated printed-photo attack
(e.g. one with cut-out, physically-blinking eye holes) was not tested and
is not claimed to be defeated - no such attack sample was created (see
`docs/RESEARCH.md` "do not create unauthorized biometric datasets").

## 3. Display/phone-screen spoofing

**Attack:** an attacker shows a photo or looping video of the enrolled user
on a phone or monitor. **This is the exact attack live-tested in §2** - a
phone screen showing a static photo was used for all of the real spoof
attempts described there, including the successful ones before the
BLINK-only mitigation. Same mechanism, same finding, same fix: read §2 in
full, it is not duplicated here.
**Residual risk:** a screen playing back a *video* of the user performing
the exact requested action defeats this - see §4. There is no moiré/
screen-reflection detector active by default (the optional passive backend,
disabled by default, targets this - see `docs/RESEARCH.md` section 3).

## 4. Video replay

**Attack:** an attacker plays a pre-recorded video of the legitimate user
blinking/turning their head, timed to the displayed challenge.
**Mitigation:** none, by default, in Phase 1. **This is stated explicitly
and repeatedly (README, RESEARCH.md, this document) rather than implied to
be handled.** A sufficiently sophisticated real-time deepfake or a lucky
pre-recorded clip matching the randomly chosen challenge could pass.
**Residual risk:** this is the single most significant gap between this
system and Windows Hello, which defeats replay structurally using IR depth
information a plain RGB webcam cannot produce. Do not deploy this system
anywhere replay resistance is required.

## 5. Unknown/unenrolled users

**Attack:** anyone attempts authentication without having enrolled.
**Mitigation:** `TemplateStore.load()` raises `TemplateNotFoundError`,
which `AuthenticationService` converts to an explicit `DENIED
(unknown_user)` - never a crash, never a default-allow (see
`tests/test_authentication.py::test_unknown_user_is_denied`).

## 6. Malicious local processes / compromised account

**Attack:** malware running as the same Windows user reads the DPAPI key
material available to that account, or directly calls the enrollment/auth
API to enroll its own face as an authorized user.
**Mitigation:** out of scope for a userland application - DPAPI's guarantee
is bounded by "same user account," not "any process running as that
account is untrusted." This matches DPAPI's documented threat model, not a
gap specific to this app.
**Residual risk:** stated explicitly. A local, already-elevated or
same-account attacker can re-enroll or tamper with this application's own
data. Real defense against this class of attacker requires OS-level
process isolation (the service/secure-desktop boundary designed in
`docs/adr/0002-process-service-and-camera-boundaries.md`), not a userland
demo app - and note that the pre-logon store that design would need is
**weaker** against a SYSTEM/Administrator attacker than Phase 1's user-scope
DPAPI, not stronger (ADR-0002 section 5.5). Pre-logon availability and
per-user protection pull in opposite directions; that trade-off is stated
rather than assumed away.

## 7. Log leakage

**Attack:** an attacker reads `data/logs/faceauth.log` hoping to recover a
face embedding, raw image, password, or other secret.
**Mitigation:** two independent layers (`logging_utils.py`) - (a)
`SecurityLogger.log_event` statically rejects any field whose name matches
a biometric/secret denylist or whose value isn't a JSON primitive, so an
embedding/frame/template cannot be logged even by a future coding mistake;
(b) a handler-level `PrivacyRedactionFilter` redacts any message that looks
like a numpy array repr regardless of how it reached the logger. Both are
covered by `tests/test_logging_utils.py`, including a regression test for
an over-broad filter bug found and fixed during development (see
git history / RESEARCH.md).
**Residual risk:** similarity scores are logged only as coarse buckets
("low"/"medium"/"high"), not raw floats, specifically to avoid this becoming
a side channel for narrowing down a real score via repeated log inspection.

## 8. Configuration tampering

**Attack:** an attacker modifies `config.json` to weaken security (e.g. set
an absurdly low similarity threshold, disable liveness, disable rate
limiting).
**Mitigation:** `config.py` validates every value (ranges, cross-field
constraints) and raises `ConfigurationError` on anything malformed -
`tests/test_config.py`. This is *validation*, not *tamper-detection*: a
config file that is valid-but-weakened (e.g. `require_liveness: false`) is
accepted, because that is a legitimate configuration choice for a
demo/dev environment.
**Residual risk:** stated explicitly - this repo does not sign or
integrity-check its own config file. A real deployment that must resist a
malicious local editor would need to protect the config file itself (e.g.
ACLs, or move sensitive policy into a signed/attested Phase 2 service).

## 9. Threshold manipulation

**Attack:** same as §8, specifically targeting `policy.similarity_threshold`.
**Mitigation:** the default (0.363) is not a guess - it is OpenCV's own
published operating point for the exact SFace checkpoint this repo ships
(`docs/RESEARCH.md` section 10, cross-checked directly against
`docs.opencv.org`'s tutorial). `faceauth-evaluate` supports recalibrating it
from real genuine/impostor score data rather than hand-tuning.
**Residual risk:** the config value is still user-editable, per §8.

## 10. Model replacement

**Attack:** an attacker swaps `models/sface_2021dec.onnx` for a different,
malicious or degraded ONNX file.
**Mitigation:** `scripts/fetch_models.py` verifies every downloaded file's
SHA-256 against `model_registry.py` before accepting it. At runtime, the
embedding model is loaded from a configured path with no further
integrity check - this is a deliberate scope decision for Phase 1 (see
"Risks and limitations").
**Residual risk:** stated explicitly - Phase 1 does not verify model file
integrity at every load, only at download time. A production deployment
should add a load-time hash check.

## 11. Corrupted templates

**Attack (or accident):** disk corruption, a failed write, or tampering
produces an unreadable/invalid template file.
**Mitigation:** `TemplateStore.load()` raises `TemplateCorruptedError` for
undecryptable ciphertext (DPAPI/Fernet failure) or malformed plaintext
(missing fields, wrong vector shape, bad JSON) -
`storage/serialization.py`'s `deserialize_template` validates every field.
`AuthenticationService` treats this identically to any other
security-critical failure: **DENY, fail closed**, never a crash and never a
silent accept (`tests/test_authentication.py::test_corrupted_template_fails_closed`).

## 12. Denial of service

**Attack:** an attacker repeatedly triggers failed authentication attempts
to lock a legitimate user out, or exhausts resources. A second, more
subtle variant of the *opposite* problem was found via live testing: an
attacker repeatedly triggering failed attempts to evade rate limiting
entirely.
**Mitigation:** escalating backoff after `max_consecutive_failures`,
capped at `max_cooldown_seconds` - a deliberate trade-off (a legitimate
user can be locked out for a bounded time by an attacker who fails enough
attempts) rather than an unbounded lockout, matching how consumer
biometric systems typically behave.
**A real gap was found live, not just reasoned about, and fixed.** The CLI
rebuilds its whole pipeline - including a fresh `RateLimiter` - on every
single `faceauth authenticate` process invocation. Live-tested by running
5 consecutive failed CLI attempts, each as its own process: the original
in-memory-only `CooldownRateLimiter` never triggered a cooldown, because
each process started counting from zero. This means five separate shell
invocations provided **no real brute-force protection at all** despite the
component itself working correctly within a single process (proven by its
own passing unit tests, which construct one instance and call it
repeatedly). **Fix:** `PersistentCooldownRateLimiter`
(`rate_limiting/persistent_cooldown_rate_limiter.py`) persists failure
count and cooldown-until to a small JSON state file, keyed to wall-clock
time (`time.time()`, not `time.monotonic()`, so it's meaningful across
restarts) so state survives across separate CLI invocations. This is now
the default (`RateLimitConfig.persistent = True`).
**Residual risk:** the state file itself has no integrity protection
(it's not biometric/secret data, so DPAPI wasn't used) - a local attacker
who can write to `data/rate_limit_state.json` could delete or reset it to
evade the cooldown; this is an availability/DoS mechanism, not the
identity-authentication decision, so this residual risk does not weaken
the authentication fail-closed guarantee. The demo application itself also
has no protection against a local attacker simply killing the process or
camera; this is out of scope for a userland demo.

## 13. Repeated guessing attempts

**Attack:** an attacker with many candidate faces (or many attempts with
their own face) tries to exceed the similarity threshold by chance.
**Mitigation:** the rate limiter (§12) bounds the attempt rate. The
similarity threshold (§9) is calibrated, not arbitrary, and
`faceauth-evaluate` supports measuring the actual FAR at the configured
threshold from real data.
**Residual risk:** with enough unlimited *time* (not attempts-per-minute),
any threshold has a non-zero false-accept rate by definition - this is
inherent to biometric authentication, not a bug, and is why FAR is reported
as a rate, not a guarantee.

## Fail-closed behavior (cross-cutting)

Every security-critical failure mode above - camera failure, model
inference failure, corrupted template, unexpected exception - is caught in
one place (`AuthenticationService.authenticate`'s `try/except`) and
converted into an explicit `DENIED` result plus a rate-limiter failure
record. There is no code path that lets an exception propagate silently in
a way that could be mistaken for "no decision made, so allow." This is
enforced structurally (the method's only two exit shapes are
`AuthResult(DENIED/GRANTED, ...)` or a `RateLimitedError` raised before any
attempt starts) and verified in
`tests/test_authentication.py::test_camera_unavailable_fails_closed` and
`test_no_face_observed_denies_rather_than_crashing`.
