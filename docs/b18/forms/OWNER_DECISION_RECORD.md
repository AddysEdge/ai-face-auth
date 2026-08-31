# B18 owner decision record — TEMPLATE

> Fill in, date, and sign **before any capture**. Items marked **blocking** stop
> the whole protocol until answered. Reference:
> [`docs/B18_REAL_INPUT_VALIDATION_PLAN.md`](../../B18_REAL_INPUT_VALIDATION_PLAN.md)
> section 4.
>
> A decision of "no" or "not now" on D1 is a legitimate, complete answer. It
> leaves B18 open and Phase 3 blocked, which is the current state anyway.

**Decision date:** `YYYY-MM-DD`
**Recorded by:** `<role, e.g. repository owner>`
**Plan revision reviewed:** `<commit SHA of the plan being approved>`

---

| # | Decision | Blocking | Answer | Rationale / constraints |
|---|---|---|---|---|
| D1 | Proceed with real-input validation at all? | ✅ | `yes / no / defer` | |
| D2 | Stage 1 (owner-only pilot) only, or Stage 2 (multi-participant)? | ✅ | | Stage 1 alone cannot clear B18 |
| D3 | If Stage 2: participant count, recruitment, relationship to owner | ✅ | | State convenience-sample status plainly |
| D4 | Consent form, withdrawal process, administrator | ✅ | | |
| D5 | Ethical / institutional review required in this jurisdiction or employment context? | ✅ | | Owner must answer; the plan cannot |
| D6a | Storage / access / encryption for **identifying records** (signed consent, contact route, pseudonym mapping) | ✅ | | Must be separate from D6b |
| D6b | Storage / access / encryption for **pseudonymised measurements** | ✅ | | Encryption is a collection-time decision |
| D7a | Retention and destruction for **identifying records**; withdrawal mechanism (held mapping vs participant-held token); does a consent record outlive the data? | ✅ | | |
| D7b | Retention and deletion for **measurements**, and the **actual erasure method** with its residual limitation | ✅ | | Plain deletion is **not** secure erasure - see plan §12.3 |
| D8 | Confirm privacy defaults (plan §11) or record deviations | ✅ | | Includes the Category A / Category B separation |
| D9 | Are raw frames ever permitted on disk? | ✅ | | Plan proposes **no** |
| D10 | Attack media: whose likeness, and disposal plan | ✅ | | Attack media is itself sensitive |
| D11 | Second camera device (required by issue #14) | | | |
| D12 | Target sample size, and therefore strength of claim | | | See plan §6 |
| D13 | Freeze thresholds 0.40 / 0.20; resolve plan §2.1 discrepancy; fix pass criteria | ✅ | | Must be numeric and pre-registered |
| D14 | Is recalibration in scope on failure? Dev/eval split? | | | See plan §10.2 |
| D15 | Who performs the independent security review? | ✅ | | Self-review must be labelled as such |
| D16 | What may be published in Git? | ✅ | | Aggregate-only, or nothing |

---

## Pre-registered pass criteria (D13)

Written **before** capture. Copy into the final report unchanged.

- Acceptable spoof margin below 0.40: `<number>` — i.e. no S1–S3 trial's
  `max(blink_score)` may exceed `<0.40 minus margin>`
- Maximum acceptable FRR: `<number>`, reported with interval
- Expected S4 (video replay) outcome: `accepted — known gap, does not fail B18`
- Consistency requirement across participants and cameras: `<statement>`

## Threshold freeze (D13)

| Parameter | Frozen value | Source of truth |
|---|---|---|
| `blink_score_high` | `0.40` | `src/faceauth/config.py` |
| `blink_score_low` | `0.20` | `src/faceauth/config.py` |
| `enabled_challenges` | `[BLINK]` | `src/faceauth/config.py` |
| `min_face_continuity` | `0.5` | `src/faceauth/config.py` |
| `challenge_timeout_seconds` | `5.0` | `src/faceauth/config.py` |

Threshold semantics confirmed against source, not documentation:
`max(scores) >= 0.40` **and** `min(scores) <= 0.20`, both inclusive.
`docs/THREAT_MODEL.md` §2 was corrected to match and now cites `config.py` as
authoritative; 0.15 survives there only as a labelled historical note.

Confirmed still true at freeze time: `yes / no`  Checked by: `<...>`

## Data-handling decisions (D6a/D6b, D7a/D7b)

| | Category A - identifying records | Category B - measurements |
|---|---|---|
| Storage location | `<D6a>` | `<D6b>` |
| Access control | `<D6a>` | `<D6b>` |
| Encryption | `<D6a>` | `<D6b>` |
| Retention | `<D7a>` | `<D7b>` |
| Destruction method | `<D7a>` | `<D7b>` |

Confirmed A and B do **not** share a directory, archive, or backup: `yes / no`

**Withdrawal mechanism (D7a):** `held mapping / participant-held token`
If participant-held token: participants are told at consent time that losing
the slip means withdrawal is not possible. Confirmed: `yes / no`

**Erasure method (D7b):** `<full-disk encryption + key destruction / encrypted
container / ATA Secure Erase / plain deletion>`
**Residual limitation, stated honestly:** `<e.g. "plain deletion on an SSD does
not guarantee the data is irrecoverable">`

---

**Signature / attestation:** `<...>`

**This record does not clear B18.** B18 is cleared, if at all, only by the
security-review decision in `SECURITY_REVIEW_CHECKLIST.md` against completed
evidence.
