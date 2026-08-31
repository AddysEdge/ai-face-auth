# B18 — real-input liveness validation: proposed protocol

> **This document is a proposal awaiting owner decision. It is not authorization,
> and it does not clear B18.**
>
> **B18 remains OPEN.** No capture may begin until the owner has recorded an
> explicit decision on every item in [section 4](#4-decisions-that-require-owner-approval).
> Publishing this plan changes nothing about the gate: a protocol is not evidence.
> Phase 3 remains blocked.

- **Criterion:** `docs/PHASE2_ACCEPTANCE_CRITERIA.md`, B18
- **Tracking:** [issue #14](https://github.com/AddysEdge/ai-face-auth/issues/14)
- **Status:** proposed, unapproved, not started
- **Scope of this document:** what would have to be decided, then done, then
  measured, then reviewed. Nothing here has been executed.

---

## 1. What this document is, and is not

**It is** a validation protocol precise enough to be argued with before anyone
points a camera at anyone: participant scope, trial design, metrics, thresholds,
statistics, privacy defaults, and the evidence that would close B18.

**It is not:**

- authorization to capture anything;
- a claim that B18 is closed, or close to closed;
- a data-collection tool — no camera integration, recording software, or attack
  media is built by this document, and none should be built before section 4 is
  settled;
- a substitute for the human security review B18(h) requires.

If this plan is followed end to end and the results are good, B18 *may* be
cleared by a recorded owner decision. If the results are bad, the correct
outcome is that B18 stays open and the liveness configuration changes — not that
the criteria move.

---

## 2. What is actually being validated

The protocol must test shipping behaviour, not an idealisation of it. As
configured today (`src/faceauth/config.py`, `LivenessConfig`):

| Parameter | Value | Meaning |
|---|---|---|
| `enabled_challenges` | `[BLINK]` | Head-turn is implemented but **not** a default security boundary |
| `blink_score_high` | **0.40** | Score must reach **at or above** this (`>=`, inclusive) |
| `blink_score_low` | **0.20** | Score must *also* reach **at or below** this (`<=`, inclusive) |
| `head_turn_min_swing` | 0.045 | Only if head-turn is explicitly enabled |
| `challenge_timeout_seconds` | 5.0 | Wall-clock window the human has |
| `max_frames_per_challenge` | 300 | Runaway-loop backstop, not the real bound |
| `min_face_continuity` | 0.5 | Fraction of frames needing exactly one detected face, else reject |

The decision is `decide_blink()` in
`src/faceauth/liveness/challenge_response.py`:

```python
passed = max(blink_scores) >= high and min(blink_scores) <= low
```

where `blink_score` is the mean of the `eyeBlinkLeft` and `eyeBlinkRight`
blendshapes.

**Test the whole attempt, not just this function.** A frame only reaches
`observe()` after the detector finds exactly one face and the quality checker
passes it, and a result that passes `decide_blink` is still overturned if face
continuity is below `min_face_continuity`
(`capture_utils.run_liveness_challenge`). FAR and FRR must therefore be defined
on the **attempt outcome**, not on the blink decision alone (section 9).

### 2.1 Threshold semantics — reconciled

Both comparisons are **inclusive**, verified against the shipping code rather
than read off a document: a window whose maximum is exactly 0.40 and whose
minimum is exactly 0.20 **passes**; 0.399 or 0.201 does not.

`docs/THREAT_MODEL.md` §2 previously described the low threshold as 0.15 and
used "rise above" / "dip below". It has been corrected in this branch to state
**at or above 0.40** and **at or below 0.20**, and to name `config.py` as
authoritative. The 0.15 value is retained there only as an explicitly labelled
historical note about the trial conditions at the time.

That correction also changed a substantive claim, not just a number. Under
`blink_score_low = 0.15` the stationary-photo trial failed *both* conditions,
which is what "nowhere near either threshold" described. At 0.20 it satisfies
the low condition, so rejection rests on the high threshold alone — see §3.1.

---

## 3. What is already known — and why it is not enough

Prior live testing exists. It is pinned as real data in
`tests/test_liveness_calibration.py` and described in `docs/THREAT_MODEL.md` §2.
It is **one person, one camera, one setup, a handful of trials**, and it is the
reason B18 exists rather than a substitute for it.

| Trial | Observation |
|---|---|
| Genuine deliberate blinks | Peaks 0.489, 0.597, 0.671, 0.722, 0.747 — clear 0.40 by a wide margin |
| Genuine open-eye baseline | Commonly 0.20–0.30; dips near 0.15 only occasionally |
| **Static propped photo, 10 s** | blink score stayed within **0.168 – 0.382** |
| Static propped photo, head-turn | `turn_ratio` spiked to **+0.123**, clearing the 0.045 swing threshold on jitter alone — this is why head-turn is disabled by default |

### 3.1 The single most important number in this plan

For that stationary-photo trial:

- `min(scores) = 0.168`, and `0.168 <= 0.20` → **the low condition was satisfied by the photo**;
- `max(scores) = 0.382`, and `0.382 >= 0.40` is false by **0.018** → only the high condition rejected it.

So in the shipping configuration, **the entire measured spoof resistance of the
default challenge rests on one threshold, with an observed margin of 0.018,
from a single trial.** Raising `blink_score_low` from 0.15 to 0.20 was justified
for usability and does not weaken the *decision* — `high` is decisive either way
— but it did mean that in this particular trial the photo went from failing both
conditions to failing only one.

That is not a claim the control is broken. It is a statement that the margin has
never been characterised, and that a 0.018 gap measured once is not a basis for
a security claim. **Characterising the distribution of per-trial
`max(blink_score)` for spoofs, across conditions, is the highest-value
measurement in this protocol** — higher than counting pass/fail, because a rate
of zero tells you nothing about how close you were.

---

## 4. Decisions that require owner approval

**No capture may begin until every item below has a recorded decision.** Use
`docs/b18/forms/OWNER_DECISION_RECORD.md`. Items marked **blocking** stop
the whole protocol; the rest stop the stage they belong to.

| # | Decision | Blocking | Notes |
|---|---|---|---|
| **D1** | Does real-input validation proceed at all, in this repository, at this time? | ✅ | A legitimate answer is "no — B18 stays open indefinitely and Phase 3 is not pursued." |
| **D2** | Participants: owner-only pilot (Stage 1) only, or consenting multi-participant (Stage 2)? | ✅ | Stage 1 alone **cannot** clear B18 (section 5). |
| **D3** | If Stage 2: how many participants, recruited how, and with what relationship to the owner? | ✅ | Colleagues/family are convenience samples; this must be stated in the report, not hidden. |
| **D4** | Consent: approve the form, the withdrawal process, and who administers it. | ✅ | Section 12. |
| **D5** | Is any ethical/institutional review required in the owner's jurisdiction or employment context? | ✅ | The owner must answer this; this document cannot. |
| **D6a** | Storage location, access control and encryption for **identifying records** — signed consent forms, contact route, pseudonym mapping. | ✅ | §11.2. Must be **separate** from D6b. |
| **D6b** | Storage location, access control and encryption for **pseudonymised measurements**. | ✅ | §11.2. Encryption is a collection-time decision (§12.3). |
| **D7a** | Retention and destruction for **identifying records**; which withdrawal mechanism (held mapping vs participant-held token); whether a consent record outlives the data it governs. | ✅ | §11.2, §12.2. |
| **D7b** | Retention and deletion for **measurements**, and the **actual erasure method** used, with its residual limitation recorded honestly. | ✅ | §12.3 — plain deletion is not secure erasure. |
| **D8** | Confirm the privacy defaults in section 11, or record deviations with reasons. | ✅ | Especially "no raw frames, ever", and the Category A / Category B separation. |
| **D9** | Are raw frames *ever* permitted to touch disk? Default proposal: **no**. | ✅ | If yes, D6b/D7b become far more demanding and the risk statement in 11.5 changes materially. |
| **D10** | Attack media: who appears in the printed photo / replay video, and what happens to that media afterwards? | ✅ | Attack media is a photograph of a person — it is itself sensitive. |
| **D11** | Second camera device: which one, and is it owned/borrowed/returned? | | Required by issue #14. |
| **D12** | Target sample size and therefore the strength of claim being attempted (section 6). | | Determines what the report may conclude. |
| **D13** | Threshold-freeze: confirm 0.40 / 0.20 are frozen pre-capture, and resolve the §2.1 discrepancy. | ✅ | Section 10. |
| **D14** | If results fail: is recalibration in scope, and if so on a separate development set only? | | Section 10.2. |
| **D15** | Who performs the independent security review (B18(h))? Can it be someone other than the person who ran the trials? | ✅ | Section 15. |
| **D16** | What is published: aggregate-only report in Git, or nothing in Git? | ✅ | Section 11.3. |

---

## 5. Staged plan

### Stage 0 — dry run, no human subjects, no camera

Purpose: prove the harness and the analysis work before anyone is recorded.

- Drive the pipeline with the existing synthetic corpus and with pre-recorded
  *synthetic* sequences only.
- Verify the manifest schema, the analysis script, the metric definitions, and
  the deletion procedure end to end.
- Rehearse the session checklist against an empty room.

**Requires no D-decisions except D1.** Clears nothing; it de-risks Stage 1 so
that a participant's time is not wasted on a broken harness.

### Stage 1 — owner-only operational pilot

Purpose: confirm the replacement runtime behaves sanely on real input at all,
and shake out the protocol.

- Single participant (the owner), consenting to their own data.
- Full condition matrix at reduced trial counts.

**Stage 1 cannot clear B18, and its results must never be reported as if it
could.** With n=1 there is no population, no between-subject variance, and no
independence: every trial shares one face, one pair of eyes, one blink habit,
one skin tone, one interpupillary distance, one pair of glasses or none. It can
demonstrate *gross* failure (e.g. genuine blinks no longer reach 0.40 at all,
which would be a regression) and it can produce a first estimate of the spoof
margin from §3.1. It cannot support any statement of the form "this works for
users."

### Stage 2 — consenting multi-participant validation

The only stage capable of producing B18 evidence. Requires D2–D5, D10, D11.

---

## 6. Sample size — what each size can and cannot support

No number here is chosen for convenience, and none is proposed as "the" answer;
D12 is the owner's decision. What follows is what each choice would license —
and, more importantly, what it would not.

### 6.1 What the arithmetic actually gives you

For a rate estimated from `n` **trials** with zero observed events, the 95 %
upper bound is approximately **3/n** (the "rule of three"):

| Trials with zero failures | 95 % upper bound |
|---|---|
| 20 | ≈ 14 % |
| 30 | ≈ 10 % |
| 60 | ≈ 5 % |
| 100 | ≈ 3 % |
| 300 | ≈ 1 % |

**Read that table narrowly.** It describes *the trials that were run*. Three
limits apply to every number produced this way, and they must travel with the
number wherever it is quoted:

1. **"Zero failures" is not "zero rate."** A clean run of 30 spoof trials is
   consistent with a true rate as high as 10 % *for those conditions*.
2. **Trials within one participant are not independent observations of people.**
   Twenty blinks from one person is closer to one observation of a person than
   to twenty observations of people, and the same holds for twenty presentations
   of one printed photo. A binomial interval computed over pooled trials
   therefore **understates uncertainty about people and attacks**, sometimes by a
   large factor. It is not a population bound and must never be presented as one.
3. **The participants are not a random sample of anyone.** Whatever is measured
   here describes the people who volunteered, the attacks that were built, the
   room they were in, and the two cameras used.

Accordingly, every rate this protocol produces is **descriptive and conditional
on the sampled trials, participants, attacks and conditions** — not a population
guarantee, not a certification, and not a security rate that can be quoted
without its denominator and its sampling limits.

### 6.2 Proposed shape, for the owner to accept or change

Trial-level bounds below are **descriptive only**, and are stated together with
the participant count that actually limits them.

| Stage | Participants | Genuine trials | Spoof trials | What it can support |
|---|---|---|---|---|
| 1 | 1 (owner) | ~40 | ~40 | Detects gross regression; produces a first margin estimate. **No claim about people at all** — one face, one blink habit. |
| 2a | ≥ 5 | ≥ 20 each (≥ 100) | ≥ 20 each (≥ 100) | Small convenience-sample **characterisation**. Trial-level zero-event bound ≈ 3 %, **but over only 5 non-randomly-chosen people, so it bounds nothing about a population.** |
| 2b | ≥ 10 | ≥ 30 each (≥ 300) | ≥ 30 each (≥ 300) | Larger convenience-sample **characterisation**, with more between-subject spread visible. Trial-level zero-event bound ≈ 1 %, **again over 10 non-randomly-chosen people; this is not evidence of generalisation.** |

**No stage in this table certifies the control, and none of them establishes
that it generalises.** Even 2b is a small, non-random, unblinded, single-site
study run by the system's own author, against attacks that same author built.
Ten participants is enough to *see variation between people*; it is not enough
to *characterise a population*, and the report must not imply otherwise. That
limitation belongs in the report's headline, not a footnote.

What the stages are genuinely for: detecting that the control is broken,
measuring the spoof margin (§6.3), and exposing between-participant variation
that a single-subject test cannot show.

### 6.3 The margin matters more than the rate

Because spoof rejection currently hinges on `max(blink_score)` failing to reach
0.40, with an observed margin of 0.018 from a single trial (§3.1), the protocol
treats **`max(blink_score)` per spoof trial as the primary outcome**, reported
as a distribution rather than a pass/fail count.

This is deliberate: a margin is far less sensitive to sample size than a rate
is. Ten spoof trials whose maxima cluster at 0.38 are far more alarming than a
hundred that sit at 0.15 — and both report FAR = 0. A distribution of near-miss
values says something useful even at small *n*, where a rate does not.

---

## 7. Trial design

### 7.1 Conditions

Every genuine and spoof cell should be attempted across this matrix. Cells the
owner drops must be recorded as dropped, not silently omitted.

| Factor | Levels (minimum) |
|---|---|
| Lighting | bright even; dim; strong side-light; backlit |
| Head pose | frontal; ±15° yaw; ±10° pitch |
| Distance | ~40 cm; ~70 cm; ~100 cm |
| Eyewear | none; clear glasses; (optional) tinted |
| Camera | **≥ 2 physically different devices** (issue #14) — e.g. the development webcam and one other |

### 7.2 Trial types

**Genuine — should pass:**
- G1 deliberate single blink within the window
- G2 natural blinking, no instruction
- G3 blink near the window boundary (first second / last second)

**Genuine non-blink — should fail (these are *correct* rejections, not FRR):**
- N1 eyes held open for the whole window
- N2 slow deliberate eye *narrowing* without a full blink
- N3 looking away / downward without blinking

**Spoof — must fail:**
- S1 printed photograph, propped and stationary
- S2 printed photograph, hand-held (natural hand tremor)
- S3 phone/tablet displaying a still photo
- S4 **display replay of video of the enrolled user genuinely blinking** — the
  known limitation in `docs/THREAT_MODEL.md` §4. This is expected to *succeed as
  an attack*; the protocol measures it to quantify a known gap, not to
  discover it.
- S5 printed photo with eye-holes cut / photo of a blinking sequence flipped by
  hand, if the owner considers it in scope

### 7.3 Procedure

- **Warm-up:** ≥ 3 unrecorded practice attempts per participant per camera, so
  the first recorded trial is not measuring unfamiliarity with the UI.
- **Randomised order:** trial type and condition randomised per participant from
  a seed recorded in the manifest. Not grouped by type — grouping lets a
  participant learn "this block is the spoof block."
- **Rest:** brief pause between trials; eye fatigue changes blink behaviour.
- **Invalid trials** — excluded, with reason recorded, and counted in the report:
  - no face detected for the whole window (hardware/framing failure);
  - participant reported they missed the prompt;
  - operator error (wrong condition set up);
  - software error or exception.
  Invalid trials are **excluded from numerators and denominators alike** and
  reported separately as an exclusion count. A protocol that quietly drops
  inconvenient trials produces meaningless rates.
- **Retries:** an invalid trial may be re-run **once** under the same condition;
  a second invalidation ends that cell and is recorded as such. Retries are
  never used to convert a *valid* failure into a pass.

### 7.4 Ground truth, labelled independently of the model

The label "the participant actually blinked" must not come from the system under
test. Proposed procedure:

- The operator records the intended trial type **before** the attempt, from the
  randomised schedule.
- The participant self-reports afterwards ("did you blink?"), recorded
  independently.
- Disagreement between intended type and self-report marks the trial
  **ambiguous** and excludes it, with the disagreement recorded.
- The model's output is **not consulted** when labelling. Whoever assigns ground
  truth should not see the score first.

For spoof trials, ground truth is definitional (a photo is not alive), so only
the condition and the media used need recording.

---

## 8. What gets recorded

Per trial, the minimum sufficient for analysis and nothing more:

- pseudonymous participant ID and session ID (section 11.2);
- trial index, randomisation seed, intended trial type, condition levels;
- camera device label (model/interface, not serial number);
- **the full per-frame `blink_score` series** for the window — required, because
  §6.3 needs distributions and §10 needs the ability to re-evaluate at a
  different threshold without re-capturing people;
- derived `max(blink_score)`, `min(blink_score)`;
- `turn_ratio` series only if head-turn is being evaluated (off by default);
- frames captured, frames with exactly one face, face-continuity ratio;
- the attempt outcome and reason string;
- independent ground-truth label and self-report;
- validity flag and exclusion reason;
- software/config provenance (section 11.4).

**Raw frames and video are not recorded** under the proposed defaults (D9).

---

## 9. Metrics

### 9.1 Definitions

Defined on the **attempt outcome** (post-continuity, as the product behaves),
over **valid** trials only:

- **FRR (false reject rate)** = genuine-blink trials (G*) that the attempt
  rejected ÷ valid G* trials.
- **FAR (false accept rate)** = spoof trials (S*) that the attempt accepted ÷
  valid S* trials.
- **Correct-rejection rate** for genuine non-blink trials (N*) is reported
  separately. **N* failures are not FRR** — rejecting someone who did not blink
  is the control working.

FAR must be reported **per attack type**. Pooling S1–S4 into one number hides
the thing that matters: S4 (video replay) is expected to succeed, and averaging
it with printed-photo trials manufactures a misleadingly moderate figure.

### 9.2 Denominators and exclusions

Every reported rate states: numerator, denominator, number excluded, and why.
Exclusion counts appear next to the rate, never only in an appendix.

### 9.3 Intervals — descriptive, and labelled as such

- Wilson score 95 % intervals for proportions (better than the normal
  approximation at small *n* and at rates near 0).
- Where zero events are observed, report the one-sided 95 % upper bound
  explicitly (§6.1) instead of "0 %".
- For `max(blink_score)` distributions: n, min, median, max, and the count
  within 0.05 of the 0.40 threshold. **Report the observed maximum explicitly**
  — it is the near-miss that matters.

**Every interval in this protocol is a trial-level, descriptive interval.** It
summarises the attempts that were actually run. It is **not** a population
bound, because trials are clustered within a small number of non-randomly
chosen participants and attacks (§6.1). Any interval quoted in the report must
be accompanied, in the same sentence or table row, by the participant count it
rests on. A trial-level bound presented without that count is a misleading
number and must not appear.

Phrases that must not be used for these figures: "the FAR is", "guarantees",
"certified", "at most X% of users", or any bare rate without its denominator
and participant count.

### 9.4 Per-participant before aggregate — the participant is the unit

**Per-participant results are primary.** Report a per-participant table first —
each participant's own FRR and FAR with counts — before any aggregate.

Aggregates over pooled trials are secondary and descriptive. If per-participant
rates vary noticeably, the aggregate is not a meaningful summary and the report
must say so rather than leading with it. Where a statement about people is
attempted at all, the number of *participants* is the sample size, not the
number of trials.

---

## 10. Threshold discipline

### 10.1 Freeze before capture

`blink_score_high = 0.40` and `blink_score_low = 0.20` — and the success
criteria in section 14 — are **frozen before the first recorded trial**, in the
owner decision record (D13), together with the resolution of §2.1.

**Thresholds must not be tuned on the final evaluation set.** Choosing a
threshold after seeing the evaluation results and then reporting performance at
that threshold is circular: it reports how well the numbers fit themselves.

### 10.2 If recalibration becomes necessary

If Stage 2 shows the current thresholds are wrong, recalibration is legitimate —
under D14, and only with a **split**:

- a **development set** (separate participants, or a pre-declared participant
  subset held out from the start) used to choose new values;
- a **held-out evaluation set** never examined during tuning, used once to
  report final performance.

If the evaluation set has already been looked at, it is no longer held out, and
the honest options are: collect new evaluation data, or report the tuned
threshold as *uncalibrated* and leave B18 open. Re-running the evaluation set at
successive thresholds until one passes is not calibration; it is fitting the
test.

---

## 11. Proposed privacy-preserving defaults

**Proposals, not decisions.** Each requires D6a/D6b, D7a/D7b, D8, D9, D16.

### 11.1 Collection

- Frames are processed **in memory only**; no raw frame or video is written to
  disk, in any stage, by default (D9).
- Only the derived measurements in section 8 are persisted.
- **No network access during capture or analysis.** The runtime is already
  network-silent (B17); the analysis environment should also be run offline, and
  `scripts/check_network_activity.py` can be run before a session as a
  precondition check.

### 11.2 Two categories of record, kept apart

This protocol produces **two** kinds of record, and conflating them is the
mistake to avoid. A signed consent form is not pseudonymous data — it is a
signature, which is a direct identifier, and it necessarily exists.

| | **Category A — identifying records** | **Category B — pseudonymised measurements** |
|---|---|---|
| Contents | Signed consent forms, signatures, contact route for withdrawal, and the pseudonym→person mapping if one is kept | Trial manifests: score series, outcomes, conditions, `P01` / `S01` only |
| Identifies a person? | **Yes, directly** | Not directly; still person-linked (§11.5) |
| Storage | Separate approved location and access control (**D6a**) | Separate approved location and access control (**D6b**) |
| Retention | **D7a** — tied to the consent/withdrawal obligation | **D7b** — tied to the analysis |
| In Git? | **Never, under any circumstances** | Never; only a verified aggregate report, under D16 |

**The two must not be stored in the same directory, the same archive, or the
same backup.** Category A is what makes withdrawal possible; Category B is what
the analysis consumes. Keeping them together would put a signature next to a
biometric-derived measurement series and defeat the point of pseudonymising the
manifest at all.

- Participants are identified in Category B by an opaque pseudonymous ID
  (`P01`) and session ID (`S01`), and by nothing else.
- **Prohibited in any Category B dataset, filename, or report:** names,
  initials, signatures, email addresses, account or user IDs, dates of birth,
  device serial numbers, photographs, and free text that could identify someone.
- **Prohibited in the repository, always:** completed consent forms,
  signatures, contact details, and any pseudonym→person mapping. `docs/b18/`
  holds blank forms only.

#### Withdrawal without putting identity in the manifest

Withdrawal requires locating one participant's Category B data from their
identity, without that identity ever appearing in Category B. Two approved
options; the owner picks one under D7a:

- **Option 1 — held mapping.** A pseudonym→person mapping is kept in Category A
  storage. Withdrawal is a lookup. Simple and reliable; the cost is that an
  identifying mapping exists for as long as the mapping is retained.
- **Option 2 — participant-held token.** No mapping is kept anywhere. Each
  participant is handed their own `P__` on a slip at consent time and told that
  quoting it is the only way to withdraw. Nothing identifying persists; the cost
  is that a participant who loses the slip **cannot** withdraw, and they must be
  told that plainly at consent time rather than discovering it later.

Whichever is chosen, it is written into the consent form so the participant
knows before signing which one applies to them.

### 11.3 What may enter Git

- **Nothing participant-level.** No per-trial manifests, no score series, no
  session logs.
- Only a **verified aggregate, non-identifying** final report may be committed,
  and only under D16 after the owner has reviewed it for re-identification risk.
- Datasets live outside the repository, at the locations set by D6a and D6b. `.gitignore`
  should be extended to make accidental commits harder before any capture
  begins.

### 11.4 Reproducibility metadata (safe to record)

Recorded per session, and safe to publish: `faceauth` commit SHA, Python
version, pinned dependency versions, `face_landmarker.task` SHA-256, the full
`LivenessConfig` in force, camera device label and resolution, randomisation
seed, and the operating system build.

### 11.5 Residual risk — stated, not waived

**Derived liveness measurements may still be sensitive.** A per-frame blink-score
series is a behavioural biometric signal: blink timing and dynamics are
person-linked, and this data is collected *because* it discriminates between
people and non-people. Landmark-derived quantities such as inter-eye distance
are physical measurements of a face.

Calling these "anonymous" would be overclaiming. The defensible statements,
**about Category B only**, are:

- they contain **no direct identifiers** (§11.2);
- they are **not images** and cannot be viewed as a face;
- re-identification from them is not straightforward, but has **not been
  formally assessed** by this project;
- they should therefore be treated as **pseudonymised personal data**, not
  anonymous data, and handled under sections 11–12 accordingly.

**None of that applies to Category A.** Signed consent forms, contact details
and any pseudonym mapping are **directly identifying records** and are not
pseudonymised by anything. They are the reason the two categories are stored and
destroyed separately (§11.2, §12.3), and they are never committed to this
repository.

The attack media (printed photo, replay video) is an image of a real person and
is unambiguously sensitive; D10 governs it.

### 11.6 Prohibited outright

No cloud upload, no telemetry, no remote API, no third-party processor, no
sharing outside the approved storage location, and no use of collected data for
any purpose other than B18 — including model training or tuning outside the
split rules in section 10.2.

---

## 12. Consent, withdrawal, retention, deletion

### 12.1 Consent

Before any recorded trial, each participant receives and signs
`docs/b18/forms/CONSENT_FORM.md`, covering: purpose; exactly what is and is
not recorded (explicitly: *no images or video are kept*); storage location and
access **for both record categories**; the two retention periods; that
participation is voluntary; **which withdrawal mechanism applies to them**
(§11.2) and its limits; that withdrawal is honoured without needing a reason;
and a contact route.

The **completed, signed form is a Category A identifying record.** It goes
straight to D6a storage, never into the measurement directory, and never into
Git. `docs/b18/forms/CONSENT_FORM.md` in this repository is a blank template
and must stay that way.

Consent is **specific to B18**. It does not cover reuse for other work.

### 12.2 Withdrawal

- A participant may withdraw at any time, during or after a session, without
  giving a reason and without consequence.
- Withdrawal is actioned through whichever mechanism was chosen in §11.2 —
  held mapping, or participant-held token.
- On withdrawal, that participant's **Category B** measurements are deleted
  under 12.3, and their **Category A** consent record is handled per D7a: either
  destroyed with it, or retained as the record that consent was given and then
  withdrawn. The owner decides which; both are defensible, and the choice is
  disclosed on the consent form.
- Deletion is recorded in the retention log with date and confirmation.
- If an aggregate report has already been published and cannot be un-published,
  the participant is told this **at consent time**, not after. Aggregates should
  therefore be constructed so that no individual's contribution is separable.

### 12.3 Retention and deletion — separately for each category

**Retention periods are set separately** (D7a for Category A, D7b for
Category B), because they answer to different obligations: consent records
exist to evidence consent and enable withdrawal; measurements exist for the
analysis.

- **Proposed default, Category B (measurements):** 90 days after the B18
  decision is recorded, then deletion.
- **Proposed default, Category A (consent records):** retained until the
  Category B data it governs is destroyed and the B18 decision is recorded,
  then destroyed — unless the owner decides under D7a that evidence of consent
  should outlive the data, in which case that period is stated explicitly.

#### Deletion procedure

1. Remove the Category B dataset directory and all derived intermediates.
2. Scrub temporary and scratch files; the analysis must not leave score series
   behind (verified, not assumed).
3. Destroy Category A records per D7a — including physical paper, if consent was
   collected on paper.
4. Destroy the pseudonym mapping, if one was kept.
5. Destroy or dispose of attack media per D10.
6. **Verify** by searching for every session and participant ID across the
   approved storage locations and confirming zero hits, and by confirming Git
   history contains nothing from either category.

Every step is recorded in `docs/b18/forms/RETENTION_DELETION_LOG.md`.

#### What deletion does and does not guarantee — stated honestly

**Deleting a file, and emptying the recycle bin, does not guarantee the data is
irrecoverable.** On SSDs — which is what this project runs on — wear levelling,
over-provisioning, and the drive's own remapping mean the original blocks may
persist and are not reliably reachable, let alone overwritable, by any
file-level tool. File-level "secure erase" utilities that overwrite in place
were designed for spinning disks and **should not be relied on for SSDs**.
Copy-on-write filesystems, snapshots, and system restore points can retain
copies independently.

The defensible approaches, in rough order of strength:

1. **Full-disk or volume-level encryption from the start**, with the dataset
   stored only inside it, so that destroying the key renders the data
   unreadable regardless of block remapping. This is the recommended default
   under D6a/D6b, and it is the reason encryption is a *collection-time* decision
   rather than an afterthought.
2. **Encrypted container per dataset**, destroyed by discarding its key.
3. **ATA Secure Erase / NVMe Format** of the whole device — effective, but
   destroys everything on it, so it is only realistic for dedicated media.
4. Plain deletion — removes the reference, and is **not** a guarantee of
   erasure.

The owner records under D7b **which method is actually used**, and the retention
log records the residual limitation truthfully. If the method is plain deletion,
the log must say that recoverability was not eliminated, rather than recording
"securely deleted".

- **Backups:** proposed default is **no backups of either category** — backups
  multiply copies that must later be found and destroyed, and each copy inherits
  the erasure problem above. If the owner requires backups (D7a/D7b), each copy's
  location, medium, and destruction must be tracked in the same log.

---

## 13. Repeatability

The result must be reproducible by someone else from the report alone:

- randomisation seed and full condition schedule recorded;
- provenance metadata (11.4) recorded per session;
- the analysis script committed and deterministic — same manifest in, same
  numbers out;
- the analysis re-run from the stored manifest at least once, by a second
  execution, confirming identical output;
- a **re-test subset**: at least one participant repeats a defined subset of
  trials in a separate session, to show the result is not an artefact of a
  single sitting.

---

## 14. What would clear B18 — and what would not

### 14.1 Evidence required (all of it)

Mapping to issue #14's checklist:

1. Genuine blink and genuine non-blink trials, with observed score
   distributions on **both sides** of 0.40 and 0.20 (§7.2, §9).
2. The configured thresholds actually exercised — demonstrated by real trials
   whose scores cross them, not by synthetic proxies.
3. FAR and FRR per §9 — **per-participant tables first**, per-attack-type
   breakdown, denominators, exclusions, and Wilson intervals or explicit
   zero-event upper bounds, each labelled **descriptive and trial-level** and
   quoted with the participant count it rests on (§9.3).
4. Static printed-photo attacks (S1–S2), **including the distribution of
   per-trial `max(blink_score)` and its margin to 0.40** (§6.3).
5. Display/replay behaviour (S3–S4), with the known replay limitation
   quantified rather than restated.
6. Lighting, pose, distance, eyewear and **≥ 2 camera devices** (§7.1).
7. The written calibration methodology — this document, plus the executed
   schedule and the committed analysis script.
8. An explicit human security review recorded as a **decision** (§15).

### 14.2 Proposed pass criteria (owner to confirm under D13)

Fixed before capture; these are proposals:

- **No spoof acceptance** in S1–S3 across all valid trials; and the observed
  maximum `max(blink_score)` over all S1–S3 trials stays **below 0.40 with a
  margin the owner finds acceptable**, stated numerically. Given §3.1, a margin
  of 0.018 should not be considered acceptable without justification.
- **S4 (video replay) is expected to be accepted.** It does not fail B18; it
  must be reported as an unmitigated known gap, and `docs/THREAT_MODEL.md` §4
  must remain accurate about it.
- **FRR** low enough that the control is usable, at a value the owner sets in
  advance, reported with its interval.
- Results **consistent across participants and both cameras** — a control that
  works for one person or one device has not been validated. Consistency here is
  a qualitative check on the participants actually tested; it is not a
  generalisation claim.

### 14.3 What would remain insufficient

- Stage 1 (owner-only) results, at any trial count.
- Any amount of additional **synthetic** measurement — the corpus provably
  cannot reach 0.40 (issue #14).
- Zero observed spoof accepts with no margin analysis (§6.3).
- Pooled FAR that averages replay attacks together with photo attacks.
- Rates reported without denominators, exclusions, or intervals.
- A pooled trial-level rate or bound quoted **without** the participant count
  and the non-independence limitation beside it (§6.1, §9.3).
- Any wording implying certification, a population security rate, or general
  applicability — from any stage of this study.
- Thresholds chosen after seeing the evaluation set (§10).
- A green summary table with no recorded human security decision (§15).
- Passing results that the report cannot explain how to reproduce (§13).

---

## 15. The security review B18(h) requires

A recorded **decision**, not an observation, using
`docs/b18/forms/SECURITY_REVIEW_CHECKLIST.md`. It must:

- be performed against the evidence, by a named reviewer role, on a stated date;
- ideally be performed by someone **other than the person who ran the trials**
  (D15) — self-review by the system's author is the weakest form and must be
  labelled as such if that is what happens;
- explicitly address the residual risks, above all video replay (S4);
- state the decision in one of three forms: **B18 cleared**, **B18 remains open
  pending specified further work**, or **B18 cannot be cleared with this
  configuration** (which would make changing the liveness design the next task);
- be committed as part of the aggregate report under D16.

**Nothing else clears B18.** Not this plan, not a clean spreadsheet, not CI.

---

## 16. Pre-capture blocker checklist

All must be true before the first recorded trial:

- [ ] Every decision (D1–D16, including D6a/D6b and D7a/D7b) recorded in the owner decision record
- [ ] Thresholds frozen; §2.1 confirms the threat model and code agree
- [ ] **Two separate storage locations provisioned** — identifying records (D6a) and measurements (D6b) — and confirmed not to share a directory, archive, or backup
- [ ] Withdrawal mechanism chosen (§11.2) and written into the consent form
- [ ] Erasure method chosen (D7b) with its residual limitation acknowledged
- [ ] Pass criteria (§14.2) written down with numbers
- [ ] Consent form approved and, if applicable, ethical review resolved (D5)
- [ ] Storage location provisioned with the approved access control and encryption
- [ ] `.gitignore` extended so participant data cannot be committed accidentally
- [ ] Stage 0 dry run completed against synthetic input
- [ ] Second camera device available (D11)
- [ ] Attack media prepared under D10, with its own disposal plan
- [ ] Retention/deletion log started
- [ ] Analysis script committed and verified deterministic on synthetic input
- [ ] Network check run in the capture environment

---

## 17. Explicitly out of scope for this document

Not built, not started, not authorized: camera integration for capture,
recording software, any biometric collection tooling, attack media, Phase 3
authentication components, Windows Credential Provider work, and any change to
liveness thresholds or security configuration.

**B18 remains OPEN. Phase 3 remains blocked.**
