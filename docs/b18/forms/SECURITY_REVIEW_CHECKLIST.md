# B18 independent security review — TEMPLATE

> This is the **decision** B18(h) requires. Nothing else clears B18 — not the
> plan, not a clean evidence report, not CI.

**Review date:** `YYYY-MM-DD`
**Reviewer role:** `<role>`
**Reviewer ran the trials?** `yes / no` — if **yes**, this is a self-review and
must be labelled as such in the outcome; it is the weakest form of review and
decision D15 should be revisited.
**Evidence reviewed:** `<evidence report reference / commit SHA>`
**Plan revision:** `<commit SHA>`

---

## A. Was the protocol actually followed?

- [ ] Owner decision record complete and signed **before** capture
- [ ] Thresholds frozen pre-capture; evaluation set never used for tuning
- [ ] Pass criteria pre-registered numerically, and reproduced unchanged in the report
- [ ] Randomised trial order; warm-up trials discarded
- [ ] Ground truth assigned independently of model output
- [ ] Invalid trials excluded with reasons, from numerator **and** denominator
- [ ] Deviations recorded as they happened
- [ ] Analysis reproducible from the stored manifest

## B. Is the evidence sufficient for the claim being made?

- [ ] Stage 2, not an owner-only pilot (a pilot **cannot** clear B18)
- [ ] Both configured thresholds genuinely exercised by real trials
- [ ] ≥ 2 physically different cameras
- [ ] Lighting, pose, distance, eyewear coverage adequate; drops justified
- [ ] Per-participant results reported **before** aggregate, with the
      participant treated as the unit of analysis
- [ ] Denominators, exclusions, and intervals present for every rate
- [ ] Zero-event rates reported as upper bounds, not as "0 %"
- [ ] FAR broken down **per attack type**, never pooled across S1–S4
- [ ] Every rate and interval is **labelled descriptive and trial-level**, and
      quoted with the participant count it rests on
- [ ] The headline limitation states exact participant count, trial counts and
      exclusions, and appears **first**
- [ ] Both participant-level and trial-level sampling limitations are stated
- [ ] **No wording implies certification, a population rate, or general
      applicability** — reject the report if it does

## C. The spoof margin — the decisive question

- [ ] Distribution of `max(blink_score)` for S1–S3 reported, not just pass/fail
- [ ] Observed maximum and its margin to 0.40 stated numerically
- [ ] Margin meets the pre-registered threshold
- [ ] Reviewer is satisfied the margin is defensible, given the prior
      single-trial observation of 0.382 (margin **0.018**)

> A FAR of zero across a handful of trials, with a margin of a few hundredths,
> is not evidence of spoof resistance. If the margin is thin, the correct
> outcome is **not** to clear B18.

## D. Residual risk

- [ ] Video replay (S4) explicitly addressed as an unmitigated known gap
- [ ] `docs/THREAT_MODEL.md` remains accurate after these results
- [ ] Head-turn remains disabled by default, or its re-enablement is separately justified
- [ ] Any newly discovered failure mode recorded and tracked
- [ ] Limitations section is honest and leads the report

## E. Privacy and data handling

- [ ] Consent obtained from every participant before recording
- [ ] No raw frames or video retained (or deviation approved under D9)
- [ ] **Identifying records (Category A) and measurements (Category B) stored
      separately** — not the same directory, archive, or backup
- [ ] Signed consent forms, contact details and any pseudonym mapping held only
      in D6a storage; **none in the repository**
- [ ] No direct identifiers in any Category B dataset, report, or filename
- [ ] Nothing participant-level committed to Git, in either category
- [ ] Withdrawal mechanism worked as described, and withdrawals were honoured
- [ ] Retention/deletion log current, **with A and B tracked separately**
- [ ] The erasure method is recorded, and the log does **not** claim secure
      erasure that the method cannot deliver
- [ ] Attack media disposed of per D10

---

## Decision — choose exactly one

- [ ] **B18 CLEARED.** The evidence supports the claim, with the limitations
      recorded in the report. Reasoning: `<...>`

- [ ] **B18 REMAINS OPEN**, pending specified further work: `<what, exactly>`

- [ ] **B18 CANNOT BE CLEARED with this configuration.** The liveness design
      must change before re-testing. Reasoning: `<...>`

**Reviewer signature:** `____________________`  **Date:** `__________`

---

If B18 is cleared, update `docs/PHASE2_ACCEPTANCE_CRITERIA.md` (B18), issue #14,
and the Phase 3 gate references — citing **this decision**, not the plan and not
the raw numbers. If it is not cleared, B18 stays open and Phase 3 stays blocked.
