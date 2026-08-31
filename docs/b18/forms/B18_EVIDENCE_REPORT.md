# B18 evidence report — TEMPLATE

> Completed after analysis, before the security review. Only a **verified
> aggregate, non-identifying** version may be committed, and only under decision
> D16. This template must not be filled in with participant-level data in the
> repository.
>
> **Completing this report does not clear B18.** Only the security-review
> decision does.

**Report date:** `YYYY-MM-DD`  **Stage:** `1 (owner-only pilot) | 2a | 2b`
**Plan revision followed:** `<commit SHA>`
**Owner decision record:** `<reference>`

---

## 0. Headline limitation — state it first

**Mandatory. This paragraph leads the report and may not be moved to an
appendix.** It must state, in numbers:

- exact number of **participants**: `<N>`
- exact number of **trials attempted / valid / excluded**: `<a / b / c>`
- that the participants are a **convenience sample**, not random, and how they
  were recruited
- that every rate below is **descriptive and trial-level**, conditional on these
  participants, these attacks, these conditions and these two cameras
- that **no result here certifies the control, establishes a population rate, or
  demonstrates general applicability**

Template: `<"N participants (convenience sample, recruited by ...), T valid
trials of A attempted (E excluded). All rates below are descriptive and
trial-level, conditional on these participants, attacks, conditions and
cameras. This characterises behaviour; it does not certify the control, does
not establish a population rate, and does not demonstrate that the result
generalises.">`

If Stage 1: **"Owner-only pilot, n = 1 participant. This cannot clear B18. No
claim about people is made."**

### 0.1 Sampling limitations — both kinds

| Limitation | Statement |
|---|---|
| **Participant sampling** | `<how many, how recruited, relationship to the author, what population they do not represent>` |
| **Trial sampling** | `<trials are clustered within participants and within a small set of attack instances; trial-level intervals therefore understate uncertainty about people and attacks>` |
| **Condition sampling** | `<which cells of the matrix were covered, which were dropped>` |
| **Attack sampling** | `<how many distinct printed photos / screens / videos; who built them>` |

## 1. Pre-registered criteria (copied unchanged from D13)

| Criterion | Pre-registered value |
|---|---|
| `blink_score_high` / `blink_score_low` | `0.40 / 0.20` |
| Acceptable spoof margin below 0.40 | `<number>` |
| Maximum acceptable FRR | `<number>` |
| S4 (video replay) expectation | accepted — known gap |
| Consistency requirement | `<statement>` |

Thresholds were frozen before capture: `yes / no`.
Evaluation set examined during any tuning: `yes / no`. If yes, see plan §10.2 —
the result is uncalibrated and B18 stays open.

## 2. What was collected

| | Count |
|---|---|
| Participants | |
| Cameras (≥ 2 required) | |
| Sessions | |
| Trials attempted | |
| Trials valid | |
| Trials excluded | |

### Exclusions by reason

| Reason | Count |
|---|---|
| no_face_detected | |
| missed_prompt | |
| operator_error | |
| software_error | |
| ambiguous_ground_truth | |

## 3. Per-participant results — primary

**These come before any aggregate, and the participant is the unit of analysis
for any statement about people.**

| Participant | Camera | Genuine n | FRR (count/den) | Spoof n | FAR (count/den) | max(blink) over spoofs |
|---|---|---|---|---|---|---|
| P01 | | | | | | |

If these vary noticeably, say so here and do **not** lead with the aggregate.

Number of participants contributing to any aggregate below: `<N>` — this, not
the trial count, is the sample size for anything said about people.

## 4. Genuine trials

- FRR = `<num>/<den>` = `<rate>`, Wilson 95 % CI `[a, b]` — **descriptive,
  trial-level, over `<N>` participants; not a population rate**
- Genuine non-blink (N*) correct-rejection rate = `<num>/<den>` — **not FRR**
- Distribution of `max(blink_score)` for genuine blinks: n, min, median, max
- Distribution of `min(blink_score)`: n, min, median, max
- Were both thresholds actually crossed by real trials? `yes / no`

## 5. Spoof trials — by attack type, never pooled

Every FAR below is **descriptive and trial-level over `<N>` participants and
`<M>` distinct attack instances**, and is not a population rate.

| Type | Description | n | Accepted | FAR (95 % CI or upper bound, descriptive) | max(blink) observed | Margin to 0.40 |
|---|---|---|---|---|---|---|
| S1 | printed photo, propped | | | | | |
| S2 | printed photo, hand-held | | | | | |
| S3 | screen, still photo | | | | | |
| S4 | screen, replay of genuine blink | | | | | |
| S5 | `<if in scope>` | | | | | |

### 5.1 Margin analysis — the primary spoof outcome (plan §6.3)

- Observed maximum `max(blink_score)` across all S1–S3: `<value>`
- Margin to the 0.40 threshold: `<0.40 − value>`
- Count of S1–S3 trials within 0.05 of 0.40: `<n>`
- Prior single-trial reference: 0.382, margin 0.018 (`tests/test_liveness_calibration.py`)

**A FAR of zero with a margin of 0.018 is not a pass.** State the margin, and
compare it to the pre-registered acceptable margin.

## 6. Condition coverage

| Factor | Levels attempted | Levels dropped | Why dropped |
|---|---|---|---|
| Lighting | | | |
| Head pose | | | |
| Distance | | | |
| Eyewear | | | |
| Camera | | | |

## 7. Repeatability

- Analysis re-run from stored manifest, identical output: `yes / no`
- Re-test subset (separate session): `<participant, trials, agreement>`
- Randomisation seed(s): `<...>`
- Provenance: commit SHA, model SHA-256, config — `<...>`

## 8. Against the pre-registered criteria

| Criterion | Result | Met? |
|---|---|---|
| No S1–S3 acceptance | | |
| Spoof margin ≥ pre-registered | | |
| FRR ≤ pre-registered | | |
| Consistent across participants and cameras | | |
| Both thresholds genuinely exercised | | |
| ≥ 2 cameras | | |

## 9. Known gaps carried forward

- **Video replay (S4)** — expected to succeed; quantified above; remains
  unmitigated. `docs/THREAT_MODEL.md` §4 must stay accurate about it.
- `<others>`

## 10. What this report does not establish

Required, and specific — not a generic disclaimer:

- **Does not certify** the liveness control.
- **Does not establish a population FAR or FRR.** The trial-level intervals
  above describe the attempts that were run; trials are clustered within `<N>`
  non-randomly-chosen participants and `<M>` attack instances.
- **Does not demonstrate generalisation** to people, cameras, lighting, or
  attacks outside those tested.
- `<Blinding, adversary sophistication, attack media quality, condition cells
  not covered, and anything else the study could not reach.>`

---

**This report is input to the security review. It is not the decision.**
Proceed to `SECURITY_REVIEW_CHECKLIST.md`.
