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

`<e.g. "This is a convenience sample of N participants, unblinded, single site,
run by the system's author. It characterises behaviour; it does not certify the
control.">`

If Stage 1: **"Owner-only pilot. This cannot clear B18 and no population claim
is made."**

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

## 3. Per-participant results (before any aggregate)

| Participant | Camera | Genuine n | FRR | Spoof n | FAR | max(blink) over spoofs |
|---|---|---|---|---|---|---|
| P01 | | | | | | |

If these vary widely, say so here and do **not** lead with the aggregate.

## 4. Genuine trials

- FRR = `<num>/<den>` = `<rate>`, Wilson 95 % CI `[a, b]`
- Genuine non-blink (N*) correct-rejection rate = `<num>/<den>` — **not FRR**
- Distribution of `max(blink_score)` for genuine blinks: n, min, median, max
- Distribution of `min(blink_score)`: n, min, median, max
- Were both thresholds actually crossed by real trials? `yes / no`

## 5. Spoof trials — by attack type, never pooled

| Type | Description | n | Accepted | FAR (95 % CI or upper bound) | max(blink) observed | Margin to 0.40 |
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

`<Be specific. Sample size, population, blinding, adversary sophistication,
attack media quality, and anything the condition matrix did not cover.>`

---

**This report is input to the security review. It is not the decision.**
Proceed to `SECURITY_REVIEW_CHECKLIST.md`.
