# B18 session checklist — TEMPLATE

> Run top to bottom. A session that skips a pre-flight item is a **pilot**, not
> evidence. Never commit a completed copy.

**Session ID:** `S__`  **Participant ID:** `P__`  **Date:** `YYYY-MM-DD`
**Operator:** `<role>`  **Camera device label:** `<model / interface>`

---

## Before the participant arrives

- [ ] Owner decision record complete and signed; D1–D16 answered
- [ ] Thresholds frozen and pass criteria pre-registered (plan §10.1, §14.2)
- [ ] Stage 0 dry run passed on this machine
- [ ] Storage location mounted, access control and encryption per D6
- [ ] `.gitignore` covers the dataset path — verified, not assumed
- [ ] Retention/deletion log open for this session
- [ ] Network check run in this environment: `python scripts/check_network_activity.py` → **0 external endpoints**
- [ ] Provenance captured (plan §11.4): commit SHA, Python version, pinned
      dependency versions, `face_landmarker.task` SHA-256, full `LivenessConfig`,
      camera label and resolution, OS build
- [ ] Randomisation seed generated and recorded: `<seed>`
- [ ] Trial schedule generated from that seed, and **not** grouped by trial type
- [ ] Attack media prepared per D10; disposal plan confirmed
- [ ] Confirm no raw-frame writing is enabled (D9 default: none)

## With the participant, before recording

- [ ] Consent form read, questions answered, signed
- [ ] Participant ID assigned; **no name written anywhere near the data**
- [ ] Explained: they may stop at any time, without a reason
- [ ] ≥ 3 warm-up attempts run and **discarded** (plan §7.3)

## During the session

- [ ] Follow the randomised schedule; do not reorder to "get the spoofs done"
- [ ] Record the **intended** trial type before each attempt
- [ ] Record participant self-report after each genuine trial
- [ ] Do **not** consult the model's score when labelling ground truth (§7.4)
- [ ] Mark invalid trials with a reason; allow at most one retry per cell
- [ ] Brief rest between trials; watch for eye fatigue
- [ ] Note any deviation from the schedule as it happens, not afterwards

## Immediately after

- [ ] Manifest written and validated against the schema
- [ ] Trial counts reconciled: attempted = valid + excluded
- [ ] Session notes recorded, including anything that felt off
- [ ] Temporary/scratch files scrubbed; **verified** by searching for the session ID
- [ ] Attack media stored or destroyed per D10
- [ ] Retention log updated with what now exists and where
- [ ] Confirm nothing participant-level entered Git: `git status --porcelain`

## Deviations

| Trial / time | What deviated | Why | Effect on analysis |
|---|---|---|---|
| | | | |

---

**Operator attestation:** the above was followed as recorded, including the
deviations listed.

Signed: `____________________`  Date: `__________`
