# Participant consent — TEMPLATE

> **Template only. Never commit a completed copy.**
> Approved under decision D4. Do not use before that decision is recorded.

**Study:** B18 — validating a face-liveness ("are you a real person?") check
**Project:** `ai-face-auth` — a local research prototype. It is **not** a
product, and it does **not** control sign-in to any computer.
**Participant ID:** `P__`  (assigned; write no name on this form)
**Date:** `YYYY-MM-DD`

---

## What this is

You will sit in front of a webcam and be asked to do simple things — blink when
prompted, or deliberately not blink. We will also point the camera at a printed
photograph and at a screen, to check the system correctly refuses those.

It takes roughly `<N>` minutes.

## What is recorded

**No photographs and no video of you are saved.** Camera frames are processed in
memory and discarded immediately.

What is saved is a set of numbers per attempt:

- a score, between 0 and 1, of how "closed" your eyes looked in each frame;
- how many frames contained a detected face;
- whether the system accepted or rejected the attempt;
- the condition (lighting, distance, which camera) and whether you blinked.

You are referred to only as `P__`. **No name, email address, account, date of
birth, or photograph is stored** with these numbers.

## Honest note about what these numbers are

We are not going to tell you this data is anonymous, because we have not proven
that. Blink timing is a personal characteristic — that is precisely why the
system measures it. We treat it as **personal data under a pseudonym**, stored
and deleted accordingly, rather than as anonymous data.

## Where it is kept, and for how long

- Stored only on `<approved location, D6>`, with access limited to `<D6>`.
- **Never uploaded anywhere.** No cloud, no external service, no sharing with
  third parties. The software makes no network connections during this work.
- Deleted after `<retention period, D7>`, and the deletion is logged.

## Voluntary participation and withdrawal

Taking part is entirely voluntary. You may stop at any moment, and you do not
have to give a reason.

You may withdraw afterwards by contacting `<contact route, D4>`. Your
measurements will then be deleted and the deletion recorded.

**One limit, told to you now rather than later:** if an aggregate summary has
already been published by the time you withdraw, that summary cannot be
un-published. It contains no data identifying you and no individual's
contribution can be separated from it.

## Attack media

If a printed photo or video of a person is used to test the system's refusal,
that media is covered by decision D10 and is destroyed afterwards. If it is a
photo **of you**, that is stated here explicitly: `yes / no`.

## Questions

Contact `<contact route>`.

---

## Consent

Please initial each line you agree with.

- `___` I have read and understood the above, and have had the chance to ask questions.
- `___` I understand no images or video of me are saved.
- `___` I understand the derived numbers are treated as pseudonymised personal data.
- `___` I understand participation is voluntary and I may stop at any time.
- `___` I understand how to withdraw, and the one limit on withdrawal after publication.
- `___` I agree to take part in this B18 validation session.

This consent is **specific to B18 validation**. It does not permit use of the
data for anything else, including training or tuning any model.

**Participant signature:** `____________________`  **Date:** `__________`

**Administered by:** `____________________`  **Date:** `__________`
