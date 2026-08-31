# Participant consent — TEMPLATE

> **Template only. Never commit a completed copy.**
> Approved under decision D4. Do not use before that decision is recorded.

> **This completed form is an identifying record.** Once signed it goes to the
> approved identifying-records storage (decision D6a) — never into the
> measurement directory, and never into the repository.

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

Two separate things are stored, in two separate places:

| | This signed form and your contact details | The measurements |
|---|---|---|
| Identifies you? | **Yes** — it has your signature | No name or signature; only `P__` |
| Kept at | `<D6a>`, access limited to `<D6a>` | `<D6b>`, access limited to `<D6b>` |
| Kept until | `<D7a>` | `<D7b>` |

They are **not** stored together, so your signature never sits alongside your
measurements.

- **Never uploaded anywhere.** No cloud, no external service, no sharing with
  third parties. The software makes no network connections during this work.
- Deletions are logged.

### What deletion means, honestly

When the retention period ends we delete this data using `<method, D7b>`. If
that method is ordinary file deletion, we will not tell you it is
unrecoverable — on modern solid-state drives, deleting a file does not
guarantee the underlying data is gone. `<If full-disk encryption or an
encrypted container is used, say so here instead: destroying the key makes the
data unreadable.>`

## Voluntary participation and withdrawal

Taking part is entirely voluntary. You may stop at any moment, and you do not
have to give a reason.

You may withdraw afterwards. How that works depends on which option applies to
this study — **the administrator will tell you which, and it is written here
before you sign**:

- `☐` **We keep a private list** linking `P__` to you, stored separately from
  the measurements. Contact `<contact route, D4>` and we look you up.
- `☐` **We keep no such list.** You are given your `P__` on a slip. Quoting it
  is the *only* way to identify your data. **If you lose it, we cannot withdraw
  your data, because we will have no way to tell which records are yours.**

Your measurements are then deleted and the deletion recorded. Whether this
signed form is destroyed at the same time or retained as proof that consent was
given and withdrawn is decision `<D7a>`: `<state which>`.

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
- `___` I understand how to withdraw, which option applies to me, and the limits on withdrawal (including after publication).
- `___` I understand this signed form is stored separately from the measurements, and is not published anywhere.
- `___` I agree to take part in this B18 validation session.

This consent is **specific to B18 validation**. It does not permit use of the
data for anything else, including training or tuning any model.

**Participant signature:** `____________________`  **Date:** `__________`

**Administered by:** `____________________`  **Date:** `__________`
