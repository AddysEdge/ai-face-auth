# B18 preparation material

**B18 is OPEN. Nothing here is authorization, and nothing here is evidence.**

This directory holds the blank forms referenced by
[`docs/B18_REAL_INPUT_VALIDATION_PLAN.md`](../B18_REAL_INPUT_VALIDATION_PLAN.md).
They exist so that, *if* the repository owner approves real-input validation,
the recording of decisions, consent, sessions, and results is consistent and
reviewable rather than improvised.

They live in `forms/`, not `templates/`, deliberately: `.gitignore` excludes
`templates/` anywhere in the tree to keep **biometric templates and enrolled
state** out of Git. That rule is a safety guard and was not weakened to make
room for a documentation folder.

| Form | Used when |
|---|---|
| `forms/OWNER_DECISION_RECORD.md` | Before anything else - records D1-D16 |
| `forms/CONSENT_FORM.md` | Per participant, before their first recorded trial |
| `forms/SESSION_CHECKLIST.md` | Per session, run top to bottom |
| `forms/TRIAL_MANIFEST_SCHEMA.md` | Defines the per-trial record the analysis consumes |
| `forms/RETENTION_DELETION_LOG.md` | From first capture until deletion is verified |
| `forms/B18_EVIDENCE_REPORT.md` | After analysis, before security review |
| `forms/SECURITY_REVIEW_CHECKLIST.md` | The B18(h) decision itself |

## Rules for this directory

- **No participant information, ever.** No names, signatures, contact details,
  photographs, pseudonym mappings, or identifiers of any kind. A **completed**
  consent form is a directly identifying record and belongs in the approved
  identifying-records storage (decision D6a), never here.
- **No captured measurements, ever.** No score series, no manifests, no session
  logs. Datasets live outside the repository (plan section 11.3).
- Templates contain placeholders only. A filled-in template containing real
  participant data must **not** be committed; only a verified aggregate,
  non-identifying final report may be, and only under decision D16.

If you are reading this because you are about to start capturing: stop, and
check plan section 16 first.

## Stage 0 tooling

`scripts/b18_stage0/` implements the Stage 0 dry run: strict whitelist
validation against `forms/TRIAL_MANIFEST_SCHEMA.md`, cross-session
comparability checks, deterministic aggregate analysis, and a rehearsal of the
workspace-deletion step. See the plan's Stage 0 section for commands and exit
codes.

Two properties are worth stating plainly, because earlier revisions got them
wrong:

- **Every accept/reject decision goes through the shipping function.**
  `scripts/b18_stage0/decision.py` calls
  `faceauth.liveness.challenge_response.decide_blink` directly, so validation,
  analysis and the report cannot drift from the system being rehearsed. The
  comparison is exact - no tolerance widens the threshold. A tolerance appears
  only as a *label* ("this sat on the boundary") and decides nothing.
- **Nothing here deletes a path you name.** The cleanup rehearsal takes no
  argument at all: it creates its own throwaway directory under the system
  temporary directory, deletes that, and reports what it did. An earlier design
  gated deletion on a marker file stored inside the candidate directory and
  called it a capability; it was not one - a forged directory and marker
  verified identically, which was demonstrated rather than argued. The marker
  survives only as a sanity check on an output destination. **No secure-erasure
  claim is made**: filesystem deletion removes directory entries, and on SSDs
  the underlying data may persist.

`analyse` writes into a fresh workspace it creates itself; there is no `--out`,
`--report`, or `--workspace`. Nothing is written until parsing, schema
validation and corpus validation have all passed, so an invalid run leaves no
directory behind.

It accepts **only** manifests declaring
`"data_classification": "synthetic_stage0"`. Feeding it real Stage 1 or Stage 2
data is not a configuration change - it requires a separate, owner-authorized,
reviewed change.

It has run only against the invented manifests in
`scripts/b18_stage0/synthetic.py`. **No real input exists, and the tooling
cannot clear B18** - only the recorded security review can.
