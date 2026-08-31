# B18 preparation material

**B18 is OPEN. Nothing here is authorization, and nothing here is evidence.**

This directory holds the templates referenced by
[`docs/B18_REAL_INPUT_VALIDATION_PLAN.md`](../B18_REAL_INPUT_VALIDATION_PLAN.md).
They exist so that, *if* the repository owner approves real-input validation,
the recording of decisions, consent, sessions, and results is consistent and
reviewable rather than improvised.

| Template | Used when |
|---|---|
| `templates/OWNER_DECISION_RECORD.md` | Before anything else - records D1-D16 |
| `templates/CONSENT_FORM.md` | Per participant, before their first recorded trial |
| `templates/SESSION_CHECKLIST.md` | Per session, run top to bottom |
| `templates/TRIAL_MANIFEST_SCHEMA.md` | Defines the per-trial record the analysis consumes |
| `templates/RETENTION_DELETION_LOG.md` | From first capture until deletion is verified |
| `templates/B18_EVIDENCE_REPORT.md` | After analysis, before security review |
| `templates/SECURITY_REVIEW_CHECKLIST.md` | The B18(h) decision itself |

## Rules for this directory

- **No participant information, ever.** No names, contact details, photographs,
  or identifiers of any kind.
- **No captured measurements, ever.** No score series, no manifests, no session
  logs. Datasets live outside the repository (plan section 11.3).
- Templates contain placeholders only. A filled-in template containing real
  participant data must **not** be committed; only a verified aggregate,
  non-identifying final report may be, and only under decision D16.

If you are reading this because you are about to start capturing: stop, and
check plan section 16 first.
