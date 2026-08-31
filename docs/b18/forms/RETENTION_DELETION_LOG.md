# B18 retention and deletion log - TEMPLATE

> Opened at first capture, closed only when deletion is **verified**. Never
> commit a completed copy. Governed by decisions D6, D7, D9, D10.

Two categories, tracked separately throughout. They must not share a directory,
archive, or backup.

| | **A - identifying records** (signed consent, contact route, pseudonym mapping) | **B - pseudonymised measurements** |
|---|---|---|
| Storage location | `<D6a>` | `<D6b>` |
| Access control | `<D6a>` | `<D6b>` |
| Encryption | `<D6a>` | `<D6b>` |
| Retention | `<D7a>` | `<D7b>` |
| Destruction method | `<D7a>` | `<D7b>` |

**Withdrawal mechanism (D7a):** `held mapping / participant-held token`
**Backups:** `<default proposal: NONE - every copy must be tracked below>`
**Raw frames permitted (D9):** `<default proposal: NO>`

**Erasure method actually used (D7b):** `<...>`
**Residual limitation, stated honestly:** `<e.g. "plain file deletion on an SSD
does not guarantee irrecoverability; blocks may persist due to wear levelling">`

---

## What exists

| Item | Cat. | Location | Created | Contains | Copies |
|---|---|---|---|---|---|
| Signed consent forms | **A** | | `YYYY-MM-DD` | signatures - directly identifying | |
| Contact route records | **A** | | | directly identifying | |
| Pseudonym mapping (if kept) | **A** | | | links `P__` to a person | |
| Session manifest `S01` | **B** | | | derived measurements, pseudonymous | 1 |
| Analysis intermediates | **B** | | | | |
| Attack media (D10) | **A** | | | image of a real person | |

Confirmed A and B are not co-located: `yes / no`  Checked: `__________`

## Withdrawals

| Participant | Requested | Deleted | Verified by | Notes |
|---|---|---|---|---|
| | | | | |

## Deletion record

Every step per plan §12.3. Deletion is not complete until **verified**.

| Step | Cat. | Done | Date | By | Verification |
|---|---|---|---|---|---|
| Measurement dataset removed | B | ☐ | | | |
| Analysis intermediates removed | B | ☐ | | | |
| Temporary / scratch files scrubbed | B | ☐ | | | |
| Signed consent forms destroyed (or retained per D7a) | A | ☐ | | | state which |
| Contact route records destroyed | A | ☐ | | | |
| Pseudonym mapping destroyed | A | ☐ | | | |
| Attack media destroyed (D10) | A | ☐ | | | incl. physical prints |
| Backups destroyed (each copy listed above) | A+B | ☐ | | | |
| **Approved erasure method applied (D7b)** | A+B | ☐ | | | name the method |
| **Storage searched for every session and participant ID - zero hits** | A+B | ☐ | | | search command + result |
| Git history confirmed free of both categories | A+B | ☐ | | | |

**Deletion complete and verified:** `____________________`  Date: `__________`

If any row above is unchecked, deletion is **not** complete, regardless of what
the retention period says.

**Honest statement of what was achieved** (do not write "securely deleted"
unless the method actually supports it):

`<e.g. "Category B removed by deleting the encrypted container and destroying
its key; contents are unreadable. Category A paper forms shredded. No claim is
made that deleted blocks were physically overwritten on the SSD.">`
