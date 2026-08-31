# B18 retention and deletion log - TEMPLATE

> Opened at first capture, closed only when deletion is **verified**. Never
> commit a completed copy. Governed by decisions D6, D7, D9, D10.

**Retention period (D7):** `<e.g. 90 days after the B18 decision is recorded>`
**Storage location (D6):** `<path / device>`
**Access control (D6):** `<who, and how enforced>`
**Encryption (D6):** `<at rest: mechanism>`
**Backups (D7):** `<default proposal: NONE - every copy must be tracked below>`
**Raw frames permitted (D9):** `<default proposal: NO>`

---

## What exists

| Item | Location | Created | Contains | Copies |
|---|---|---|---|---|
| Session manifest `S01` | | `YYYY-MM-DD` | derived measurements, pseudonymous | 1 |
| Pseudonym mapping (if kept) | | | links `P__` to a person | 1 |
| Attack media (D10) | | | image of a real person | |
| Analysis intermediates | | | | |

## Withdrawals

| Participant | Requested | Deleted | Verified by | Notes |
|---|---|---|---|---|
| | | | | |

## Deletion record

Every step per plan §12.3. Deletion is not complete until **verified**.

| Step | Done | Date | By | Verification |
|---|---|---|---|---|
| Dataset directory removed | ☐ | | | |
| Analysis intermediates removed | ☐ | | | |
| Temporary / scratch files scrubbed | ☐ | | | |
| Pseudonym mapping destroyed | ☐ | | | |
| Attack media destroyed (D10) | ☐ | | | |
| Backups destroyed (each copy above) | ☐ | | | |
| Recycle bin emptied / secure-delete run | ☐ | | | |
| **Machine searched for every session ID - zero hits** | ☐ | | | search command + result |
| Git history confirmed free of participant data | ☐ | | | |

**Deletion complete and verified:** `____________________`  Date: `__________`

If any row above is unchecked, deletion is **not** complete, regardless of what
the retention period says.
