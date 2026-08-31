"""Stage 0 rehearsal of the workspace cleanup step.

This proves the *procedure* runs before it is ever pointed at real material -
plan §5 Stage 0, "verify ... the deletion procedure end to end".

What this is not
----------------
**This is not secure erasure, and it must never be described as such.** It
removes directory entries. On the SSDs this project runs on, wear levelling,
over-provisioning and the drive's own block remapping mean the underlying data
may persist and is not reliably reachable - let alone overwritable - by any
file-level tool. Copy-on-write filesystems, snapshots and restore points can
retain independent copies. Plan §12.3 ranks the approaches that *are*
defensible; encryption with key destruction leads that list, and none of them
is implemented here.

Why this module takes no path
-----------------------------
Two designs were tried and rejected.

The first let the caller declare any directory a "workspace" and delete inside
it. Passing ``Path.home()`` made ``AppData`` and ``Documents`` legal targets.

The second required a marker file carrying a random token, and called that a
capability. **It was not one.** The marker lived entirely inside the directory
being checked, so it was self-authenticating: anyone able to create a directory
could equally create the marker, and a forged pair verified exactly like a real
one. That was demonstrated, not theorised - a forged directory passed
verification and its contents were accepted as a deletion target.

A token that travels with the thing it protects proves nothing about it. The
fix is not a better token: it is to stop accepting the question. **No function
here takes a filesystem path from a caller.** :func:`rehearse` creates its own
temporary directory, deletes that directory, and reports what it did. There is
no API - and no CLI flag - that will delete a path you name. The checks below
still run, as defence in depth, against a directory this module itself created
moments earlier.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from scripts.b18_stage0.workspace import (
    REPO_ROOT,
    WORKSPACE_PREFIX,
    WorkspaceError,
    contains_reparse_point,
    system_temp_root,
)

DISCLAIMER = (
    "Filesystem deletion is NOT proof of physical erasure. On SSDs, wear "
    "levelling and block remapping mean deleted data may persist beyond the "
    "reach of file-level tools. No secure-erasure claim is made."
)

#: Prefix for the throwaway directory a rehearsal creates and destroys.
REHEARSAL_PREFIX = "b18_stage0_rehearsal_"

USER_DATA_FOLDERS = (
    "AppData",
    "Documents",
    "Desktop",
    "Downloads",
    "Pictures",
    "Videos",
)


class UnsafeTarget(Exception):
    """A deletion was refused. Nothing was removed."""


def _redirection_roots(home: Path) -> set[Path]:
    """Roots that a cloud client may have redirected the known folders into.

    Windows known-folder redirection is the default on consumer Windows 11:
    ``Desktop``, ``Documents`` and ``Pictures`` commonly live under
    ``%USERPROFILE%/OneDrive`` and do **not** exist at ``home/<name>`` at all.
    Naming only the un-redirected paths would leave the guard listing folders
    that do not exist while missing the ones that do - verified on the machine
    this was written on, where ``home/Desktop`` is absent and
    ``home/OneDrive/Desktop`` holds the real files.

    Read from the environment rather than the registry: no system or security
    configuration is inspected or changed, and the behaviour stays testable by
    setting a variable.
    """
    roots: set[Path] = set()
    for variable in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        value = os.environ.get(variable, "").strip()
        if not value:
            continue
        candidate = Path(value)
        if candidate.is_absolute():
            roots.add(candidate)
    # Cover a client that did not export a variable, and the per-tenant
    # "OneDrive - Contoso" naming, without globbing outside the home directory.
    with contextlib.suppress(OSError):
        roots.update(child for child in home.iterdir() if child.name.startswith("OneDrive"))
    return {root.resolve() for root in roots}


def _forbidden_paths() -> set[Path]:
    """Paths that must never be deleted, whatever else is true.

    Defence in depth. The primary protection is that no caller can name a path
    at all; this list exists so that a future refactor reintroducing a path
    argument still cannot reach anything that matters.
    """
    home = Path.home().resolve()
    forbidden = {REPO_ROOT, home, Path.cwd().resolve(), system_temp_root()}
    forbidden |= set(REPO_ROOT.parents)
    forbidden |= set(home.parents)
    for root in {home, *_redirection_roots(home)}:
        forbidden.add(root)
        forbidden |= set(root.parents)
        for name in USER_DATA_FOLDERS:
            forbidden.add(root / name)
    return forbidden


def _assert_disposable(target: Path, created: Path) -> Path:
    """Vet a directory this module created moments ago, before removing it.

    ``created`` is the directory :func:`rehearse` made in this same call. It is
    not caller input, and this function is private precisely so that it cannot
    quietly become caller input again.
    """
    if contains_reparse_point(target) is not None:
        raise UnsafeTarget(f"refusing a symlink, junction or reparse point at or below: {target}")

    resolved = target.resolve()
    if not resolved.is_absolute():
        raise UnsafeTarget(f"refusing a non-absolute target: {target}")
    if resolved == resolved.anchor or resolved.parent == resolved:
        raise UnsafeTarget(f"refusing a filesystem root: {resolved}")
    if resolved in _forbidden_paths():
        raise UnsafeTarget(
            f"refusing a protected path (repository, home, a user data folder "
            f"including its cloud-redirected location, cwd, the temp root, or an "
            f"ancestor of one): {resolved}"
        )
    if resolved == REPO_ROOT or REPO_ROOT in resolved.parents:
        raise UnsafeTarget(f"refusing a target inside the repository: {resolved}")
    if system_temp_root() not in resolved.parents:
        raise UnsafeTarget(f"refusing a target outside the system temp root: {resolved}")
    if not resolved.name.startswith((REHEARSAL_PREFIX, WORKSPACE_PREFIX)):
        raise UnsafeTarget(f"refusing a directory this tool did not create: {resolved}")
    if resolved != created.resolve():
        raise UnsafeTarget(
            f"refusing {resolved}: a rehearsal may only delete the directory it "
            f"created during this same call ({created.resolve()})"
        )
    if not resolved.exists():
        raise UnsafeTarget(f"refusing a target that does not exist: {resolved}")
    if not resolved.is_dir():
        raise UnsafeTarget(f"refusing a non-directory target: {resolved}")
    return resolved


def rehearse() -> dict[str, Any]:
    """Create a throwaway directory, delete it, and report what happened.

    Takes no arguments by design: there is no path a caller can supply, so there
    is no path a caller can have deleted. The contents are synthetic files this
    function writes itself - never a manifest, never a real record.
    """
    created = Path(tempfile.mkdtemp(prefix=REHEARSAL_PREFIX))
    written: list[str] = []
    try:
        (created / "nested").mkdir()
        for relative, body in (
            ("placeholder.json", '{"note": "synthetic Stage 0 rehearsal placeholder"}\n'),
            ("nested/placeholder.txt", "synthetic Stage 0 rehearsal content\n"),
        ):
            (created / relative).write_text(body, encoding="utf-8", newline="\n")
            written.append(relative)

        target = _assert_disposable(created, created)
        removed = sorted(
            str(path.relative_to(target)).replace("\\", "/") for path in target.rglob("*")
        )
        shutil.rmtree(target)
        return {
            "rehearsal": "stage0-cleanup",
            "created_under_system_temp": True,
            "files_created": sorted(written),
            "entries_removed": removed,
            "directory_removed": not target.exists(),
            "caller_supplied_path": None,
            "accepts_caller_path": False,
            "secure_erasure": False,
            "disclaimer": DISCLAIMER,
        }
    finally:
        # A failure anywhere above must not leave the throwaway behind.
        if created.exists():
            shutil.rmtree(created, ignore_errors=True)


def rehearsal_report(record: dict[str, Any]) -> str:
    """Render a rehearsal record for a human, disclaimer included."""
    lines = [
        "B18 Stage 0 - cleanup procedure rehearsal",
        "",
        f"  directory removed : {record['directory_removed']}",
        f"  entries removed   : {len(record['entries_removed'])}",
        f"  caller path used  : {record['caller_supplied_path']}",
        "",
        DISCLAIMER,
    ]
    return "\n".join(lines) + "\n"


__all__ = [
    "DISCLAIMER",
    "REHEARSAL_PREFIX",
    "USER_DATA_FOLDERS",
    "UnsafeTarget",
    "WorkspaceError",
    "rehearsal_report",
    "rehearse",
]
