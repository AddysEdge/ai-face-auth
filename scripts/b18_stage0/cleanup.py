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

The safety model
----------------
An earlier revision let the caller declare any directory a "workspace" and then
delete inside it. Passing ``Path.home()`` therefore made ``AppData`` and
``Documents`` legal targets - a real defect, reproduced before this rewrite.

Deletion is now **capability-based**, not argument-based. The only thing that
can be removed is a directory this tool created beneath the system temporary
directory, carrying the marker and capability token that
:mod:`scripts.b18_stage0.workspace` wrote. No string a caller passes can
manufacture that. A path outside such a workspace is refused whatever
``workspace_root`` is claimed alongside it.
"""

from __future__ import annotations

import contextlib
import os
import shutil
from pathlib import Path
from typing import Any

from scripts.b18_stage0.workspace import (
    REPO_ROOT,
    WorkspaceError,
    contains_reparse_point,
    system_temp_root,
    verify_workspace,
)

DISCLAIMER = (
    "Filesystem deletion is NOT proof of physical erasure. On SSDs, wear "
    "levelling and block remapping mean deleted data may persist beyond the "
    "reach of file-level tools. No secure-erasure claim is made."
)


class UnsafeTarget(Exception):
    """The requested deletion target was refused. Nothing was removed."""


USER_DATA_FOLDERS = (
    "AppData",
    "Documents",
    "Desktop",
    "Downloads",
    "Pictures",
    "Videos",
)


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
    """Paths that must never be a deletion target, whatever a caller passes."""
    home = Path.home().resolve()
    forbidden = {REPO_ROOT, home, Path.cwd().resolve(), system_temp_root()}
    forbidden |= set(REPO_ROOT.parents)
    forbidden |= set(home.parents)
    # Named explicitly because these were the paths the previous model accepted.
    for root in {home, *_redirection_roots(home)}:
        forbidden.add(root)
        forbidden |= set(root.parents)
        for name in USER_DATA_FOLDERS:
            forbidden.add(root / name)
    return forbidden


def assert_safe_target(target: Path, workspace: Path) -> Path:
    """Vet a deletion target against a tool-created workspace.

    ``workspace`` must pass :func:`verify_workspace` - it is not enough for the
    caller to say a directory is a workspace. ``target`` must then be a real
    directory strictly inside it, free of links at every level.
    """
    try:
        verified_workspace = verify_workspace(workspace)
    except WorkspaceError as exc:
        raise UnsafeTarget(
            f"refusing: {workspace} is not a tool-created Stage 0 workspace ({exc})"
        ) from exc

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
    if resolved == verified_workspace:
        raise UnsafeTarget(
            f"refusing the workspace root here; use remove_workspace_root() to "
            f"dispose of the whole workspace: {resolved}"
        )
    if verified_workspace not in resolved.parents:
        raise UnsafeTarget(
            f"refusing a target outside the verified workspace: {resolved} is not "
            f"inside {verified_workspace}"
        )
    if not resolved.exists():
        raise UnsafeTarget(f"refusing a target that does not exist: {resolved}")
    if not resolved.is_dir():
        raise UnsafeTarget(f"refusing a non-directory target: {resolved}")
    return resolved


def _record(resolved: Path, removed: list[str]) -> dict[str, Any]:
    return {
        "target": str(resolved),
        "files_removed": len(removed),
        "entries_removed": removed,
        "verified_absent": not resolved.exists(),
        "secure_erasure_claimed": False,
        "disclaimer": DISCLAIMER,
    }


def _entries(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root).as_posix()) for p in root.rglob("*") if p.is_file())


def remove_workspace(target: Path, workspace: Path) -> dict[str, Any]:
    """Remove a vetted directory *inside* a tool-created workspace."""
    resolved = assert_safe_target(target, workspace)
    removed = _entries(resolved)
    shutil.rmtree(resolved)
    return _record(resolved, removed)


def remove_workspace_root(workspace: Path) -> dict[str, Any]:
    """Dispose of an entire tool-created workspace.

    Separated from :func:`remove_workspace` deliberately: removing the root is a
    different, larger act than removing a run inside it, and the API says which
    one the caller meant rather than inferring it.
    """
    try:
        verified = verify_workspace(workspace)
    except WorkspaceError as exc:
        raise UnsafeTarget(
            f"refusing: {workspace} is not a tool-created Stage 0 workspace ({exc})"
        ) from exc
    if verified in _forbidden_paths():
        raise UnsafeTarget(f"refusing a protected path: {verified}")
    removed = _entries(verified)
    shutil.rmtree(verified)
    return _record(verified, removed)
