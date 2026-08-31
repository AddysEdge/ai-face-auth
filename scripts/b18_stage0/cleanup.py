"""Stage 0 rehearsal of the workspace cleanup step.

This exists to prove the *procedure* runs before it is ever pointed at real
material - plan §5 Stage 0, "verify ... the deletion procedure end to end".

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

The guard rails below exist because a deletion helper is exactly the kind of
tool that, pointed at the wrong path once, destroys something irreplaceable.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

DISCLAIMER = (
    "Filesystem deletion is NOT proof of physical erasure. On SSDs, wear "
    "levelling and block remapping mean deleted data may persist beyond the "
    "reach of file-level tools. No secure-erasure claim is made."
)


class UnsafeTarget(Exception):
    """The requested deletion target was refused. Nothing was removed."""


def _forbidden_paths() -> set[Path]:
    """Paths that must never be a deletion target, whatever the caller passes."""
    forbidden = {REPO_ROOT, Path.home().resolve(), Path.cwd().resolve()}
    forbidden |= set(REPO_ROOT.parents)
    forbidden |= set(Path.home().resolve().parents)
    return forbidden


def assert_safe_target(target: Path, workspace_root: Path) -> Path:
    """Resolve and vet a deletion target. Raises rather than guessing.

    ``target`` must be a real directory strictly inside ``workspace_root``, and
    ``workspace_root`` must itself be somewhere disposable that the caller
    created. Symlinks are refused outright: following one would let a link
    inside the workspace redirect the delete anywhere on the machine.
    """
    if target.is_symlink():
        raise UnsafeTarget(f"refusing a symlink target: {target}")

    resolved = target.resolve()
    root = workspace_root.resolve()

    if not resolved.is_absolute():
        raise UnsafeTarget(f"refusing a non-absolute target: {target}")
    if resolved == resolved.anchor or resolved.parent == resolved:
        raise UnsafeTarget(f"refusing a filesystem root: {resolved}")
    if resolved in _forbidden_paths():
        raise UnsafeTarget(
            f"refusing a protected path (repository root, home, cwd or an "
            f"ancestor of one): {resolved}"
        )
    if resolved == root:
        raise UnsafeTarget(
            f"refusing the workspace root itself; delete a subdirectory of it: {resolved}"
        )
    if root not in resolved.parents:
        raise UnsafeTarget(
            f"refusing a target outside the declared workspace: {resolved} "
            f"is not inside {root}"
        )
    if resolved == REPO_ROOT or REPO_ROOT in resolved.parents:
        raise UnsafeTarget(f"refusing a target inside the repository: {resolved}")
    if not resolved.exists():
        raise UnsafeTarget(f"refusing a target that does not exist: {resolved}")
    if not resolved.is_dir():
        raise UnsafeTarget(f"refusing a non-directory target: {resolved}")
    return resolved


def remove_workspace(target: Path, workspace_root: Path) -> dict[str, Any]:
    """Remove a vetted Stage 0 workspace directory and report what happened.

    Returns a record suitable for pasting into
    ``docs/b18/forms/RETENTION_DELETION_LOG.md`` - including the honest
    statement about what deletion does and does not achieve.
    """
    resolved = assert_safe_target(target, workspace_root)

    removed = sorted(
        str(p.relative_to(resolved)) for p in resolved.rglob("*") if p.is_file()
    )
    shutil.rmtree(resolved)

    return {
        "target": str(resolved),
        "files_removed": len(removed),
        "entries_removed": removed,
        "verified_absent": not resolved.exists(),
        "secure_erasure_claimed": False,
        "disclaimer": DISCLAIMER,
    }
