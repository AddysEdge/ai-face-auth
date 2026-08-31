"""Behavioural tests for the Stage 0 cleanup rehearsal.

Every destructive call in this file operates on a directory the test itself
created under pytest's ``tmp_path``. Nothing here touches project files, user
files, participant data, or runtime state - and the refusal tests assert
precisely that, by pointing the helper at protected paths and requiring it to
refuse *without* deleting.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.b18_stage0.cleanup import (  # noqa: E402
    DISCLAIMER,
    UnsafeTarget,
    assert_safe_target,
    remove_workspace,
)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A disposable Stage 0 workspace with a couple of synthetic artefacts."""
    root = tmp_path / "stage0_workspace"
    target = root / "session_run"
    (target / "nested").mkdir(parents=True)
    (target / "results.json").write_text("{}", encoding="utf-8")
    (target / "nested" / "report.md").write_text("# synthetic", encoding="utf-8")
    return root


# ------------------------------------------------------------- happy path


def test_a_workspace_subdirectory_is_removed(workspace):
    target = workspace / "session_run"
    assert target.exists()

    record = remove_workspace(target, workspace)

    assert not target.exists()
    assert record["verified_absent"] is True
    assert record["files_removed"] == 2
    assert record["entries_removed"] == ["nested/report.md", "results.json"] or \
        record["entries_removed"] == ["nested\\report.md", "results.json"]


def test_the_record_refuses_to_claim_secure_erasure(workspace):
    record = remove_workspace(workspace / "session_run", workspace)
    assert record["secure_erasure_claimed"] is False
    assert "NOT proof of physical erasure" in record["disclaimer"]
    assert "SSD" in DISCLAIMER


def test_removal_leaves_the_workspace_root_itself_intact(workspace):
    remove_workspace(workspace / "session_run", workspace)
    assert workspace.exists(), "only the subdirectory should have been removed"


# ------------------------------------------------------------- refusals
#
# Each of these must refuse AND leave the target untouched.


def test_the_repository_root_is_refused():
    with pytest.raises(UnsafeTarget, match="protected path|inside the repository"):
        assert_safe_target(REPO_ROOT, REPO_ROOT.parent)
    assert REPO_ROOT.exists()


def test_a_path_inside_the_repository_is_refused(tmp_path):
    inside = REPO_ROOT / "src"
    with pytest.raises(UnsafeTarget):
        assert_safe_target(inside, REPO_ROOT)
    assert inside.exists(), "the repository must be untouched"


def test_the_home_directory_is_refused():
    home = Path.home()
    with pytest.raises(UnsafeTarget, match="protected path"):
        assert_safe_target(home, home.parent)
    assert home.exists()


def test_a_filesystem_root_is_refused():
    anchor = Path(Path.cwd().anchor)
    with pytest.raises(UnsafeTarget):
        assert_safe_target(anchor, anchor)
    assert anchor.exists()


def test_the_workspace_root_itself_is_refused(workspace):
    """Deleting the root would remove the very thing scoping the operation."""
    with pytest.raises(UnsafeTarget, match="workspace root itself"):
        assert_safe_target(workspace, workspace)
    assert workspace.exists()


def test_a_target_outside_the_declared_workspace_is_refused(tmp_path, workspace):
    outsider = tmp_path / "somewhere_else"
    outsider.mkdir()
    with pytest.raises(UnsafeTarget, match="outside the declared workspace"):
        assert_safe_target(outsider, workspace)
    assert outsider.exists(), "a refused target must not be deleted"


def test_a_traversal_target_is_refused(tmp_path, workspace):
    """`workspace/../elsewhere` must not escape by string concatenation."""
    escape = tmp_path / "escape_me"
    escape.mkdir()
    traversal = workspace / ".." / "escape_me"
    with pytest.raises(UnsafeTarget, match="outside the declared workspace"):
        assert_safe_target(traversal, workspace)
    assert escape.exists()


def test_a_missing_target_is_refused(workspace):
    with pytest.raises(UnsafeTarget, match="does not exist"):
        assert_safe_target(workspace / "never_created", workspace)


def test_a_file_target_is_refused(workspace):
    a_file = workspace / "loose.txt"
    a_file.write_text("synthetic", encoding="utf-8")
    with pytest.raises(UnsafeTarget, match="non-directory"):
        assert_safe_target(a_file, workspace)
    assert a_file.exists()


def test_a_symlinked_target_is_refused(tmp_path, workspace):
    """A link inside the workspace must not redirect the delete elsewhere."""
    elsewhere = tmp_path / "precious"
    elsewhere.mkdir()
    (elsewhere / "keep.txt").write_text("synthetic", encoding="utf-8")

    link = workspace / "looks_local"
    try:
        link.symlink_to(elsewhere, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation requires privileges not available here")

    with pytest.raises(UnsafeTarget, match="symlink"):
        assert_safe_target(link, workspace)
    assert (elsewhere / "keep.txt").exists(), "the link target must be untouched"


def test_remove_workspace_refuses_before_deleting_anything(tmp_path, workspace):
    """The refusal happens in the same call that would otherwise delete."""
    outsider = tmp_path / "not_mine"
    outsider.mkdir()
    (outsider / "file.txt").write_text("synthetic", encoding="utf-8")

    with pytest.raises(UnsafeTarget):
        remove_workspace(outsider, workspace)

    assert (outsider / "file.txt").exists()
