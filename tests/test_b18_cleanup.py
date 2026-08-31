"""Behavioural tests for Stage 0 workspace safety, cleanup and output publishing.

**No destructive call in this file targets a real user directory.** Every
deletion operates on a workspace created for the test. The refusal tests point
the validators at protected paths - including `AppData` and `Documents`, which
an earlier revision wrongly accepted - and assert both that the call raises and
that the path still exists afterwards.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.b18_stage0 import cleanup, cli  # noqa: E402
from scripts.b18_stage0.cleanup import (  # noqa: E402
    DISCLAIMER,
    UnsafeTarget,
    assert_safe_target,
    remove_workspace,
    remove_workspace_root,
)
from scripts.b18_stage0.synthetic import session_one, session_two  # noqa: E402
from scripts.b18_stage0.workspace import (  # noqa: E402
    MARKER_NAME,
    WorkspaceError,
    create_workspace,
    next_run_directory,
    system_temp_root,
    verify_workspace,
)


@pytest.fixture
def workspace():
    """A real tool-created workspace, disposed of afterwards.

    Teardown deliberately does NOT use ``remove_workspace_root``: several tests
    corrupt the marker on purpose, and the production API would then - correctly
    - refuse to touch it. Cleanup is done test-side instead, guarded so it can
    only ever remove a directory this fixture created under the temp root.
    """
    path = create_workspace()
    yield path
    resolved = path.resolve()
    assert resolved.name.startswith("b18_stage0_"), resolved
    assert system_temp_root() in resolved.parents, resolved
    shutil.rmtree(resolved, ignore_errors=True)


@pytest.fixture
def populated(workspace):
    run = workspace / "run-0001"
    (run / "nested").mkdir(parents=True)
    (run / "results.json").write_text("{}", encoding="utf-8")
    (run / "nested" / "report.md").write_text("# synthetic", encoding="utf-8")
    return workspace, run


# ------------------------------------------------------- workspace identity


def test_a_created_workspace_verifies(workspace):
    assert verify_workspace(workspace) == workspace.resolve()
    assert (workspace / MARKER_NAME).is_file()


def test_the_marker_carries_a_capability_token(workspace):
    marker = json.loads((workspace / MARKER_NAME).read_text(encoding="utf-8"))
    assert marker["tool"] == "scripts.b18_stage0"
    assert len(marker["capability"]) == 32
    bytes.fromhex(marker["capability"])


def test_two_workspaces_get_different_capabilities():
    first, second = create_workspace(), create_workspace()
    try:
        a = json.loads((first / MARKER_NAME).read_text(encoding="utf-8"))["capability"]
        b = json.loads((second / MARKER_NAME).read_text(encoding="utf-8"))["capability"]
        assert a != b
    finally:
        shutil.rmtree(first, ignore_errors=True)
        shutil.rmtree(second, ignore_errors=True)


# ------------------------- REGRESSION: a caller cannot declare a workspace


def test_the_home_directory_is_not_a_workspace():
    """The exact hole: home as workspace_root made AppData a legal target."""
    with pytest.raises(WorkspaceError):
        verify_workspace(Path.home())
    assert Path.home().exists()


@pytest.mark.parametrize("name", ["AppData", "Documents"])
def test_home_data_folders_are_refused_and_not_deleted(name):
    target = Path.home() / name
    if not target.is_dir():
        pytest.skip(f"{name} does not exist on this machine")
    with pytest.raises(UnsafeTarget):
        assert_safe_target(target, Path.home())
    assert target.is_dir(), "a refused target must still exist"


def test_a_verified_workspace_still_cannot_reach_a_home_data_folder(workspace):
    """Exercise the protected-path branch itself.

    Passing ``Path.home()`` as the workspace fails at workspace verification, so
    it never reaches the forbidden-path check. A *verified* workspace with a
    protected target does.
    """
    target = Path.home() / "AppData"
    if not target.is_dir():
        pytest.skip("AppData does not exist on this machine")
    # Either refusal is correct: AppData also holds junctions ("Application
    # Data"), and the reparse-point check runs first.
    with pytest.raises(UnsafeTarget, match="protected path|reparse point"):
        assert_safe_target(target, workspace)
    assert target.is_dir(), "a refused target must still exist"


# --------------------------- REGRESSION: cloud-redirected known folders
#
# Found during final verification: on this machine ``home/Desktop`` and
# ``home/Pictures`` do not exist, because Windows known-folder redirection -
# the consumer Windows 11 default - moved them under ``home/OneDrive``. A guard
# naming only ``home/<name>`` therefore listed folders that do not exist while
# missing the ones that hold the real files.


def test_redirected_data_folders_are_forbidden(tmp_path, monkeypatch, workspace):
    """A redirected Documents folder is protected, not just ``home/Documents``."""
    redirected = tmp_path / "OneDrive"
    (redirected / "Documents").mkdir(parents=True)
    monkeypatch.setenv("OneDrive", str(redirected))

    assert redirected / "Documents" in cleanup._forbidden_paths()
    with pytest.raises(UnsafeTarget, match="protected path"):
        assert_safe_target(redirected / "Documents", workspace)
    assert (redirected / "Documents").is_dir(), "a refused target must still exist"


def test_the_redirection_root_and_its_ancestors_are_forbidden(tmp_path, monkeypatch):
    redirected = tmp_path / "OneDrive"
    redirected.mkdir()
    monkeypatch.setenv("OneDrive", str(redirected))

    forbidden = cleanup._forbidden_paths()
    assert redirected in forbidden
    assert tmp_path in forbidden, "an ancestor of a redirection root must be protected"


@pytest.mark.parametrize("variable", ["OneDriveConsumer", "OneDriveCommercial"])
def test_every_onedrive_variable_is_honoured(tmp_path, monkeypatch, variable):
    redirected = tmp_path / variable
    (redirected / "Desktop").mkdir(parents=True)
    for name in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(variable, str(redirected))

    assert redirected / "Desktop" in cleanup._forbidden_paths()


def test_a_relative_or_empty_variable_is_ignored_without_crashing(monkeypatch):
    monkeypatch.setenv("OneDrive", "   ")
    monkeypatch.setenv("OneDriveConsumer", "relative/path")
    forbidden = cleanup._forbidden_paths()
    assert Path.home() in forbidden, "the guard must still work"
    assert Path("relative/path").resolve() not in forbidden


def test_the_real_redirected_folders_on_this_machine_are_refused(workspace):
    """Whatever this machine's actual layout is, its real data folders are safe."""
    home = Path.home().resolve()
    roots = [home, *sorted(cleanup._redirection_roots(home))]
    checked = 0
    for root in roots:
        for name in cleanup.USER_DATA_FOLDERS:
            target = root / name
            if not target.is_dir():
                continue
            checked += 1
            with pytest.raises(UnsafeTarget, match="protected path|reparse point"):
                assert_safe_target(target, workspace)
            assert target.is_dir(), f"a refused target must still exist: {target}"
    assert checked, "expected at least one real user data folder to check"


def test_the_repository_is_not_a_workspace():
    with pytest.raises(WorkspaceError):
        verify_workspace(REPO_ROOT)
    assert REPO_ROOT.exists()


def test_a_plain_temp_directory_without_a_marker_is_refused(tmp_path):
    with pytest.raises(WorkspaceError, match="prefix|marker"):
        verify_workspace(tmp_path)
    assert tmp_path.exists()


def test_a_directory_outside_the_system_temp_root_is_refused(tmp_path, workspace):
    """Even a valid marker cannot make an arbitrary location a workspace."""
    impostor = REPO_ROOT / "b18_stage0_impostor"
    impostor.mkdir(exist_ok=True)
    try:
        (impostor / MARKER_NAME).write_text(
            (workspace / MARKER_NAME).read_text(encoding="utf-8"), encoding="utf-8"
        )
        with pytest.raises(WorkspaceError):
            verify_workspace(impostor)
        assert impostor.exists()
    finally:
        for child in impostor.iterdir():
            child.unlink()
        impostor.rmdir()


# ----------------------------------------- REGRESSION: marker validation


def test_a_missing_marker_is_refused(workspace):
    (workspace / MARKER_NAME).unlink()
    with pytest.raises(WorkspaceError, match="missing"):
        verify_workspace(workspace)


def test_a_malformed_marker_is_refused(workspace):
    (workspace / MARKER_NAME).write_text("not json", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="malformed"):
        verify_workspace(workspace)


def test_a_marker_from_another_tool_is_refused(workspace):
    (workspace / MARKER_NAME).write_text(
        json.dumps({"tool": "something_else", "capability": "0" * 32}), encoding="utf-8"
    )
    with pytest.raises(WorkspaceError, match="tool"):
        verify_workspace(workspace)


@pytest.mark.parametrize("capability", ["", "short", "z" * 32, None, 12345])
def test_a_malformed_capability_is_refused(workspace, capability):
    marker = json.loads((workspace / MARKER_NAME).read_text(encoding="utf-8"))
    marker["capability"] = capability
    (workspace / MARKER_NAME).write_text(json.dumps(marker), encoding="utf-8")
    with pytest.raises(WorkspaceError, match="capability"):
        verify_workspace(workspace)


# ----------------------------------------------------------- deletion


def test_a_run_directory_inside_a_workspace_is_removed(populated):
    workspace, run = populated
    record = remove_workspace(run, workspace)
    assert not run.exists()
    assert workspace.exists(), "only the run directory should have gone"
    assert record["verified_absent"] is True
    assert record["files_removed"] == 2
    assert record["entries_removed"] == ["nested/report.md", "results.json"]


def test_the_record_refuses_to_claim_secure_erasure(populated):
    workspace, run = populated
    record = remove_workspace(run, workspace)
    assert record["secure_erasure_claimed"] is False
    assert "NOT proof of physical erasure" in record["disclaimer"]
    assert "SSD" in DISCLAIMER


def test_removing_the_root_requires_the_explicit_api(populated):
    workspace, _ = populated
    with pytest.raises(UnsafeTarget, match="remove_workspace_root"):
        remove_workspace(workspace, workspace)
    assert workspace.exists()

    record = remove_workspace_root(workspace)
    assert not workspace.exists()
    assert record["secure_erasure_claimed"] is False


# ----------------------------------------------------------- refusals


def test_a_target_outside_the_workspace_is_refused_and_kept(tmp_path, workspace):
    outsider = tmp_path / "somewhere_else"
    outsider.mkdir()
    (outsider / "keep.txt").write_text("synthetic", encoding="utf-8")
    with pytest.raises(UnsafeTarget, match="outside the verified workspace"):
        remove_workspace(outsider, workspace)
    assert (outsider / "keep.txt").exists()


def test_a_traversal_target_is_refused(tmp_path, workspace):
    escape = tmp_path / "escape_me"
    escape.mkdir()
    with pytest.raises(UnsafeTarget):
        assert_safe_target(workspace / ".." / "escape_me", workspace)
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
    elsewhere = tmp_path / "precious"
    elsewhere.mkdir()
    (elsewhere / "keep.txt").write_text("synthetic", encoding="utf-8")
    link = workspace / "looks_local"
    try:
        link.symlink_to(elsewhere, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation requires privileges not available here")
    with pytest.raises(UnsafeTarget, match="symlink, junction or reparse point"):
        assert_safe_target(link, workspace)
    assert (elsewhere / "keep.txt").exists()


def test_a_symlink_nested_inside_the_workspace_blocks_verification(tmp_path, workspace):
    """A link below the root could redirect a recursive delete."""
    elsewhere = tmp_path / "precious2"
    elsewhere.mkdir()
    nested = workspace / "run-0001"
    nested.mkdir()
    try:
        (nested / "sneaky").symlink_to(elsewhere, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation requires privileges not available here")
    with pytest.raises(WorkspaceError, match="reparse point"):
        verify_workspace(workspace)
    assert elsewhere.exists()


def test_remove_workspace_refuses_before_deleting_anything(tmp_path, workspace):
    outsider = tmp_path / "not_mine"
    outsider.mkdir()
    (outsider / "file.txt").write_text("synthetic", encoding="utf-8")
    with pytest.raises(UnsafeTarget):
        remove_workspace(outsider, workspace)
    assert (outsider / "file.txt").exists()


def test_an_unverifiable_workspace_makes_every_target_unsafe(tmp_path):
    target = tmp_path / "child"
    target.mkdir()
    with pytest.raises(UnsafeTarget, match="not a tool-created"):
        remove_workspace(target, tmp_path)
    assert target.exists()


# ------------------------------- REGRESSION: output destination safety


def _write(tmp_path: Path, name: str, session) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(session), encoding="utf-8")
    return path


def test_the_cli_no_longer_accepts_arbitrary_output_paths(tmp_path):
    """`--out pyproject.toml` was accepted once; the option is gone."""
    manifest = _write(tmp_path, "a.json", session_one())
    with pytest.raises(SystemExit):
        cli.main(["analyse", str(manifest), "--out", "pyproject.toml"])
    with pytest.raises(SystemExit):
        cli.main(["analyse", str(manifest), "--report", str(tmp_path / "r.md")])


def test_analyse_publishes_into_a_fresh_run_directory(tmp_path, workspace, capsys):
    manifests = [_write(tmp_path, "a.json", session_one()),
                 _write(tmp_path, "b.json", session_two())]
    assert cli.main(["analyse", *map(str, manifests), "--workspace", str(workspace)]) == 0
    run = workspace / "run-0001"
    assert (run / "results.json").is_file()
    assert (run / "report.md").is_file()
    assert "published" in capsys.readouterr().out


def test_a_second_run_never_overwrites_the_first(tmp_path, workspace):
    manifest = _write(tmp_path, "a.json", session_one())
    for expected in ("run-0001", "run-0002"):
        assert cli.main(["analyse", str(manifest), "--workspace", str(workspace)]) == 0
        assert (workspace / expected / "results.json").is_file()
    first = (workspace / "run-0001" / "results.json").read_bytes()
    second = (workspace / "run-0002" / "results.json").read_bytes()
    assert first == second, "same input, so identical content - in separate runs"


def test_the_cli_refuses_a_workspace_it_did_not_create(tmp_path):
    manifest = _write(tmp_path, "a.json", session_one())
    assert cli.main(["analyse", str(manifest), "--workspace", str(tmp_path)]) == cli.EXIT_USAGE


def test_the_cli_refuses_the_repository_as_a_workspace(tmp_path, capsys):
    manifest = _write(tmp_path, "a.json", session_one())
    assert cli.main(["analyse", str(manifest), "--workspace", str(REPO_ROOT)]) == cli.EXIT_USAGE
    assert "workspace" in capsys.readouterr().err


def test_no_source_file_is_touched_by_a_run(tmp_path, workspace):
    """Nothing outside the workspace may be written."""
    before = (REPO_ROOT / "pyproject.toml").read_bytes()
    manifest = _write(tmp_path, "a.json", session_one())
    assert cli.main(["analyse", str(manifest), "--workspace", str(workspace)]) == 0
    assert (REPO_ROOT / "pyproject.toml").read_bytes() == before


def test_an_invalid_manifest_publishes_no_run(tmp_path, workspace):
    """A half-published run would look like a completed result."""
    session = session_one()
    session["participant_id"] = "Alex"
    manifest = _write(tmp_path, "bad.json", session)
    assert cli.main(["analyse", str(manifest), "--workspace", str(workspace)]) == cli.EXIT_INVALID
    assert not list(workspace.glob("run-*"))
    assert not list(workspace.glob("*.staging"))


def test_an_unaggregatable_corpus_publishes_no_run(tmp_path, workspace, capsys):
    manifest = _write(tmp_path, "a.json", session_one())
    assert cli.main(
        ["analyse", str(manifest), str(manifest), "--workspace", str(workspace)]
    ) == cli.EXIT_INVALID
    assert "cannot legitimately be aggregated" in capsys.readouterr().err
    assert not list(workspace.glob("run-*"))
    assert not list(workspace.glob("*.staging"))


def test_next_run_directory_requires_a_verified_workspace(tmp_path):
    with pytest.raises(WorkspaceError):
        next_run_directory(tmp_path)


def test_repeated_runs_produce_byte_identical_artifacts(tmp_path, workspace):
    manifests = [_write(tmp_path, "a.json", session_one()),
                 _write(tmp_path, "b.json", session_two())]
    for _ in range(2):
        assert cli.main(["analyse", *map(str, manifests), "--workspace", str(workspace)]) == 0
    first_run, second_run = workspace / "run-0001", workspace / "run-0002"
    assert (first_run / "results.json").read_bytes() == (second_run / "results.json").read_bytes()
    assert (first_run / "report.md").read_bytes() == (second_run / "report.md").read_bytes()


def test_stage0_tooling_opens_no_socket(tmp_path, workspace, monkeypatch):
    """B17 made the runtime network-silent; Stage 0 tooling must be too."""
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("Stage 0 tooling attempted network access")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)

    manifest = _write(tmp_path, "a.json", session_one())
    assert cli.main(["validate", str(manifest)]) == 0
    assert cli.main(["analyse", str(manifest), "--workspace", str(workspace)]) == 0
