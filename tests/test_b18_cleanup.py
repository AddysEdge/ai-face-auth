"""Behavioural tests for Stage 0 output safety and the cleanup rehearsal.

**No destructive call in this file targets a real user directory.** The cleanup
API takes no path at all, so there is nothing to point anywhere; the tests that
exercise the defence-in-depth checks pass directories the test itself created
under ``tmp_path`` or the system temp root, and assert both that the call raises
and that the path still exists afterwards.
"""

from __future__ import annotations

import inspect
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
    REHEARSAL_PREFIX,
    UnsafeTarget,
    rehearsal_report,
    rehearse,
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

    Teardown is done test-side, guarded so it can only ever remove a directory
    this fixture created under the temp root.
    """
    path = create_workspace()
    yield path
    resolved = path.resolve()
    assert resolved.name.startswith("b18_stage0_"), resolved
    assert system_temp_root() in resolved.parents, resolved
    shutil.rmtree(resolved, ignore_errors=True)


def _write(tmp_path: Path, name: str, session) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(session), encoding="utf-8")
    return path


def _stage0_workspaces() -> set[str]:
    return {p.name for p in system_temp_root().iterdir() if p.name.startswith("b18_stage0_")}


def _marker_of_a_fresh_workspace() -> dict:
    path = create_workspace()
    try:
        return json.loads((path / MARKER_NAME).read_text(encoding="utf-8"))
    finally:
        shutil.rmtree(path, ignore_errors=True)


# =====================================================================
# REGRESSION (E): the cleanup API accepts no caller-supplied path at all
# =====================================================================


def test_no_public_cleanup_function_accepts_a_path():
    """The design requirement, asserted directly against the module.

    Both previous designs failed the same way: they accepted a path and then
    tried to decide whether it was safe. This pins the shape of the fix, so a
    change that reintroduces a path argument fails here rather than in review.
    """
    offenders = []
    for name in cleanup.__all__:
        attribute = getattr(cleanup, name)
        if not inspect.isfunction(attribute):
            continue
        for parameter in inspect.signature(attribute).parameters.values():
            annotation = str(parameter.annotation).lower()
            if "path" in annotation or "path" in parameter.name.lower():
                offenders.append(f"{name}({parameter.name})")
    assert not offenders, f"cleanup exposes path-taking function(s): {offenders}"


def test_the_removed_path_taking_api_is_gone():
    """The forgeable-capability API must not return under its old names."""
    for name in ("assert_safe_target", "remove_workspace", "remove_workspace_root"):
        assert not hasattr(cleanup, name), f"{name} still exists"


def test_rehearse_takes_no_arguments():
    assert list(inspect.signature(rehearse).parameters) == []


def test_a_forged_marker_grants_no_deletion():
    """REGRESSION: the marker was self-authenticating, and was forged.

    A directory plus a copied marker verified exactly like a real workspace, and
    its contents were then accepted as a deletion target. The forgery still
    passes the *structural* check - that is precisely the point, the marker never
    proved anything - but nothing destructive consults it any more, so forging
    one now buys nothing at all.
    """
    real = create_workspace()
    forged = system_temp_root() / "b18_stage0_forged_by_test"
    victim = forged / "victim"
    try:
        victim.mkdir(parents=True, exist_ok=True)
        (forged / MARKER_NAME).write_text(
            (real / MARKER_NAME).read_text(encoding="utf-8"), encoding="utf-8"
        )
        assert verify_workspace(forged) == forged.resolve()
        assert not hasattr(cleanup, "assert_safe_target")
        assert victim.is_dir(), "nothing may have removed the forged directory"
    finally:
        shutil.rmtree(forged, ignore_errors=True)
        shutil.rmtree(real, ignore_errors=True)


def test_the_marker_is_documented_as_not_a_capability():
    source = (REPO_ROOT / "scripts" / "b18_stage0" / "workspace.py").read_text(encoding="utf-8")
    assert "not a capability" in source
    assert '"capability"' not in source


def test_the_marker_carries_a_nonce_not_a_capability():
    marker = _marker_of_a_fresh_workspace()
    assert "capability" not in marker
    assert len(marker["nonce"]) == 32
    bytes.fromhex(marker["nonce"])


# =====================================================================
# The rehearsal itself
# =====================================================================


def test_rehearse_creates_and_removes_its_own_directory():
    record = rehearse()
    assert record["directory_removed"] is True
    assert record["caller_supplied_path"] is None
    assert record["accepts_caller_path"] is False
    assert sorted(record["entries_removed"]) == [
        "nested", "nested/placeholder.txt", "placeholder.json",
    ]


def test_rehearse_leaves_nothing_behind():
    def rehearsal_dirs() -> set[str]:
        return {p.name for p in system_temp_root().iterdir()
                if p.name.startswith(REHEARSAL_PREFIX)}

    before = rehearsal_dirs()
    rehearse()
    assert rehearsal_dirs() == before, "a rehearsal must not leave its directory behind"


def test_the_record_refuses_to_claim_secure_erasure():
    record = rehearse()
    assert record["secure_erasure"] is False
    assert "NOT proof of physical erasure" in record["disclaimer"]
    assert "NOT proof of physical erasure" in rehearsal_report(record)


def test_two_rehearsals_do_not_collide():
    first, second = rehearse(), rehearse()
    assert first["directory_removed"] and second["directory_removed"]


def test_the_cli_rehearsal_takes_no_path(capsys):
    assert cli.main(["rehearse-cleanup"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "caller path used  : None" in out
    assert DISCLAIMER in out


def test_the_cli_rehearsal_rejects_a_path_argument():
    """There is no flag or positional naming something to delete."""
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["rehearse-cleanup", str(Path.home())])
    assert excinfo.value.code != 0
    assert Path.home().exists()


# =====================================================================
# Defence in depth: the private check still refuses everything dangerous
# =====================================================================


def test_a_home_data_folder_is_refused():
    target = Path.home() / "AppData"
    if not target.is_dir():
        pytest.skip("AppData does not exist on this machine")
    # Either refusal is correct: AppData also holds junctions ("Application
    # Data"), and the reparse-point check runs first.
    with pytest.raises(UnsafeTarget, match="protected path|reparse point"):
        cleanup._assert_disposable(target, target)
    assert target.is_dir(), "a refused target must still exist"


def test_the_repository_is_refused():
    with pytest.raises(UnsafeTarget):
        cleanup._assert_disposable(REPO_ROOT, REPO_ROOT)
    assert REPO_ROOT.is_dir()


def test_a_directory_outside_the_temp_root_is_refused(tmp_path):
    outsider = tmp_path / "elsewhere"
    outsider.mkdir()
    with pytest.raises(UnsafeTarget, match="outside the system temp root|did not create"):
        cleanup._assert_disposable(outsider, outsider)
    assert outsider.is_dir()


def test_a_temp_directory_this_tool_did_not_create_is_refused():
    stranger = system_temp_root() / "not_a_stage0_directory_test"
    stranger.mkdir(exist_ok=True)
    try:
        with pytest.raises(UnsafeTarget, match="did not create"):
            cleanup._assert_disposable(stranger, stranger)
        assert stranger.is_dir()
    finally:
        shutil.rmtree(stranger, ignore_errors=True)


def test_a_directory_other_than_the_one_created_is_refused():
    """Even a correctly-prefixed sibling is refused: only *this call's* directory."""
    mine = system_temp_root() / f"{REHEARSAL_PREFIX}mine_test"
    other = system_temp_root() / f"{REHEARSAL_PREFIX}other_test"
    mine.mkdir(exist_ok=True)
    other.mkdir(exist_ok=True)
    try:
        with pytest.raises(UnsafeTarget, match="same call"):
            cleanup._assert_disposable(other, mine)
        assert other.is_dir()
    finally:
        shutil.rmtree(mine, ignore_errors=True)
        shutil.rmtree(other, ignore_errors=True)


def test_a_filesystem_root_is_refused():
    root = Path(Path.cwd().anchor)
    with pytest.raises(UnsafeTarget):
        cleanup._assert_disposable(root, root)
    assert root.exists()


def test_a_symlinked_target_is_refused(tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    link = system_temp_root() / f"{REHEARSAL_PREFIX}link_test"
    try:
        link.symlink_to(victim, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating a symlink needs privileges unavailable here")
    try:
        with pytest.raises(UnsafeTarget, match="symlink, junction or reparse point"):
            cleanup._assert_disposable(link, link)
        assert victim.is_dir(), "the symlink target must be untouched"
    finally:
        link.unlink(missing_ok=True)


def test_a_reparse_point_nested_inside_the_target_is_refused(tmp_path):
    """The scan is recursive: a link *below* the target redirects just as well."""
    victim = tmp_path / "victim"
    victim.mkdir()
    holder = system_temp_root() / f"{REHEARSAL_PREFIX}nested_test"
    holder.mkdir(exist_ok=True)
    nested = holder / "inner"
    try:
        nested.symlink_to(victim, target_is_directory=True)
    except (OSError, NotImplementedError):
        shutil.rmtree(holder, ignore_errors=True)
        pytest.skip("creating a symlink needs privileges unavailable here")
    try:
        with pytest.raises(UnsafeTarget, match="symlink, junction or reparse point"):
            cleanup._assert_disposable(holder, holder)
        assert victim.is_dir(), "the symlink target must be untouched"
    finally:
        nested.unlink(missing_ok=True)
        shutil.rmtree(holder, ignore_errors=True)


def test_redirected_data_folders_are_forbidden(tmp_path, monkeypatch):
    """REGRESSION: `home/Documents` may not be where Documents actually lives."""
    redirected = tmp_path / "OneDrive"
    (redirected / "Documents").mkdir(parents=True)
    monkeypatch.setenv("OneDrive", str(redirected))
    assert redirected / "Documents" in cleanup._forbidden_paths()
    assert (redirected / "Documents").is_dir()


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
    assert Path.home() in forbidden
    assert Path("relative/path").resolve() not in forbidden


def test_the_real_data_folders_on_this_machine_are_refused():
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
                cleanup._assert_disposable(target, target)
            assert target.is_dir(), f"a refused target must still exist: {target}"
    assert checked, "expected at least one real user data folder to check"


# =====================================================================
# REGRESSION (G): invalid input must not create an output workspace
# =====================================================================


def test_invalid_input_publishes_no_workspace(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"nope": 1}', encoding="utf-8")
    before = _stage0_workspaces()
    assert cli.main(["analyse", str(bad)]) == cli.EXIT_INVALID
    assert _stage0_workspaces() == before, (
        "an invalid run must leave no workspace behind: an empty workspace is "
        "indistinguishable from a run that produced nothing"
    )


def test_an_unaggregatable_corpus_publishes_no_workspace(tmp_path, capsys):
    manifest = _write(tmp_path, "a.json", session_one())
    before = _stage0_workspaces()
    assert cli.main(["analyse", str(manifest), str(manifest)]) == cli.EXIT_INVALID
    assert _stage0_workspaces() == before
    assert "cannot legitimately be aggregated" in capsys.readouterr().err


def test_an_unreadable_file_publishes_no_workspace(tmp_path):
    before = _stage0_workspaces()
    assert cli.main(["analyse", str(tmp_path / "missing.json")]) == cli.EXIT_USAGE
    assert _stage0_workspaces() == before


def test_a_valid_run_publishes_exactly_one_workspace(tmp_path, capsys):
    manifests = [
        _write(tmp_path, "a.json", session_one()),
        _write(tmp_path, "b.json", session_two()),
    ]
    before = _stage0_workspaces()
    assert cli.main(["analyse", *map(str, manifests)]) == cli.EXIT_OK
    created = _stage0_workspaces() - before
    assert len(created) == 1
    published = system_temp_root() / created.pop()
    try:
        run = published / "run-0001"
        assert (run / "results.json").is_file()
        assert (run / "report.md").is_file()
    finally:
        shutil.rmtree(published, ignore_errors=True)


# =====================================================================
# Output destination safety and determinism
# =====================================================================


def test_the_cli_no_longer_accepts_arbitrary_output_paths(tmp_path):
    manifest = _write(tmp_path, "a.json", session_one())
    for flag in ("--out", "--report", "--workspace"):
        with pytest.raises(SystemExit) as excinfo:
            cli.main(["analyse", str(manifest), flag, str(tmp_path / "x")])
        assert excinfo.value.code != 0, f"{flag} must not be accepted"


def test_no_source_file_is_touched_by_a_run(tmp_path):
    pyproject = REPO_ROOT / "pyproject.toml"
    before_bytes = pyproject.read_bytes()
    manifests = [
        _write(tmp_path, "a.json", session_one()),
        _write(tmp_path, "b.json", session_two()),
    ]
    before = _stage0_workspaces()
    assert cli.main(["analyse", *map(str, manifests)]) == cli.EXIT_OK
    for name in _stage0_workspaces() - before:
        shutil.rmtree(system_temp_root() / name, ignore_errors=True)
    assert pyproject.read_bytes() == before_bytes


def test_a_second_run_never_overwrites_the_first(workspace):
    first = next_run_directory(workspace)
    first.mkdir()
    second = next_run_directory(workspace)
    assert second != first
    assert second.name == "run-0002"


def test_next_run_directory_requires_a_verified_workspace(tmp_path):
    with pytest.raises(WorkspaceError):
        next_run_directory(tmp_path)


def test_repeated_runs_produce_byte_identical_artifacts(tmp_path):
    """REGRESSION (H): the same corpus must render identically every time."""
    manifests = [
        _write(tmp_path, "a.json", session_one()),
        _write(tmp_path, "b.json", session_two()),
    ]
    before = _stage0_workspaces()
    try:
        for _ in range(2):
            assert cli.main(["analyse", *map(str, manifests)]) == cli.EXIT_OK
        created = sorted(_stage0_workspaces() - before)
        assert len(created) == 2
        outputs = []
        for name in created:
            run = system_temp_root() / name / "run-0001"
            outputs.append((
                (run / "results.json").read_bytes(),
                (run / "report.md").read_bytes(),
            ))
        assert outputs[0][0] == outputs[1][0], "results.json is not deterministic"
        assert outputs[0][1] == outputs[1][1], "report.md is not deterministic"
    finally:
        for name in _stage0_workspaces() - before:
            shutil.rmtree(system_temp_root() / name, ignore_errors=True)


def test_stage0_tooling_opens_no_socket(tmp_path, monkeypatch):
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("Stage 0 tooling must not open a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    manifests = [
        _write(tmp_path, "a.json", session_one()),
        _write(tmp_path, "b.json", session_two()),
    ]
    before = _stage0_workspaces()
    assert cli.main(["analyse", *map(str, manifests)]) == cli.EXIT_OK
    for name in _stage0_workspaces() - before:
        shutil.rmtree(system_temp_root() / name, ignore_errors=True)
