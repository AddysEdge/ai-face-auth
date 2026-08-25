"""Tests for the OS-level outbound-network regression check.

The check itself is in `scripts/check_network_activity.py`. These tests cover
its decision logic cheaply and deterministically, plus one slow end-to-end test
that actually runs the probe.

Why the logic tests matter as much as the end-to-end one: the failure mode this
check is most exposed to is not "it reports the wrong host", it is "it silently
observes nothing and reports PASS". See docs/PRIVACY_NETWORK_AUDIT.md section 4.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_network_activity.py"
ALLOWLIST = REPO_ROOT / "scripts" / "network_allowlist.json"
LANDMARKER = REPO_ROOT / "models" / "face_landmarker.task"


def _load_check_module():
    spec = importlib.util.spec_from_file_location("check_network_activity", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load_check_module()

windows_only = pytest.mark.skipif(
    sys.platform != "win32",
    reason="the check depends on Get-NetTCPConnection",
)


# --------------------------------------------------------------- allowlist


def test_allowlist_is_valid_json_with_the_expected_shape() -> None:
    data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    assert isinstance(data["allowed"], list)
    for entry in data["allowed"]:
        assert isinstance(entry["hostname"], str) and entry["hostname"]
        assert isinstance(entry["port"], int)
        # Every entry must carry its justification. An allowlist entry without
        # these is an undocumented exception, which is the thing this file
        # exists to prevent.
        for field in ("source", "trigger", "transmits", "opt_out", "documented_in"):
            assert entry[field], f"{entry['hostname']} is missing {field}"


def test_the_only_declared_destination_is_the_documented_mediapipe_endpoint() -> None:
    """A canary, not a rule.

    If a new destination is added, this test should fail and force whoever
    added it to say so out loud rather than quietly widening the allowlist.
    """
    data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    assert [(e["hostname"], e["port"]) for e in data["allowed"]] == [
        ("play.googleapis.com", 443)
    ]


def test_load_allowlist_matches_the_file() -> None:
    entries = check.load_allowlist()
    raw = json.loads(ALLOWLIST.read_text(encoding="utf-8"))["allowed"]
    assert entries == raw


# ------------------------------------------------------------ parsing logic


@windows_only
def test_outbound_connections_excludes_loopback_and_wildcard() -> None:
    """Loopback must never count: the native IPC transport is a local pipe."""
    for address in check.LOCAL_ADDRESSES:
        assert address in {"0.0.0.0", "::", "127.0.0.1", "::1"}


def test_dns_names_for_returns_empty_without_addresses() -> None:
    assert check.dns_names_for(set()) == {}


def test_dns_names_for_never_invents_a_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    """An IP with no cache entry stays unresolved rather than being guessed."""
    monkeypatch.setattr(
        check,
        "_powershell",
        lambda *_a, **_k: json.dumps([{"Entry": "example.test", "Data": "10.0.0.1"}]),
    )
    mapping = check.dns_names_for({"10.0.0.1", "10.0.0.2"})
    assert mapping == {"10.0.0.1": "example.test"}
    assert "10.0.0.2" not in mapping


def test_dns_names_for_survives_unparseable_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(check, "_powershell", lambda *_a, **_k: "not json at all")
    assert check.dns_names_for({"10.0.0.1"}) == {}


# ---------------------------------------------------------------- the probe


def test_child_source_reports_its_own_pid_first() -> None:
    """Guards the trampoline-venv bug described in the audit, section 4.

    Some virtualenv layouts launch the real interpreter as a separate process,
    so `Popen.pid` is a stub that owns no sockets. Polling it produces a
    vacuous PASS. The child must announce its own pid.
    """
    assert 'print("PID %d" % os.getpid(), flush=True)' in check._CHILD_SOURCE
    assert check._CHILD_SOURCE.index("PID %d") < check._CHILD_SOURCE.index("IMPORTS_DONE")


def test_child_source_tears_the_session_down() -> None:
    """close() is the trigger. A probe that skips it observes nothing."""
    assert "lm.close()" in check._CHILD_SOURCE
    assert check._CHILD_SOURCE.index("lm.detect") < check._CHILD_SOURCE.index("lm.close()")


def test_child_source_uses_only_synthetic_input() -> None:
    """No camera, no biometric data - enforced, not just intended."""
    assert "numpy.zeros" in check._CHILD_SOURCE
    for forbidden in ("VideoCapture", "imread", "cv2.VideoCapture"):
        assert forbidden not in check._CHILD_SOURCE


# ------------------------------------------------------------- end to end


@windows_only
@pytest.mark.realmodel
@pytest.mark.skipif(
    not LANDMARKER.exists(),
    reason="model files not downloaded; run scripts/fetch_models.py",
)
def test_check_runs_and_reports_only_declared_destinations() -> None:
    """Slow (~30s): runs the real probe against the real dependency stack.

    Asserts the check passes *and* that it actually observed something, so a
    silently-blind check cannot masquerade as a clean result.
    """
    completed = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(REPO_ROOT),
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "PASS" in completed.stdout
    assert "check liveness: OK" in completed.stdout, (
        "the probe observed no traffic at all, so this PASS proves nothing:\n"
        + completed.stdout
    )
