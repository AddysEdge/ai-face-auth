"""Tests for the OS-level outbound-network regression check.

The check itself is in `scripts/check_network_activity.py`.

The failure this check is most exposed to is not "it reports the wrong host" -
it is "it observed nothing because it was broken, and printed PASS". So these
tests exercise the failure modes as hard as the success path: a missing
PowerShell, a non-zero exit, a timeout, malformed output, a child that dies
before it is ready, a child that hangs, a child that cannot be spawned at all,
an observer that cannot see a connection it is holding open itself, and every
way a run can lose visibility partway through.

The pure decision logic is tested without any subprocess. The parts that can
only be proven against the real OS - the loopback health canary, catching a
connection that opens and closes while the child is silent, and the deadline
actually bounding a real run - use real child processes and really ask Windows.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import socket
import subprocess
import sys
import threading
import time
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
    # Register before executing: `dataclass` resolves annotations through
    # sys.modules, and this module is a script rather than an installed package.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


check = _load_check_module()
Connection = check.Connection
ObserverError = check.ObserverError
ObserverFailure = check.ObserverFailure
ProbeOutcome = check.ProbeOutcome

windows_only = pytest.mark.skipif(
    sys.platform != "win32",
    reason="the check depends on Get-NetTCPConnection",
)

DECLARED = [
    {
        "hostname": "play.googleapis.com",
        "port": 443,
        "source": "mediapipe",
        "trigger": "session teardown",
        "transmits": "usage metadata",
        "opt_out": "none",
        "documented_in": "docs/PRIVACY_NETWORK_AUDIT.md",
    }
]


def _healthy(**overrides) -> ProbeOutcome:
    """An outcome that would PASS, so each test can spoil exactly one thing."""
    defaults = dict(
        all_connections={Connection("127.0.0.1", 54321)},
        canary_seen=True,
        canary_port=54321,
        successful_polls=5,
        reached_ready=True,
        child_pid=4242,
    )
    defaults.update(overrides)
    return ProbeOutcome(**defaults)


class _FakeCompleted:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _no_connections(_pid, _timeout=None):
    return set()


# ============================================================== allowlist


def test_allowlist_is_valid_json_with_the_expected_shape() -> None:
    data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    assert isinstance(data["allowed"], list)
    for entry in data["allowed"]:
        assert isinstance(entry["hostname"], str) and entry["hostname"]
        assert isinstance(entry["port"], int)
        # An allowlist entry without its justification is an undocumented
        # exception, which is the thing this file exists to prevent.
        for field in ("source", "trigger", "transmits", "opt_out", "documented_in"):
            assert entry[field], f"{entry['hostname']} is missing {field}"


def test_the_allowlist_is_empty() -> None:
    """A canary, not a rule: re-adding a destination must be said out loud.

    This asserted ("play.googleapis.com", 443) while the mediapipe wheel was a
    dependency. That dependency is gone, so the runtime is expected to contact
    nothing and the list is empty - which is what blocker B17 requires. A
    future entry here re-opens B17 and must arrive with the same investigation
    the original had.
    """
    data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    assert data["allowed"] == []
    assert data["allow_empty_for_phase3"] is True


def test_loopback_is_never_allowlistable_as_an_external_destination() -> None:
    data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    for entry in data["allowed"]:
        assert entry["hostname"] not in check.LOOPBACK_ADDRESSES
    for address in ("127.0.0.1", "::1", "0.0.0.0", "::"):
        assert Connection(address, 443).is_loopback
    assert not Connection("172.217.113.4", 443).is_loopback


def test_load_allowlist_matches_the_file() -> None:
    raw = json.loads(ALLOWLIST.read_text(encoding="utf-8"))["allowed"]
    assert check.load_allowlist() == raw


# ================================================== powershell failure modes


def test_missing_powershell_executable_raises_rather_than_returning_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a, **_k):
        raise FileNotFoundError("powershell not found")

    monkeypatch.setattr(check.subprocess, "run", boom)
    with pytest.raises(ObserverError) as excinfo:
        check.query_connections(1)
    assert excinfo.value.kind is ObserverFailure.EXECUTABLE_MISSING


def test_powershell_non_zero_exit_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        check.subprocess,
        "run",
        lambda *_a, **_k: _FakeCompleted(1, "", "execution policy blocked this"),
    )
    with pytest.raises(ObserverError) as excinfo:
        check.query_connections(1)
    assert excinfo.value.kind is ObserverFailure.NONZERO_EXIT


def test_powershell_timeout_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="powershell", timeout=1)

    monkeypatch.setattr(check.subprocess, "run", slow)
    with pytest.raises(ObserverError) as excinfo:
        check.query_connections(1)
    assert excinfo.value.kind is ObserverFailure.TIMEOUT


def test_output_without_the_success_sentinel_is_malformed_not_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point: silence must never read as 'no connections'."""
    monkeypatch.setattr(
        check.subprocess, "run", lambda *_a, **_k: _FakeCompleted(0, "some noise\n")
    )
    with pytest.raises(ObserverError) as excinfo:
        check.query_connections(1)
    assert excinfo.value.kind is ObserverFailure.MALFORMED_OUTPUT


def test_completely_empty_output_is_malformed_not_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check.subprocess, "run", lambda *_a, **_k: _FakeCompleted(0, ""))
    with pytest.raises(ObserverError) as excinfo:
        check.query_connections(1)
    assert excinfo.value.kind is ObserverFailure.MALFORMED_OUTPUT


def test_cmdlet_reported_error_is_query_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        check.subprocess,
        "run",
        lambda *_a, **_k: _FakeCompleted(
            0, "STATUS ERR CommandNotFoundException: Get-NetTCPConnection\n"
        ),
    )
    with pytest.raises(ObserverError) as excinfo:
        check.query_connections(1)
    assert excinfo.value.kind is ObserverFailure.QUERY_FAILED


def test_successful_query_with_zero_connections_returns_empty_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine zero, distinguishable from every failure above."""
    monkeypatch.setattr(
        check.subprocess, "run", lambda *_a, **_k: _FakeCompleted(0, "STATUS OK\n")
    )
    assert check.query_connections(1) == set()


def test_successful_query_parses_connection_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        check.subprocess,
        "run",
        lambda *_a, **_k: _FakeCompleted(
            0, "CONN 172.217.113.4 443\nCONN 127.0.0.1 5000\nSTATUS OK\n"
        ),
    )
    assert check.query_connections(1) == {
        Connection("172.217.113.4", 443),
        Connection("127.0.0.1", 5000),
    }


def test_unparseable_connection_row_is_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        check.subprocess,
        "run",
        lambda *_a, **_k: _FakeCompleted(0, "CONN not-a-port\nSTATUS OK\n"),
    )
    with pytest.raises(ObserverError) as excinfo:
        check.query_connections(1)
    assert excinfo.value.kind is ObserverFailure.MALFORMED_OUTPUT


def test_non_numeric_port_is_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        check.subprocess,
        "run",
        lambda *_a, **_k: _FakeCompleted(0, "CONN 10.0.0.1 https\nSTATUS OK\n"),
    )
    with pytest.raises(ObserverError) as excinfo:
        check.query_connections(1)
    assert excinfo.value.kind is ObserverFailure.MALFORMED_OUTPUT


def test_redaction_strips_local_paths() -> None:
    assert str(REPO_ROOT) not in check._redact(f"error at {REPO_ROOT}\\src\\x.py")


# ============================================ deadline plumbed into the query


def test_deadline_query_timeout_is_clamped_to_what_remains() -> None:
    short = check.Deadline(3.0)
    assert 0 < short.query_timeout() <= 3.0
    long_budget = check.Deadline(10_000.0)
    assert long_budget.query_timeout() == check.POWERSHELL_TIMEOUT_MAX


def test_expired_deadline_yields_a_zero_query_timeout() -> None:
    expired = check.Deadline(0.0)
    assert expired.expired()
    assert expired.query_timeout() == 0.0


def test_query_connections_passes_its_timeout_through_to_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The supplied bound must actually reach subprocess.run, not be dropped."""
    seen: dict[str, float] = {}

    def capture(*_a, **kwargs):
        seen["timeout"] = kwargs["timeout"]
        return _FakeCompleted(0, "STATUS OK\n")

    monkeypatch.setattr(check.subprocess, "run", capture)
    check.query_connections(1, 4.25)
    assert seen["timeout"] == 4.25


def test_a_query_with_no_budget_left_fails_instead_of_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_run(*_a, **_k):
        raise AssertionError("a query was started with no deadline budget left")

    monkeypatch.setattr(check.subprocess, "run", must_not_run)
    with pytest.raises(ObserverError) as excinfo:
        check.query_connections(1, 0.0)
    assert excinfo.value.kind is ObserverFailure.TIMEOUT


# ============================================================ DNS inference


def test_dns_inference_returns_empty_without_addresses() -> None:
    result = check.dns_inference_for(set())
    assert result.names == {}
    assert result.complete is True


def test_dns_inference_never_invents_a_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        check.subprocess,
        "run",
        lambda *_a, **_k: _FakeCompleted(0, "DNS example.test 10.0.0.1\nSTATUS OK\n"),
    )
    result = check.dns_inference_for({"10.0.0.1", "10.0.0.2"})
    assert result.names == {"10.0.0.1": "example.test"}
    assert "10.0.0.2" not in result.names
    assert result.complete is True


def test_reverse_dns_failure_is_reported_as_incomplete_not_as_knowing_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two must stay distinguishable.

    "The cache knew nothing" and "the lookup failed" both produce an empty
    mapping. Only the second means the run cannot be classified.
    """
    monkeypatch.setattr(
        check.subprocess, "run", lambda *_a, **_k: _FakeCompleted(1, "", "denied")
    )
    result = check.dns_inference_for({"10.0.0.1"})
    assert result.names == {}
    assert result.complete is False
    assert result.reason and "reverse DNS" in result.reason


def test_forward_resolution_names_an_address_the_cache_missed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cache lookup is unreliable; the declared name's address set helps.

    play.googleapis.com round-robins across eight A records, and the cache
    entry for the address a connection actually used can be absent by the time
    the query runs. That produced a false "undeclared destination" about one
    run in six before forward resolution was added.
    """
    monkeypatch.setattr(check, "_dns_cache_reverse", lambda _addrs, _t: ({}, None))
    monkeypatch.setattr(
        check.socket,
        "getaddrinfo",
        lambda *_a, **_k: [(None, None, None, "", ("172.217.113.4", 443))],
    )
    result = check.dns_inference_for({"172.217.113.4"}, declared={"play.googleapis.com"})
    assert result.names == {"172.217.113.4": "play.googleapis.com"}
    assert result.complete is True


def test_an_address_outside_every_declared_set_stays_unnamed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check, "_dns_cache_reverse", lambda _addrs, _t: ({}, None))
    monkeypatch.setattr(
        check.socket,
        "getaddrinfo",
        lambda *_a, **_k: [(None, None, None, "", ("172.217.113.4", 443))],
    )
    result = check.dns_inference_for({"203.0.113.9"}, declared={"play.googleapis.com"})
    assert result.names == {}
    # The lookup finished; it simply did not match. That is a real answer.
    assert result.complete is True


def test_forward_resolution_failure_is_incomplete_not_an_undeclared_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the declared name cannot be resolved, nothing can be attributed.

    "Cannot attribute" is a different claim from "not declared", and only the
    second is a verdict. This must not become exit 1.
    """

    def boom(*_a, **_k):
        raise OSError("dns down")

    monkeypatch.setattr(check, "_dns_cache_reverse", lambda _addrs, _t: ({}, None))
    monkeypatch.setattr(check.socket, "getaddrinfo", boom)
    result = check.dns_inference_for({"203.0.113.9"}, declared={"play.googleapis.com"})
    assert result.names == {}
    assert result.complete is False


def test_cache_hit_short_circuits_forward_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No live lookup happens when the cache already accounts for everything."""
    monkeypatch.setattr(
        check, "_dns_cache_reverse", lambda _addrs, _t: ({"10.0.0.1": "cached.test"}, None)
    )

    def must_not_run(*_a, **_k):
        raise AssertionError("forward resolution ran despite a complete cache hit")

    monkeypatch.setattr(check.socket, "getaddrinfo", must_not_run)
    result = check.dns_inference_for({"10.0.0.1"}, declared={"x.test"})
    assert result.names == {"10.0.0.1": "cached.test"}
    assert result.complete is True


def test_a_matched_address_is_recorded_as_a_dns_candidate_not_an_observed_host() -> None:
    """The evidence boundary, enforced in the data shape.

    A name here means "this IP is in that hostname's DNS results", not "the
    child was observed contacting that hostname". Anything else sharing the
    address and port would be indistinguishable, so the field is named for what
    it is.
    """
    outcome = _healthy(
        all_connections={Connection("172.217.113.4", 443), Connection("127.0.0.1", 54321)}
    )
    decision = check.decide(
        "full", outcome, DECLARED, {"172.217.113.4": "play.googleapis.com"}
    )
    assert decision.exit_code == 0
    assert decision.external == [
        {
            "address": "172.217.113.4",
            "port": 443,
            "dns_candidate": "play.googleapis.com",
            "classification": check.CLASSIFICATION_DECLARED,
        }
    ]
    assert "hostname" not in decision.external[0]


def test_the_check_does_not_claim_to_prove_which_hostname_was_contacted() -> None:
    """Guards against the stronger claim creeping back into the wording."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert "cannot launder an unknown host into a pass" not in source
    assert "TLS SNI" in source
    assert "DNS inference" in source or "DNS INFERENCE" in source


def test_unresolved_address_is_treated_as_undeclared() -> None:
    outcome = _healthy(
        all_connections={Connection("172.217.113.4", 443), Connection("127.0.0.1", 54321)}
    )
    decision = check.decide("full", outcome, DECLARED, names={})  # DNS gave nothing
    assert decision.exit_code == 1
    assert decision.undeclared == [
        {
            "address": "172.217.113.4",
            "port": 443,
            "dns_candidate": None,
            "classification": check.CLASSIFICATION_UNDECLARED,
        }
    ]


# ====================================================== decision: fail closed


def test_fatal_observer_error_cannot_pass() -> None:
    outcome = _healthy(fatal=(ObserverFailure.QUERY_FAILED, "cmdlet missing"))
    assert check.decide("full", outcome, [], {}).exit_code == 2


def test_child_spawn_failure_cannot_pass() -> None:
    outcome = _healthy(fatal=(ObserverFailure.CHILD_SPAWN_FAILED, "no such interpreter"))
    decision = check.decide("full", outcome, [], {})
    assert decision.exit_code == 2
    assert "could not be started" in decision.headline


def test_missing_child_pid_cannot_pass() -> None:
    assert check.decide("full", _healthy(child_pid=None), [], {}).exit_code == 2


def test_child_that_never_reached_ready_cannot_pass() -> None:
    outcome = _healthy(reached_ready=False, child_returncode=3)
    decision = check.decide("full", outcome, [], {})
    assert decision.exit_code == 2
    assert "before READY" in decision.headline


def test_zero_successful_polls_cannot_pass() -> None:
    outcome = _healthy(
        successful_polls=0, failed_polls=[(ObserverFailure.TIMEOUT, "after 60s")]
    )
    decision = check.decide("full", outcome, [], {})
    assert decision.exit_code == 2
    assert "no OS query ever succeeded" in decision.headline


def test_unseen_canary_cannot_pass_even_with_successful_polls() -> None:
    """The core anti-vacuous-pass guarantee."""
    outcome = _healthy(canary_seen=False, all_connections=set())
    decision = check.decide("imports", outcome, [], {})
    assert decision.exit_code == 2
    assert "canary" in decision.headline


@pytest.mark.parametrize(
    "kind",
    [
        ObserverFailure.TIMEOUT,
        ObserverFailure.NONZERO_EXIT,
        ObserverFailure.MALFORMED_OUTPUT,
        ObserverFailure.EXECUTABLE_MISSING,
        ObserverFailure.QUERY_FAILED,
    ],
)
def test_any_failed_poll_makes_the_result_indeterminate(kind) -> None:
    """A failed poll is an interval nobody watched.

    Successful polls either side of a gap say nothing about the gap, so
    "some polls succeeded" must never excuse one.
    """
    outcome = _healthy(successful_polls=9, failed_polls=[(kind, "detail")])
    decision = check.decide("imports", outcome, [], {})
    assert decision.exit_code == 2
    assert "unwatched interval" in decision.headline


def test_a_failed_poll_outranks_an_otherwise_clean_full_run() -> None:
    """Even with the declared endpoint seen, a gap is still indeterminate."""
    outcome = _healthy(
        all_connections={Connection("172.217.113.4", 443), Connection("127.0.0.1", 54321)},
        failed_polls=[(ObserverFailure.TIMEOUT, "after 4.0s")],
    )
    decision = check.decide(
        "full", outcome, DECLARED, {"172.217.113.4": "play.googleapis.com"}
    )
    assert decision.exit_code == 2


def test_timed_out_cannot_pass_even_when_everything_else_looks_healthy() -> None:
    """pid found, READY reached, canary seen, traffic observed - still exit 2."""
    outcome = _healthy(
        timed_out=True,
        all_connections={Connection("172.217.113.4", 443), Connection("127.0.0.1", 54321)},
    )
    decision = check.decide(
        "full", outcome, DECLARED, {"172.217.113.4": "play.googleapis.com"}
    )
    assert decision.exit_code == 2
    assert "deadline expired" in decision.headline


# ================================================ decision: outbound verdicts


def test_undeclared_destination_returns_one() -> None:
    outcome = _healthy(
        all_connections={Connection("203.0.113.9", 443), Connection("127.0.0.1", 54321)}
    )
    decision = check.decide("full", outcome, DECLARED, {"203.0.113.9": "evil.test"})
    assert decision.exit_code == 1
    assert decision.undeclared[0]["dns_candidate"] == "evil.test"


def test_declared_destination_observed_passes() -> None:
    outcome = _healthy(
        all_connections={Connection("172.217.113.4", 443), Connection("127.0.0.1", 54321)}
    )
    decision = check.decide(
        "full", outcome, DECLARED, {"172.217.113.4": "play.googleapis.com"}
    )
    assert decision.exit_code == 0


def test_full_mode_missing_an_expected_declared_endpoint_cannot_pass() -> None:
    """A non-empty allowlist in FULL mode is an expectation, not a permission."""
    outcome = _healthy(all_connections={Connection("127.0.0.1", 54321)})
    decision = check.decide("full", outcome, DECLARED, {})
    assert decision.exit_code == 1
    assert "INDETERMINATE" in decision.headline
    assert decision.missing_expected == ["play.googleapis.com:443"]


def test_imports_mode_with_zero_external_traffic_passes_on_canary_health() -> None:
    """Imports-only cannot observe teardown, so absence there is not a mismatch."""
    outcome = _healthy(all_connections={Connection("127.0.0.1", 54321)})
    decision = check.decide("imports", outcome, DECLARED, {})
    assert decision.exit_code == 0
    assert decision.external == []


def test_empty_allowlist_with_no_external_traffic_passes_in_full_mode() -> None:
    """The eventual B17 end state: nothing declared, nothing observed."""
    outcome = _healthy(all_connections={Connection("127.0.0.1", 54321)})
    decision = check.decide("full", outcome, [], {})
    assert decision.exit_code == 0


def test_loopback_never_counts_as_an_external_destination() -> None:
    outcome = _healthy(
        all_connections={Connection("127.0.0.1", 54321), Connection("::1", 9999)}
    )
    decision = check.decide("imports", outcome, [], {})
    assert decision.exit_code == 0
    assert decision.external == []


# ================================================= orchestration, real children


def _child(body: str) -> str:
    """A child that reports its pid, then runs `body`."""
    return (
        "import os, socket, sys, time\n"
        'print("PID %d" % os.getpid(), flush=True)\n'
        "canary_port = int(sys.argv[1])\n" + body
    )


_CONNECT_CANARY = (
    '_c = socket.create_connection(("127.0.0.1", canary_port), timeout=30)\n'
    'print("CANARY_CONNECTED", flush=True)\n'
)


@windows_only
def test_watch_child_observes_the_loopback_health_canary() -> None:
    """Proves the observer works, using nothing but a socket we own."""
    body = _CONNECT_CANARY + 'print("READY", flush=True)\ntime.sleep(30)\n'
    outcome = check.watch_child(
        lambda port: [sys.executable, "-c", _child(body), str(port)],
        overall_timeout=90,
        drain_seconds=1.0,
        poll_interval=0.05,
    )
    assert outcome.child_pid is not None
    assert outcome.reached_ready
    assert outcome.successful_polls > 0
    assert not outcome.failed_polls
    assert not outcome.timed_out
    assert outcome.canary_seen, f"canary not seen; log={outcome.log}"
    assert outcome.external == set()
    assert check.decide("imports", outcome, [], {}).exit_code == 0


@windows_only
def test_watch_child_reports_a_missing_canary_rather_than_assuming_health() -> None:
    body = 'print("READY", flush=True)\ntime.sleep(6)\n'
    outcome = check.watch_child(
        lambda port: [sys.executable, "-c", _child(body), str(port)],
        overall_timeout=60,
        drain_seconds=1.0,
        poll_interval=0.05,
    )
    assert outcome.reached_ready
    assert not outcome.canary_seen
    assert check.decide("imports", outcome, [], {}).exit_code == 2


@windows_only
def test_a_transient_connection_is_seen_while_the_child_is_silent() -> None:
    """Polling must not be driven by child output.

    The child prints READY and then says nothing at all while it opens a
    connection and closes it again. A parent that only polled around log lines
    would miss it entirely.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    transient_port = int(listener.getsockname()[1])
    accepted: list[socket.socket] = []
    stop = threading.Event()

    def serve() -> None:
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            accepted.append(conn)

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    try:
        body = (
            _CONNECT_CANARY
            + 'print("READY", flush=True)\n'
            + "time.sleep(1.0)\n"
            # Silence from here on: no further stdout at all.
            + f'_t = socket.create_connection(("127.0.0.1", {transient_port}), timeout=10)\n'
            + "time.sleep(4.0)\n"
            + "_t.close()\n"
            + "time.sleep(10)\n"
        )
        outcome = check.watch_child(
            lambda port: [sys.executable, "-c", _child(body), str(port)],
            overall_timeout=90,
            drain_seconds=6.0,
            poll_interval=0.05,
        )
    finally:
        stop.set()
        server.join(timeout=5)
        for conn in accepted:
            conn.close()
        listener.close()

    assert outcome.canary_seen
    # The child emitted no stdout after READY, so seeing this proves the poll
    # loop runs on its own cadence.
    assert any(
        c.remote_port == transient_port for c in outcome.all_connections
    ), f"transient connection missed; observed={sorted(outcome.all_connections)}"


@windows_only
def test_child_failing_before_ready_is_detected_with_stderr() -> None:
    body = (
        'sys.stderr.write("child blew up\\n")\nsys.stderr.flush()\nraise SystemExit(3)\n'
    )
    outcome = check.watch_child(
        lambda port: [sys.executable, "-c", _child(body), str(port)],
        overall_timeout=60,
        drain_seconds=0.5,
        poll_interval=0.05,
        connection_query=_no_connections,
    )
    assert not outcome.reached_ready
    assert outcome.child_returncode == 3
    assert any("blew up" in line for line in outcome.stderr_tail)
    assert check.decide("imports", outcome, [], {}).exit_code == 2


@windows_only
def test_a_child_that_cannot_be_spawned_is_a_controlled_exit_two() -> None:
    """A bad interpreter path must not surface as a traceback."""
    outcome = check.watch_child(
        lambda port: [str(REPO_ROOT / "no-such-interpreter.exe"), str(port)],
        overall_timeout=30,
        drain_seconds=0.5,
        poll_interval=0.05,
        connection_query=_no_connections,
    )
    assert outcome.fatal is not None
    assert outcome.fatal[0] is ObserverFailure.CHILD_SPAWN_FAILED
    assert check.decide("imports", outcome, [], {}).exit_code == 2


@windows_only
def test_a_hung_child_is_bounded_by_the_overall_deadline() -> None:
    """A child that never becomes ready must not hang the check."""
    body = "time.sleep(600)\n"
    started = time.monotonic()
    outcome = check.watch_child(
        lambda port: [sys.executable, "-c", _child(body), str(port)],
        overall_timeout=6.0,
        drain_seconds=1.0,
        poll_interval=0.05,
        connection_query=_no_connections,
    )
    elapsed = time.monotonic() - started
    assert outcome.timed_out
    assert not outcome.reached_ready
    assert elapsed < 40, f"overall deadline was not enforced (took {elapsed:.1f}s)"
    assert check.decide("imports", outcome, [], {}).exit_code == 2


@windows_only
def test_ready_before_the_deadline_still_cannot_pass_if_the_drain_outlives_it() -> None:
    """READY is not enough: the observation window itself has to complete."""
    body = _CONNECT_CANARY + 'print("READY", flush=True)\ntime.sleep(120)\n'
    started = time.monotonic()
    outcome = check.watch_child(
        lambda port: [sys.executable, "-c", _child(body), str(port)],
        overall_timeout=8.0,
        drain_seconds=120.0,  # deliberately outlives the overall deadline
        poll_interval=0.05,
    )
    elapsed = time.monotonic() - started
    assert outcome.reached_ready
    assert outcome.timed_out
    assert elapsed < 45, f"deadline not enforced during drain (took {elapsed:.1f}s)"
    assert check.decide("imports", outcome, [], {}).exit_code == 2


@windows_only
def test_the_real_probe_stays_inside_a_short_deadline() -> None:
    """The production child and the real PowerShell query, on a tight budget.

    Covers `run_probe` only; `main` including DNS inference is covered below.
    Before the deadline was threaded through, a single query could sit on its
    fixed 60s timeout and blow straight past a short budget.
    """
    budget = 8.0
    started = time.monotonic()
    outcome = check.run_probe("imports", overall_timeout=budget)
    elapsed = time.monotonic() - started
    # Budget + bounded child cleanup, nothing like a 60s query overrun.
    assert elapsed < budget + check.CHILD_REAP_TIMEOUT, (
        f"a {budget}s budget took {elapsed:.1f}s - the deadline is not bounding "
        "the PowerShell query"
    )
    assert outcome.timed_out or outcome.reached_ready


@windows_only
def test_a_fatal_observer_error_stops_the_watch_immediately() -> None:
    """A missing cmdlet must abort, not spin pretending to watch."""

    def always_fails(_pid, _timeout=None):
        raise ObserverError(ObserverFailure.QUERY_FAILED, "cmdlet missing")

    body = _CONNECT_CANARY + 'print("READY", flush=True)\ntime.sleep(30)\n'
    outcome = check.watch_child(
        lambda port: [sys.executable, "-c", _child(body), str(port)],
        overall_timeout=60,
        drain_seconds=2.0,
        poll_interval=0.05,
        connection_query=always_fails,
    )
    assert outcome.fatal is not None
    assert outcome.successful_polls == 0
    assert check.decide("imports", outcome, [], {}).exit_code == 2


@windows_only
def test_watch_child_clamps_each_query_timeout_to_the_remaining_budget() -> None:
    """The bound must reach the query, not just the loop that calls it."""
    seen: list[float] = []

    def record(_pid, timeout):
        seen.append(timeout)
        return set()

    body = _CONNECT_CANARY + 'print("READY", flush=True)\ntime.sleep(30)\n'
    check.watch_child(
        lambda port: [sys.executable, "-c", _child(body), str(port)],
        overall_timeout=10.0,
        drain_seconds=1.0,
        poll_interval=0.05,
        connection_query=record,
    )
    assert seen, "no query was ever attempted"
    assert all(t <= 10.0 for t in seen), f"a query outlived the budget: {seen}"
    assert all(t <= check.POWERSHELL_TIMEOUT_MAX for t in seen)
    # Later queries have less budget than earlier ones.
    assert seen[-1] < seen[0]


# =============================================== one deadline for the command


def test_main_shares_one_deadline_with_the_probe_and_dns_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole command draws on one budget that is never topped up.

    Regression test for a real defect: `main` built a Deadline, then started the
    probe with a *separate* one, and afterwards handed the DNS stage
    `max(MIN_QUERY_BUDGET, remaining)`. With `--timeout 0.1` that granted the
    post-probe stage a fresh 2 seconds and produced a substantive exit 1 on a
    budget that was already spent.
    """
    granted: dict[str, object] = {}

    def spy(addresses, declared=None, deadline=None):
        granted["called"] = True
        granted["deadline"] = deadline
        return check.DnsInference({}, complete=True)

    monkeypatch.setattr(check, "dns_inference_for", spy)
    # An outcome with a real external address, so the DNS stage would run if
    # anything were willing to give it time.
    monkeypatch.setattr(
        check,
        "run_probe",
        lambda stage, **kw: check.ProbeOutcome(
            all_connections={
                Connection("203.0.113.7", 443),
                Connection("127.0.0.1", 1),
            },
            canary_seen=True,
            canary_port=1,
            successful_polls=3,
            reached_ready=True,
            child_pid=999,
        ),
    )

    assert check.main(["--timeout", "0.1"]) == 2
    assert "called" not in granted, (
        "the DNS stage was given time the deadline no longer had"
    )


def test_main_still_classifies_when_the_budget_allows_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The guard must not block classification on a normal budget."""
    seen: dict[str, object] = {}

    def spy(addresses, declared=None, deadline=None):
        seen["deadline"] = deadline
        return check.DnsInference({"203.0.113.7": "example.test"}, complete=True)

    monkeypatch.setattr(check, "dns_inference_for", spy)
    monkeypatch.setattr(
        check,
        "run_probe",
        lambda stage, **kw: check.ProbeOutcome(
            all_connections={
                Connection("203.0.113.7", 443),
                Connection("127.0.0.1", 1),
            },
            canary_seen=True,
            canary_port=1,
            successful_polls=3,
            reached_ready=True,
            child_pid=999,
        ),
    )
    # Undeclared host, so this is a real verdict rather than a pass.
    assert check.main(["--timeout", "120"]) == 1
    assert isinstance(seen["deadline"], check.Deadline), (
        "the DNS stage must receive the command's own Deadline"
    )


def test_an_unclassifiable_destination_is_indeterminate_not_a_verdict() -> None:
    outcome = _healthy(
        all_connections={Connection("203.0.113.7", 443), Connection("127.0.0.1", 54321)}
    )
    decision = check.decide("full", outcome, DECLARED, {}, dns_complete=False)
    assert decision.exit_code == 2
    assert "could not be classified within the deadline" in decision.headline


@windows_only
def test_the_whole_command_stays_inside_a_short_deadline() -> None:
    """End-to-end: main(), real child, real queries, real DNS stage."""
    budget = 8.0
    started = time.monotonic()
    exit_code = check.main(["--timeout", str(budget)])
    elapsed = time.monotonic() - started
    assert elapsed < budget + check.CHILD_REAP_TIMEOUT, (
        f"a {budget}s budget took {elapsed:.1f}s end to end"
    )
    # Too short to finish honestly, so it must refuse rather than guess.
    assert exit_code == 2


def test_forward_resolution_is_bounded_and_fails_closed_when_it_overruns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`getaddrinfo` cannot be cancelled, so an overrun must leave it unnamed."""

    def slow(*_a, **_k):
        time.sleep(30)
        return [(None, None, None, "", ("203.0.113.7", 443))]

    monkeypatch.setattr(check.socket, "getaddrinfo", slow)
    started = time.monotonic()
    infos, reason = check._bounded_getaddrinfo("example.test", 0.5)
    assert infos is None
    assert reason and "budget" in reason
    assert time.monotonic() - started < 5


def test_forward_resolution_stops_once_the_deadline_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_run(*_a, **_k):
        raise AssertionError("a lookup started with no budget left")

    monkeypatch.setattr(check, "_bounded_getaddrinfo", must_not_run)
    expired = check.Deadline(0.0)
    mapping, reason = check._forward_resolve({"a.test"}, {"203.0.113.7"}, expired)
    assert mapping == {}
    assert reason and "deadline expired" in reason


# ====================== the command deadline covers classification too


def _probe_that_burns_the_budget(external: set | None = None):
    """A probe that finishes cleanly but leaves nothing on the clock.

    Deterministic rather than timing-dependent: it spins on the shared Deadline
    until it has genuinely expired, so the state under test is guaranteed.
    """

    def probe(stage, **kwargs):
        deadline = kwargs.get("deadline")
        while deadline is not None and not deadline.expired():
            time.sleep(0.01)
        return check.ProbeOutcome(
            all_connections={Connection("127.0.0.1", 1)} | (external or set()),
            canary_seen=True,
            canary_port=1,
            successful_polls=5,
            reached_ready=True,
            child_pid=999,
            timed_out=False,  # the probe itself was not cut short
        )

    return probe


def _stage_marker(tmp_path: Path, stage: str) -> Path:
    """A synthetic stage-selection marker, independent of real weights.

    `main` chooses FULL vs IMPORTS ONLY purely from whether `check.LANDMARKER`
    exists, so for these tests the file only has to exist or not. `run_probe` is
    mocked throughout, so this marker is **never opened as a MediaPipe model** -
    it is a fixture, not weights.

    This helper previously pointed at the repository's real
    `models/face_landmarker.task`, which is deliberately not committed. That made
    the selected mode depend on untracked local state: locally the tests ran FULL
    and passed, and in CI they silently ran IMPORTS ONLY, where
    `test_an_unexpired_deadline_preserves_full_mode_missing_expected` got exit 0
    instead of exit 1.
    """
    # Distinct names per stage, so the helper cannot be confused by call order:
    # asking for "imports" must never find a marker a previous "full" call made.
    if stage == "full":
        marker = tmp_path / "present-stage-marker.task"
        marker.write_bytes(b"")
        return marker
    return tmp_path / "absent-stage-marker.task"


def _recording(probe):
    """Wrap a probe so a test can assert which stage `main()` actually selected.

    Without this, a test named "full mode" proves nothing: both modes return
    exit 2 once the deadline has expired, so an expired-deadline test would pass
    identically while silently running imports-only.
    """
    stages: list[str] = []

    def wrapper(stage, **kwargs):
        stages.append(stage)
        return probe(stage, **kwargs)

    wrapper.stages = stages
    return wrapper


def _run_main(monkeypatch, tmp_path, stage, probe, timeout="2.0", extra=()):
    monkeypatch.setattr(check, "LANDMARKER", _stage_marker(tmp_path, stage))
    monkeypatch.setattr(check, "run_probe", probe)
    return check.main(["--timeout", timeout, *extra])


def test_stage_selection_never_touches_the_repository_model(tmp_path: Path) -> None:
    """Mode selection must not depend on untracked local state.

    The repository's weights are deliberately not committed, so a helper that
    pointed at them made these tests pass locally and behave differently in CI.
    The marker lives entirely inside pytest's tmp_path and is an empty file -
    a stage-selection fixture, never a model that could be opened.
    """
    full_marker = _stage_marker(tmp_path, "full")
    imports_marker = _stage_marker(tmp_path, "imports")

    for marker in (full_marker, imports_marker):
        assert tmp_path in marker.parents, "the marker escaped the temporary directory"
        assert marker != LANDMARKER
        assert "models" not in marker.parts

    assert full_marker.exists()
    assert full_marker.stat().st_size == 0, "the marker must never be real weights"
    assert not imports_marker.exists()


def test_imports_only_with_no_addresses_cannot_pass_after_the_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reported defect, half one.

    `main` guarded its final deadline check with `and addresses`, so a probe
    that observed nothing external skipped the check entirely and reported a
    clean PASS on a clock that had already run out.
    """
    probe = _recording(_probe_that_burns_the_budget())
    assert _run_main(monkeypatch, tmp_path, "imports", probe) == 2
    assert probe.stages == ["imports"], "this test must actually exercise imports-only"
    out = capsys.readouterr().out
    assert "PASS" not in out
    assert "command deadline expired    : YES" in out


def test_full_mode_with_no_addresses_cannot_report_missing_expected_after_the_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reported defect, half two.

    Same conditions in FULL mode produced a substantive exit 1 for the missing
    declared endpoint - a claim about what the run observed, made after the run
    had lost the authority to make it.
    """
    probe = _recording(_probe_that_burns_the_budget())
    assert _run_main(monkeypatch, tmp_path, "full", probe) == 2
    # Without this the test would pass while silently running imports-only:
    # both modes return exit 2 once the deadline has expired.
    assert probe.stages == ["full"], "this test must actually exercise FULL mode"
    out = capsys.readouterr().out
    assert "mode: FULL" in out
    assert "INDETERMINATE: a declared destination" not in out
    assert "command deadline expired    : YES" in out


def test_the_expired_command_deadline_is_reported_truthfully(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Human output printed `outcome.timed_out`, which is a different clock.

    The probe finishing cleanly is not the same fact as the command budget
    surviving, and printing the first under a label that reads like the second
    told the reader the opposite of what happened.
    """
    _run_main(monkeypatch, tmp_path, "imports", _probe_that_burns_the_budget())
    out = capsys.readouterr().out
    assert "probe observation cut short : no" in out
    assert "command deadline expired    : YES" in out


def test_json_distinguishes_the_probe_clock_from_the_command_clock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = _run_main(
        monkeypatch,
        tmp_path,
        "imports",
        _probe_that_burns_the_budget(),
        extra=("--json",),
    )
    out = capsys.readouterr().out
    payload, _end = json.JSONDecoder().raw_decode(out[out.index("{") :])
    assert exit_code == 2
    assert payload["observer"]["probe_timed_out"] is False
    assert payload["command_deadline_expired"] is True
    assert payload["dns_complete"] is True  # DNS was never the problem here


def _quick_probe(stage, **_kw):
    """A healthy probe that returns immediately with no external traffic."""
    return check.ProbeOutcome(
        all_connections={Connection("127.0.0.1", 1)},
        canary_seen=True,
        canary_port=1,
        successful_polls=5,
        reached_ready=True,
        child_pid=999,
    )


def test_an_unexpired_deadline_still_lets_imports_only_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The guard must not turn every run into exit 2."""
    probe = _recording(_quick_probe)
    assert _run_main(monkeypatch, tmp_path, "imports", probe, timeout="120") == 0
    assert probe.stages == ["imports"]


def test_an_unexpired_deadline_preserves_full_mode_missing_expected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """FULL mode must still notice a declared endpoint that went missing.

    This is the test the model-dependent helper broke: in CI it silently ran
    imports-only, where a missing declared endpoint is not a mismatch, and got
    exit 0.
    """
    # The project's own allowlist is empty now, so there is nothing that could
    # go missing; this exercises the logic with a synthetic declared endpoint.
    monkeypatch.setattr(check, "load_allowlist", lambda: DECLARED)
    probe = _recording(_quick_probe)
    assert _run_main(monkeypatch, tmp_path, "full", probe, timeout="120") == 1
    assert probe.stages == ["full"], "this test must actually exercise FULL mode"


def test_an_expired_command_deadline_blocks_both_substantive_verdicts() -> None:
    """Neither exit 0 nor exit 1 is reachable once the budget is gone."""
    # Would otherwise PASS.
    passing = _healthy(
        all_connections={Connection("172.217.113.4", 443), Connection("127.0.0.1", 1)}
    )
    assert (
        check.decide(
            "full",
            passing,
            DECLARED,
            {"172.217.113.4": "play.googleapis.com"},
            deadline_expired=True,
        ).exit_code
        == 2
    )
    # Would otherwise FAIL as undeclared.
    assert (
        check.decide("full", passing, DECLARED, {}, deadline_expired=True).exit_code == 2
    )
    # Would otherwise be missing-expected exit 1.
    empty = _healthy(all_connections={Connection("127.0.0.1", 1)})
    assert check.decide("full", empty, DECLARED, {}, deadline_expired=True).exit_code == 2
    # And would otherwise PASS with nothing observed at all.
    assert check.decide("imports", empty, [], {}, deadline_expired=True).exit_code == 2


def test_the_command_deadline_message_does_not_borrow_dns_wording() -> None:
    """This branch is reached with zero external addresses observed.

    Reusing the DNS message would tell the reader "external connections were
    observed" about a run in which none were.
    """
    decision = check.decide(
        "imports",
        _healthy(all_connections={Connection("127.0.0.1", 1)}),
        [],
        {},
        deadline_expired=True,
    )
    assert decision.exit_code == 2
    assert "classification" in decision.headline
    joined = " ".join(decision.notes).lower()
    assert "external connections were observed" not in joined
    assert "dns" not in joined


# ================================ DNS completion must reach the verdict


def _probe_with_one_external(address: str = "203.0.113.7"):
    """A healthy probe that observed exactly one external endpoint."""
    return lambda stage, **kw: check.ProbeOutcome(
        all_connections={Connection(address, 443), Connection("127.0.0.1", 1)},
        canary_seen=True,
        canary_port=1,
        successful_polls=3,
        reached_ready=True,
        child_pid=999,
    )


def test_reverse_dns_that_starts_in_budget_and_expires_during_it_is_exit_two(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact defect this block exists for.

    `main` checked the deadline *before* DNS and never again. Reverse DNS could
    start with plenty of budget, consume all of it, return an empty mapping, and
    the run would go on to report a substantive undeclared-destination FAIL on a
    clock that had already run out.
    """
    monkeypatch.setattr(check, "run_probe", _probe_with_one_external())

    def slow_but_successful(addresses, timeout):
        # Burn the granted budget, plus a small margin so the deadline is
        # unambiguously expired rather than landing exactly on the boundary.
        # Without the margin this raced: an empty allowlist means no declared
        # hostnames to forward-resolve, and the overhead that used to push the
        # clock past zero is gone.
        time.sleep(max(0.0, timeout) + 0.05)
        return {}, None  # succeeded, knew nothing

    monkeypatch.setattr(check, "_dns_cache_reverse", slow_but_successful)
    monkeypatch.setattr(check, "_bounded_getaddrinfo", lambda h, t: ([], None))

    started = time.monotonic()
    exit_code = check.main(["--timeout", "2.1"])
    elapsed = time.monotonic() - started
    assert exit_code == 2, "a verdict was reached after the deadline expired"
    assert elapsed < 2.1 + check.CHILD_REAP_TIMEOUT


def test_forward_resolution_hitting_its_bound_is_exit_two_not_exit_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An abandoned lookup leaves the address unnamed - that is not a verdict."""
    monkeypatch.setattr(check, "load_allowlist", lambda: DECLARED)
    monkeypatch.setattr(check, "run_probe", _probe_with_one_external())
    monkeypatch.setattr(check, "_dns_cache_reverse", lambda _a, _t: ({}, None))
    monkeypatch.setattr(
        check,
        "_bounded_getaddrinfo",
        lambda h, t: (None, f"resolving {h} exceeded its {t:.1f}s budget"),
    )
    assert check.main(["--timeout", "60"]) == 2


def test_partial_dns_followed_by_deadline_expiry_is_exit_two(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Some addresses named, then the clock runs out: still indeterminate.

    A partial mapping is the most dangerous shape, because it looks like
    evidence. The named address would pass and the unnamed one would fail, and
    neither conclusion is supportable.
    """
    monkeypatch.setattr(check, "load_allowlist", lambda: DECLARED)
    monkeypatch.setattr(
        check,
        "run_probe",
        lambda stage, **kw: check.ProbeOutcome(
            all_connections={
                Connection("203.0.113.7", 443),
                Connection("203.0.113.8", 443),
                Connection("127.0.0.1", 1),
            },
            canary_seen=True,
            canary_port=1,
            successful_polls=3,
            reached_ready=True,
            child_pid=999,
        ),
    )
    monkeypatch.setattr(
        check,
        "_dns_cache_reverse",
        lambda _a, _t: ({"203.0.113.7": "play.googleapis.com"}, None),
    )
    monkeypatch.setattr(
        check,
        "_bounded_getaddrinfo",
        lambda h, t: (None, "resolving exceeded its budget"),
    )
    assert check.main(["--timeout", "60"]) == 2


def test_deadline_expiring_immediately_before_classification_is_exit_two(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DNS finished cleanly, but the clock ran out before the verdict.

    `main` re-checks the one shared Deadline after DNS. Having had enough budget
    to start DNS says nothing about whether anything was left afterwards.
    """
    monkeypatch.setattr(check, "run_probe", _probe_with_one_external())

    def complete_but_slow(addresses, declared=None, deadline=None):
        # A clean, complete inference that happens to exhaust the budget.
        while deadline is not None and not deadline.expired():
            time.sleep(0.01)
        return check.DnsInference({"203.0.113.7": "play.googleapis.com"}, complete=True)

    monkeypatch.setattr(check, "dns_inference_for", complete_but_slow)
    assert check.main(["--timeout", "2.5"]) == 2


def test_completed_dns_with_an_unnamed_destination_still_fails_as_undeclared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fail-closed path must survive: a real exit 1 is still reachable."""
    monkeypatch.setattr(check, "run_probe", _probe_with_one_external())
    monkeypatch.setattr(
        check,
        "dns_inference_for",
        lambda *_a, **_k: check.DnsInference({}, complete=True),
    )
    assert check.main(["--timeout", "120"]) == 1


def test_completed_dns_matching_a_declared_destination_still_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """And so must exit 0, or the check would just be a very slow `exit 2`."""
    declared = DECLARED[0]
    monkeypatch.setattr(check, "load_allowlist", lambda: DECLARED)
    monkeypatch.setattr(check, "run_probe", _probe_with_one_external("172.217.113.4"))
    monkeypatch.setattr(
        check,
        "dns_inference_for",
        lambda *_a, **_k: check.DnsInference(
            {"172.217.113.4": declared["hostname"]}, complete=True
        ),
    )
    assert check.main(["--timeout", "120"]) == 0


def test_incomplete_dns_never_yields_a_substantive_verdict() -> None:
    """Whatever the mapping looks like, incomplete means exit 2."""
    outcome = _healthy(
        all_connections={Connection("172.217.113.4", 443), Connection("127.0.0.1", 54321)}
    )
    # Even a mapping that would otherwise PASS.
    passing_names = {"172.217.113.4": "play.googleapis.com"}
    assert (
        check.decide("full", outcome, DECLARED, passing_names, dns_complete=False).exit_code
        == 2
    )
    # And one that would otherwise FAIL as undeclared.
    assert check.decide("full", outcome, DECLARED, {}, dns_complete=False).exit_code == 2


def test_the_incomplete_reason_is_surfaced_to_the_reader() -> None:
    decision = check.decide(
        "full",
        _healthy(all_connections={Connection("203.0.113.7", 443)}),
        DECLARED,
        {},
        dns_complete=False,
        dns_reason="resolving example.test exceeded its 0.4s budget",
    )
    assert decision.exit_code == 2
    assert any("0.4s budget" in note for note in decision.notes)


def test_a_sliver_of_budget_is_not_enough_to_start_a_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Below MIN_RESOLVE_BUDGET a lookup would only time out.

    Spending it would let a timeout masquerade as a completed lookup, so the
    work is skipped and reported as unfinished instead.
    """

    def must_not_run(*_a, **_k):
        raise AssertionError("a lookup started with an unusable budget")

    monkeypatch.setattr(check, "_bounded_getaddrinfo", must_not_run)
    sliver = check.Deadline(check.MIN_RESOLVE_BUDGET / 2)
    mapping, reason = check._forward_resolve({"a.test"}, {"203.0.113.7"}, sliver)
    assert mapping == {}
    assert reason is not None


# ================ observed endpoints survive an indeterminate verdict


UNCLASSIFIED = "unclassified"


def _observing_probe(*endpoints, **outcome_kwargs):
    """A healthy probe that observed the given external endpoints."""
    conns = {Connection("127.0.0.1", 1)} | {
        Connection(addr, port) for addr, port in endpoints
    }
    base = dict(
        all_connections=conns,
        canary_seen=True,
        canary_port=1,
        successful_polls=3,
        reached_ready=True,
        child_pid=999,
    )
    base.update(outcome_kwargs)
    return lambda stage, **_kw: check.ProbeOutcome(**base)


def _main_json(monkeypatch, tmp_path, stage, probe, timeout="120"):
    """Run main() with --json and return (exit_code, stdout, parsed payload)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = _run_main(
            monkeypatch, tmp_path, stage, probe, timeout=timeout, extra=("--json",)
        )
    out = buf.getvalue()
    payload, _end = json.JSONDecoder().raw_decode(out[out.index("{") :])
    return code, out, payload


def _assert_visible_but_unclassified(out, payload, expected):
    """Every expected IP:port is present, unclassified, and not a verdict."""
    assert payload["external_observed_count"] == len(expected)
    assert len(payload["external"]) == len(expected)
    assert payload["undeclared"] == [], "an indeterminate run must claim nothing"
    seen = {(r["address"], r["port"]): r for r in payload["external"]}
    assert set(seen) == set(expected)
    for (address, port), record in seen.items():
        assert record["classification"] == UNCLASSIFIED
        # Visible as a raw fact in the human output too.
        assert f"{address}:{port}" in out
        assert "unclassified" in out
    # Never rendered as a verdict.
    assert "[  declared  ]" not in out
    assert "UNDECLARED" not in out
    assert "external endpoints observed (fact: IP:port): 0" not in out


def test_a_failed_poll_keeps_the_observed_endpoint_visible_and_unclassified(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exit 2 must not erase what was actually seen.

    Every exit-2 return used to construct a Decision with no `external` at all,
    so the program printed "external endpoints observed: 0" about a run that had
    observed one. The endpoint is a fact; only its classification is in doubt.
    """
    probe = _observing_probe(
        ("203.0.113.7", 443),
        failed_polls=[(check.ObserverFailure.TIMEOUT, "simulated")],
    )
    code, out, payload = _main_json(monkeypatch, tmp_path, "imports", probe)
    assert code == 2
    _assert_visible_but_unclassified(out, payload, {("203.0.113.7", 443)})


def test_an_expired_command_deadline_keeps_the_observed_endpoint_visible(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    probe = _observing_probe(("203.0.113.7", 443))

    def burns(stage, **kwargs):
        deadline = kwargs.get("deadline")
        while deadline is not None and not deadline.expired():
            time.sleep(0.01)
        return probe(stage, **kwargs)

    code, out, payload = _main_json(monkeypatch, tmp_path, "imports", burns, timeout="2.0")
    assert code == 2
    _assert_visible_but_unclassified(out, payload, {("203.0.113.7", 443)})


def test_incomplete_dns_keeps_every_endpoint_visible_including_a_partial_mapping(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A partial mapping is the most dangerous shape: it looks like evidence.

    One address resolved, one did not. Neither may be reported as a verdict, and
    the resolved one's name is inference, not an observed hostname.
    """
    probe = _observing_probe(("203.0.113.7", 443), ("203.0.113.8", 443))
    monkeypatch.setattr(
        check,
        "dns_inference_for",
        lambda *_a, **_k: check.DnsInference(
            {"203.0.113.7": "play.googleapis.com"},
            complete=False,
            reason="resolving exceeded its budget",
        ),
    )
    code, out, payload = _main_json(monkeypatch, tmp_path, "imports", probe)
    assert code == 2
    _assert_visible_but_unclassified(
        out, payload, {("203.0.113.7", 443), ("203.0.113.8", 443)}
    )
    by_addr = {r["address"]: r for r in payload["external"]}
    # The candidate is preserved where inference produced one, and absent where
    # it did not - but neither becomes a classification.
    assert by_addr["203.0.113.7"]["dns_candidate"] == "play.googleapis.com"
    assert by_addr["203.0.113.8"]["dns_candidate"] is None
    assert "DNS INFERENCE" in out


def test_a_fatal_observer_failure_retains_already_observed_facts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    probe = _observing_probe(
        ("203.0.113.7", 443),
        fatal=(check.ObserverFailure.QUERY_FAILED, "cmdlet missing"),
    )
    code, out, payload = _main_json(monkeypatch, tmp_path, "imports", probe)
    assert code == 2
    _assert_visible_but_unclassified(out, payload, {("203.0.113.7", 443)})


def test_a_run_with_no_external_endpoints_still_reports_zero_honestly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Preserving evidence must not invent it."""
    probe = _observing_probe(failed_polls=[(check.ObserverFailure.TIMEOUT, "x")])
    code, out, payload = _main_json(monkeypatch, tmp_path, "imports", probe)
    assert code == 2
    assert payload["external_observed_count"] == 0
    assert payload["external"] == []
    assert "external endpoints observed (fact: IP:port): 0" in out


def test_a_completed_run_still_classifies_a_declared_destination(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    declared = DECLARED[0]
    monkeypatch.setattr(check, "load_allowlist", lambda: DECLARED)
    probe = _observing_probe(("172.217.113.4", 443))
    monkeypatch.setattr(
        check,
        "dns_inference_for",
        lambda *_a, **_k: check.DnsInference(
            {"172.217.113.4": declared["hostname"]}, complete=True
        ),
    )
    code, out, payload = _main_json(monkeypatch, tmp_path, "imports", probe)
    assert code == 0
    assert payload["external_observed_count"] == 1
    assert payload["external"][0]["classification"] == check.CLASSIFICATION_DECLARED
    assert payload["undeclared"] == []
    assert "declared" in out


def test_a_completed_run_still_fails_on_an_unmatched_destination(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    probe = _observing_probe(("203.0.113.9", 443))
    monkeypatch.setattr(
        check,
        "dns_inference_for",
        lambda *_a, **_k: check.DnsInference({"203.0.113.9": "evil.test"}, complete=True),
    )
    code, out, payload = _main_json(monkeypatch, tmp_path, "imports", probe)
    assert code == 1
    assert payload["external"][0]["classification"] == check.CLASSIFICATION_UNDECLARED
    assert [(r["address"], r["port"]) for r in payload["undeclared"]] == [
        ("203.0.113.9", 443)
    ]
    assert "UNDECLARED" in out


def test_human_and_json_output_agree_on_every_observed_endpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The two renderings must not be able to disagree."""
    probe = _observing_probe(
        ("203.0.113.7", 443),
        ("203.0.113.8", 8443),
        failed_polls=[(check.ObserverFailure.TIMEOUT, "simulated")],
    )
    monkeypatch.setattr(
        check,
        "dns_inference_for",
        lambda *_a, **_k: check.DnsInference(
            {"203.0.113.7": "candidate.test"}, complete=True
        ),
    )
    code, out, payload = _main_json(monkeypatch, tmp_path, "imports", probe)
    assert code == 2

    # Count agrees.
    header = next(
        ln for ln in out.splitlines() if "external endpoints observed" in ln
    )
    assert header.rstrip().endswith(str(payload["external_observed_count"]))
    assert payload["external_observed_count"] == 2

    # Address, port, classification and DNS-candidate status all agree.
    rendered = [ln for ln in out.splitlines() if ln.strip().startswith("[")]
    assert len(rendered) == 2
    for record in payload["external"]:
        line = next(
            ln for ln in rendered if f"{record['address']}:{record['port']}" in ln
        )
        assert record["classification"] in line
        if record["dns_candidate"]:
            assert record["dns_candidate"] in line
        else:
            assert "(no DNS candidate)" in line


def test_the_decision_never_reports_an_unclassified_record_as_undeclared() -> None:
    """`undeclared` is the evidence behind exit 1 and must stay empty on exit 2."""
    outcome = _healthy(
        all_connections={Connection("203.0.113.7", 443), Connection("127.0.0.1", 1)},
        failed_polls=[(ObserverFailure.TIMEOUT, "x")],
    )
    decision = check.decide("full", outcome, DECLARED, {})
    assert decision.exit_code == 2
    assert decision.undeclared == []
    assert [r["classification"] for r in decision.external] == [UNCLASSIFIED]


# ==================================================== the shipped child source


def test_child_source_reports_its_own_pid_first() -> None:
    """Guards the trampoline-venv bug described in the audit, section 4."""
    assert 'print("PID %d" % os.getpid(), flush=True)' in check._CHILD_SOURCE
    assert check._CHILD_SOURCE.index("PID %d") < check._CHILD_SOURCE.index("IMPORTS_DONE")


def test_child_source_opens_the_health_canary_before_importing_anything() -> None:
    """Observer health must be provable even if an import later hangs."""
    assert check._CHILD_SOURCE.index("create_connection") < check._CHILD_SOURCE.index(
        "import numpy"
    )


def test_child_source_tears_the_session_down() -> None:
    """Teardown was the MediaPipe trigger; a probe that skips it observes nothing.

    The replacement runtime is not known to upload on teardown, but the probe
    must still perform one: "we no longer think anything happens there" is not
    a reason to stop looking.
    """
    assert "del provider" in check._CHILD_SOURCE
    assert check._CHILD_SOURCE.index("provider.observe") < check._CHILD_SOURCE.index(
        "del provider"
    )


def test_child_source_exercises_the_real_liveness_provider() -> None:
    """The probe must run the code path the product runs, not a stand-in.

    If this drifts from what authentication actually calls, the check stops
    being evidence about the product.
    """
    assert "MediaPipeChallengeResponseLiveness" in check._CHILD_SOURCE
    assert "provider.finalize()" in check._CHILD_SOURCE


def test_child_source_does_not_import_mediapipe() -> None:
    """B17: the telemetry-bearing runtime must be gone, not merely unused."""
    assert "mediapipe" not in check._CHILD_SOURCE
    assert "ai_edge_litert" in check._CHILD_SOURCE


def test_child_source_uses_only_synthetic_input() -> None:
    """No camera, no biometric data - enforced, not just intended.

    The frame is drawn with cv2 primitives from a flat numpy fill. Nothing is
    read from a device or a file, so there is no path by which a real face
    could reach this probe.
    """
    assert "numpy.full" in check._CHILD_SOURCE
    assert "cv2.ellipse" in check._CHILD_SOURCE
    for forbidden in ("VideoCapture", "imread", "imshow"):
        assert forbidden not in check._CHILD_SOURCE


def test_child_source_drives_a_detectable_face_not_a_blank_frame() -> None:
    """All three models must actually run, not just load.

    On a blank frame the detector finds nothing and the provider returns early,
    so the landmark and blendshape models would be loaded but never inferred
    against - and a runtime that only phones home once it has done real work
    would go unobserved. The probe therefore draws a face the detector can
    find, and reports the liveness reason so a regression to
    "no_face_observed_during_challenge" is visible in the run output.
    """
    assert "LIVENESS_REASON" in check._CHILD_SOURCE
    assert check._CHILD_SOURCE.index("cv2.ellipse") < check._CHILD_SOURCE.index(
        "provider.observe"
    )


def test_child_source_does_not_claim_a_dwell_threshold() -> None:
    """A zero-dwell, zero-inference session still uploads. Measured."""
    assert "not reported upstream at all" not in check._CHILD_SOURCE


# ============================================================== end to end


@windows_only
@pytest.mark.realmodel
@pytest.mark.skipif(
    not LANDMARKER.exists(),
    reason="model files not downloaded; run scripts/fetch_models.py",
)
def test_check_runs_and_observes_no_external_destination() -> None:
    """Slow: runs the real probe against the real dependency stack.

    Asserts the check passes, that it proved observer health, and that it lost
    no observation window - so a blind check cannot masquerade as a clean
    result. It used to also assert that the declared MediaPipe endpoint *was*
    observed; with that dependency removed the assertion is inverted, and zero
    external endpoints is the expected result. The canary and poll assertions
    are what keep that zero from being vacuous.
    """
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        capture_output=True,
        text=True,
        timeout=420,
        cwd=str(REPO_ROOT),
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

    # The JSON block is followed by the human-readable verdict, so decode
    # just the object rather than the rest of the stream.
    start = completed.stdout.index("{")
    payload, _end = json.JSONDecoder().raw_decode(completed.stdout[start:])
    assert payload["mode"] == "full"
    assert payload["exit_code"] == 0
    assert payload["observer"]["canary_seen"] is True, "observer health not proven"
    assert payload["observer"]["successful_polls"] > 0
    assert payload["observer"]["failed_polls"] == []
    assert payload["observer"]["probe_timed_out"] is False
    assert payload["command_deadline_expired"] is False
    assert payload["dns_complete"] is True
    assert payload["undeclared"] == []
    assert payload["missing_expected"] == []
    assert payload["external"] == [], "the runtime must contact nothing at all"
    assert payload["external_observed_count"] == 0
    # The output must not overstate what a name means. The human-readable
    # "DNS INFERENCE" banner is only printed when there are addresses to name,
    # so with zero external endpoints the JSON field is what carries it.
    assert payload["name_attribution"] == "dns-inference-only; not observed SNI"
