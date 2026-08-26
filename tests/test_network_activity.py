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

import importlib.util
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


def test_the_only_declared_destination_is_the_documented_mediapipe_endpoint() -> None:
    """A canary, not a rule: adding a destination must be said out loud."""
    data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    assert [(e["hostname"], e["port"]) for e in data["allowed"]] == [
        ("play.googleapis.com", 443)
    ]


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
    assert check.dns_inference_for(set()) == {}


def test_dns_inference_never_invents_a_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        check.subprocess,
        "run",
        lambda *_a, **_k: _FakeCompleted(0, "DNS example.test 10.0.0.1\nSTATUS OK\n"),
    )
    mapping = check.dns_inference_for({"10.0.0.1", "10.0.0.2"})
    assert mapping == {"10.0.0.1": "example.test"}
    assert "10.0.0.2" not in mapping


def test_dns_failure_leaves_addresses_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """A DNS failure must not launder an unknown address into a pass."""
    monkeypatch.setattr(
        check.subprocess, "run", lambda *_a, **_k: _FakeCompleted(1, "", "denied")
    )
    assert check.dns_inference_for({"10.0.0.1"}) == {}


def test_forward_resolution_names_an_address_the_cache_missed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cache lookup is unreliable; the declared name's address set helps.

    play.googleapis.com round-robins across eight A records, and the cache
    entry for the address a connection actually used can be absent by the time
    the query runs. That produced a false "undeclared destination" about one
    run in six before forward resolution was added.
    """
    monkeypatch.setattr(check, "_dns_cache_reverse", lambda _addrs, _t: {})
    monkeypatch.setattr(
        check.socket,
        "getaddrinfo",
        lambda *_a, **_k: [(None, None, None, "", ("172.217.113.4", 443))],
    )
    mapping = check.dns_inference_for({"172.217.113.4"}, declared={"play.googleapis.com"})
    assert mapping == {"172.217.113.4": "play.googleapis.com"}


def test_an_address_outside_every_declared_set_stays_unnamed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(check, "_dns_cache_reverse", lambda _addrs, _t: {})
    monkeypatch.setattr(
        check.socket,
        "getaddrinfo",
        lambda *_a, **_k: [(None, None, None, "", ("172.217.113.4", 443))],
    )
    assert check.dns_inference_for({"203.0.113.9"}, declared={"play.googleapis.com"}) == {}


def test_forward_resolution_failure_leaves_the_address_unresolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a, **_k):
        raise OSError("dns down")

    monkeypatch.setattr(check, "_dns_cache_reverse", lambda _addrs, _t: {})
    monkeypatch.setattr(check.socket, "getaddrinfo", boom)
    assert check.dns_inference_for({"203.0.113.9"}, declared={"play.googleapis.com"}) == {}


def test_cache_hit_short_circuits_forward_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No live lookup happens when the cache already accounts for everything."""
    monkeypatch.setattr(
        check, "_dns_cache_reverse", lambda _addrs, _t: {"10.0.0.1": "cached.test"}
    )

    def must_not_run(*_a, **_k):
        raise AssertionError("forward resolution ran despite a complete cache hit")

    monkeypatch.setattr(check.socket, "getaddrinfo", must_not_run)
    assert check.dns_inference_for({"10.0.0.1"}, declared={"x.test"}) == {
        "10.0.0.1": "cached.test"
    }


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
        {"address": "172.217.113.4", "port": 443, "dns_candidate": "play.googleapis.com"}
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
        {"address": "172.217.113.4", "port": 443, "dns_candidate": None}
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
        return {}

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
        return {"203.0.113.7": "example.test"}

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
    assert "before destinations could be classified" in decision.headline


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
    assert check._bounded_getaddrinfo("example.test", 0.5) is None
    assert time.monotonic() - started < 5


def test_forward_resolution_stops_once_the_deadline_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_run(*_a, **_k):
        raise AssertionError("a lookup started with no budget left")

    monkeypatch.setattr(check, "_bounded_getaddrinfo", must_not_run)
    expired = check.Deadline(0.0)
    assert check._forward_resolve({"a.test"}, {"203.0.113.7"}, expired) == {}


# ==================================================== the shipped child source


def test_child_source_reports_its_own_pid_first() -> None:
    """Guards the trampoline-venv bug described in the audit, section 4."""
    assert 'print("PID %d" % os.getpid(), flush=True)' in check._CHILD_SOURCE
    assert check._CHILD_SOURCE.index("PID %d") < check._CHILD_SOURCE.index("IMPORTS_DONE")


def test_child_source_opens_the_health_canary_before_importing_anything() -> None:
    """Observer health must be provable even if an import later hangs."""
    assert check._CHILD_SOURCE.index("create_connection") < check._CHILD_SOURCE.index(
        "import mediapipe"
    )


def test_child_source_tears_the_session_down() -> None:
    """close() is the trigger. A probe that skips it observes nothing."""
    assert "lm.close()" in check._CHILD_SOURCE
    assert check._CHILD_SOURCE.index("lm.detect") < check._CHILD_SOURCE.index("lm.close()")


def test_child_source_uses_only_synthetic_input() -> None:
    """No camera, no biometric data - enforced, not just intended."""
    assert "numpy.zeros" in check._CHILD_SOURCE
    for forbidden in ("VideoCapture", "imread", "imshow"):
        assert forbidden not in check._CHILD_SOURCE


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
def test_check_runs_and_reports_only_declared_destinations() -> None:
    """Slow: runs the real probe against the real dependency stack.

    Asserts the check passes, that it proved observer health, that it lost no
    observation window, and that it actually saw the declared endpoint - so a
    blind check cannot masquerade as a clean result.
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
    assert payload["observer"]["timed_out"] is False
    assert payload["undeclared"] == []
    assert payload["missing_expected"] == []
    assert [(e["dns_candidate"], e["port"]) for e in payload["external"]] == [
        ("play.googleapis.com", 443)
    ]
    # The output must not overstate what a name means.
    assert payload["name_attribution"] == "dns-inference-only; not observed SNI"
    assert "DNS INFERENCE" in completed.stdout
