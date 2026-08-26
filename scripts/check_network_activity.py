"""OS-level outbound-network regression check.

Why this is not a Python-level check
------------------------------------
The one outbound connection this project actually makes is opened from native
code inside MediaPipe's bundled `libmediapipe.dll`, using its own HTTP client.
It never enters CPython's `socket` module, so patching `socket.socket.connect`
observes *nothing* - and did observe nothing for the entire life of the defect
this check exists to prevent recurring. See `docs/PRIVACY_NETWORK_AUDIT.md`
section 1.5.

So this check runs one level down. It launches a child process that exercises
the runtime, and the *parent* asks Windows which TCP connections that child
owns. What it records is `IP:port`. Hostnames are attached afterwards as **DNS
inference**, not as observed fact - see "What a destination name means" below.

Failing closed
--------------
The dangerous failure of a check like this is not a wrong answer - it is a
confident PASS produced by an observer that saw nothing because it was broken.
So:

* **Any failed OS observation makes the whole result indeterminate.** A failed
  poll is an interval during which the child was unwatched, and no number of
  successful polls before or after it can testify about that interval. Every
  `ObserverFailure` kind ends at exit 2. "Some polls succeeded" is not an
  excuse.
* **Running out of time is a failure, not a footnote.** If the overall deadline
  expires, the result is exit 2 even when the pid was found, READY was reached,
  the canary was seen, and connections were already observed - because the
  observation was cut short.
* **An observer-health canary gates every PASS.** The parent opens a loopback
  listener; the child connects to it and holds the connection. Windows must
  report that connection under the child's self-reported PID. If it cannot, the
  observer is not trustworthy and the check exits 2.
* In FULL mode a non-empty allowlist is an *expectation*, not just a permission
  list. A declared destination that should be observable and is not is a
  mismatch to investigate, not a pass.

Loopback never participates in outbound evaluation and can never be allowlisted
as an external destination.

What a destination name means
-----------------------------
**Observed fact:** the child opened a TCP connection to a specific IP and port.

**DNS inference:** that IP appeared in the DNS client cache for a hostname, or
is in the set of addresses a *declared* hostname currently resolves to. That is
inference, not attribution. This check never observes the DNS lookup the child
performed and never inspects TLS SNI, so it **cannot** prove which hostname the
child actually contacted.

The practical limit: a different service sharing an IP and port with a declared
hostname is indistinguishable to this check, and would be reported as matching
the declaration. Front-ends of this kind are common, so this is a real gap, not
a theoretical one. An address that matches nothing stays unresolved and is
treated as undeclared, which fails - but the converse does not hold, and no
claim to the contrary is made anywhere in this file.

The independent evidence that `play.googleapis.com` is genuinely the
destination is separate from this check: the endpoint literal in
`libmediapipe.dll` and the measured correlation with MediaPipe session
teardown, both recorded in `docs/PRIVACY_NETWORK_AUDIT.md`.

What it proves, and what it does not
------------------------------------
It proves *where*, at IP level, traffic went. It says nothing about payload
contents - it observes connection endpoints, not bytes. It is a detector, not a
proof of absence: a connection shorter than the poll interval could be missed.

Safety
------
Read-only with respect to system state. No firewall, proxy, certificate,
registry, or service change. The only socket it creates is a transient loopback
listener owned by this process. No camera is opened and no biometric data is
read: the child runs synthetic frames only.

Windows-only, because it depends on `Get-NetTCPConnection`.

Usage
-----
    python scripts/check_network_activity.py [--json] [--timeout SECONDS]

Exit codes
----------
0   completed successfully; no undeclared destination
1   an undeclared destination, or a FULL-mode declared-expectation mismatch
2   the check could not reliably observe network activity
"""

from __future__ import annotations

import argparse
import contextlib
import json
import queue
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST_PATH = Path(__file__).resolve().parent / "network_allowlist.json"
MODELS_DIR = REPO_ROOT / "models"
LANDMARKER = MODELS_DIR / "face_landmarker.task"

# Addresses that are never an outbound destination. The native IPC transport is
# a local pipe and the health canary is a loopback socket; neither is traffic
# leaving the machine, and neither may ever appear in the external allowlist.
LOOPBACK_ADDRESSES = frozenset({"0.0.0.0", "::", "127.0.0.1", "::1"})

POLL_INTERVAL = 0.15
DRAIN_SECONDS = 8.0
OVERALL_TIMEOUT = 300.0

# Upper bound on any single PowerShell query. The *effective* timeout is the
# smaller of this and the time left on the overall deadline, so a query can
# never overrun the run it belongs to.
POWERSHELL_TIMEOUT_MAX = 60.0

# A PowerShell round trip costs roughly a second. Starting one with less budget
# than this just burns the remainder and reports a timeout, so the loop stops
# instead and records that it ran out of time.
MIN_QUERY_BUDGET = 2.0

# Killing and reaping the child is outside the observation deadline: the run is
# already over by then. It is bounded so it cannot hang, and the overshoot it
# can contribute is stated honestly in the docs rather than hidden.
CHILD_REAP_TIMEOUT = 10.0

# How long the child holds a MediaPipe session open before tearing it down.
# Measured: the upload happens even at a dwell of 0.0s, so this is not required
# to make the trigger fire and is deliberately not presented as a threshold.
SESSION_DWELL_SECONDS = 1.0

# Emitted by every PowerShell helper as the last line of a successful run.
# Its absence means the query did not complete, which is never the same thing
# as the query completing with no results.
_PS_OK = "STATUS OK"
_PS_ERR = "STATUS ERR"


class ObserverFailure(Enum):
    """Why an OS observation could not be trusted. Every kind ends at exit 2."""

    EXECUTABLE_MISSING = "the PowerShell executable could not be launched"
    TIMEOUT = "the PowerShell query timed out"
    NONZERO_EXIT = "PowerShell exited non-zero"
    QUERY_FAILED = "the cmdlet reported an error (missing, permission, or execution failure)"
    MALFORMED_OUTPUT = "the query produced output without a success sentinel"
    CHILD_SPAWN_FAILED = "the probe child process could not be started"
    DEADLINE_EXPIRED = "the overall deadline expired before observation finished"


class ObserverError(RuntimeError):
    """Raised when an observation failed. Never downgraded to an empty result."""

    def __init__(self, kind: ObserverFailure, detail: str = "") -> None:
        super().__init__(f"{kind.value}{': ' + detail if detail else ''}")
        self.kind = kind
        self.detail = detail


class Deadline:
    """A single monotonic budget for one run, shared by every bounded step."""

    def __init__(self, seconds: float) -> None:
        self._end = time.monotonic() + seconds

    def remaining(self) -> float:
        return max(0.0, self._end - time.monotonic())

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def query_timeout(self) -> float:
        """Effective timeout for one PowerShell call: never past the deadline."""
        return max(0.0, min(POWERSHELL_TIMEOUT_MAX, self.remaining()))


@dataclass(frozen=True)
class Connection:
    remote_address: str
    remote_port: int

    @property
    def is_loopback(self) -> bool:
        return self.remote_address in LOOPBACK_ADDRESSES


@dataclass
class ProbeOutcome:
    """Everything the parent learned. Interpreted by `decide`, never by the probe."""

    all_connections: set[Connection] = field(default_factory=set)
    canary_seen: bool = False
    canary_port: int | None = None
    successful_polls: int = 0
    failed_polls: list[tuple[ObserverFailure, str]] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    stderr_tail: list[str] = field(default_factory=list)
    child_returncode: int | None = None
    child_pid: int | None = None
    reached_ready: bool = False
    timed_out: bool = False
    fatal: tuple[ObserverFailure, str] | None = None

    @property
    def external(self) -> set[Connection]:
        return {c for c in self.all_connections if not c.is_loopback}


# --------------------------------------------------------------------- child
# Runs in a separate process so its PID owns only its own connections. Prints
# its real pid first, opens the health-canary loopback connection, then
# exercises the runtime and prints READY.
_CHILD_SOURCE = '''
import os, socket, sys, time

# Report our REAL pid before anything else. Popen.pid is NOT reliable here:
# some virtualenv layouts (uv, and console-script shims generally) install a
# trampoline python.exe that launches the actual interpreter as a separate
# process. Polling the trampoline's pid finds no connections and the check
# passes vacuously - which is exactly how this check first fooled itself.
print("PID %d" % os.getpid(), flush=True)

stage = sys.argv[1]
canary_port = int(sys.argv[2])

# Observer-health canary: hold a loopback connection open for the whole run so
# the parent can prove Windows reports a connection under this pid. Kept in a
# module-level name so it is not garbage-collected.
_canary = socket.create_connection(("127.0.0.1", canary_port), timeout=30)
print("CANARY_CONNECTED", flush=True)

# Import surface: every runtime dependency this project loads.
import numpy            # noqa: F401
import cv2              # noqa: F401
import onnxruntime      # noqa: F401
import mediapipe as mp
from mediapipe.tasks import python as mp_python
from mediapipe.tasks.python import vision as mp_vision
import faceauth         # noqa: F401
print("IMPORTS_DONE", flush=True)

if stage == "full":
    landmarker_path = sys.argv[3]
    dwell = float(sys.argv[4])
    opts = mp_vision.FaceLandmarkerOptions(
        base_options=mp_python.BaseOptions(model_asset_path=landmarker_path),
        output_face_blendshapes=True,
        num_faces=1,
    )
    lm = mp_vision.FaceLandmarker.create_from_options(opts)
    # Synthetic frame only. No camera, no biometric data.
    frame = numpy.zeros((240, 320, 3), dtype=numpy.uint8)
    lm.detect(mp.Image(image_format=mp.ImageFormat.SRGB, data=frame))
    time.sleep(dwell)
    lm.close()          # <-- this is what triggers the telemetry upload
    print("SESSION_DONE", flush=True)

print("READY", flush=True)
# Stay alive so the parent can keep observing; the parent terminates us.
time.sleep(600)
'''


# ----------------------------------------------------------------- powershell


def _redact(text: str) -> str:
    """Strip local absolute paths so diagnostics can be pasted into an issue."""
    for secret in (str(REPO_ROOT), str(Path.home())):
        if secret:
            text = text.replace(secret, "<path>")
            text = text.replace(secret.replace("\\", "/"), "<path>")
    return text


def _run_powershell(command: str, timeout: float) -> str:
    """Run a PowerShell command, raising ObserverError on any failure.

    `timeout` is supplied by the caller from the remaining overall budget, so a
    single query can never outlive the run it belongs to. Nothing here ever
    converts a failure into empty output.
    """
    if timeout <= 0:
        raise ObserverError(ObserverFailure.TIMEOUT, "no time left on the overall deadline")
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ObserverError(ObserverFailure.EXECUTABLE_MISSING, str(exc)) from exc
    except OSError as exc:
        raise ObserverError(ObserverFailure.EXECUTABLE_MISSING, str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise ObserverError(ObserverFailure.TIMEOUT, f"after {timeout:.1f}s") from exc

    if completed.returncode != 0:
        detail = _redact((completed.stderr or "").strip())[:400]
        raise ObserverError(
            ObserverFailure.NONZERO_EXIT, f"exit {completed.returncode}: {detail}"
        )

    stdout = completed.stdout or ""
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    if lines and lines[-1].startswith(_PS_ERR):
        raise ObserverError(
            ObserverFailure.QUERY_FAILED, _redact(lines[-1][len(_PS_ERR):].strip())[:400]
        )
    if not lines or lines[-1] != _PS_OK:
        raise ObserverError(
            ObserverFailure.MALFORMED_OUTPUT,
            f"last line was {lines[-1][:120]!r}" if lines else "no output at all",
        )
    return "\n".join(lines[:-1])


def _wrap(body: str) -> str:
    """Wrap a PowerShell body so success and failure are both explicit.

    `-ErrorAction Stop` plus a catch means a missing cmdlet, a permission
    failure, or an execution-policy problem surfaces as STATUS ERR rather than
    as silence that would read as "no connections".
    """
    return (
        "$ErrorActionPreference = 'Stop'; "
        "try { " + body + "; "
        f"Write-Output '{_PS_OK}' " + "} "
        "catch { Write-Output ('" + _PS_ERR + " ' + "
        "$_.Exception.GetType().Name + ': ' + $_.Exception.Message) }"
    )


def query_connections(pid: int, timeout: float = POWERSHELL_TIMEOUT_MAX) -> set[Connection]:
    """Every TCP connection Windows attributes to `pid`, loopback included.

    Deliberately queries the whole table and filters in PowerShell. Passing
    `-OwningProcess` directly throws ObjectNotFound when a process owns no
    connections, which would make "zero connections" indistinguishable from
    "the query failed".
    """
    body = (
        "$all = @(Get-NetTCPConnection); "
        f"foreach ($c in $all) {{ if ($c.OwningProcess -eq {pid}) {{ "
        "Write-Output ('CONN ' + $c.RemoteAddress + ' ' + $c.RemotePort) } }"
    )
    out = _run_powershell(_wrap(body), timeout)

    found: set[Connection] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0] != "CONN":
            raise ObserverError(
                ObserverFailure.MALFORMED_OUTPUT, f"unparseable row {line[:120]!r}"
            )
        if not parts[2].isdigit():
            raise ObserverError(
                ObserverFailure.MALFORMED_OUTPUT, f"non-numeric port in {line[:120]!r}"
            )
        found.add(Connection(parts[1], int(parts[2])))
    return found


# ------------------------------------------------------------- DNS inference


def _dns_cache_reverse(addresses: set[str], timeout: float) -> dict[str, str]:
    """Names the DNS client cache currently associates with these addresses."""
    body = (
        "$rows = @(Get-DnsClientCache); "
        "foreach ($r in $rows) { "
        "Write-Output ('DNS ' + $r.Entry + ' ' + $r.Data) }"
    )
    try:
        out = _run_powershell(_wrap(body), timeout)
    except ObserverError:
        # Reported by the caller. Unresolved addresses stay undeclared.
        return {}

    mapping: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0] != "DNS":
            continue
        _, entry, data = parts
        if data in addresses and entry:
            mapping.setdefault(data, entry)
    return mapping


def _forward_resolve(hostnames: set[str], addresses: set[str]) -> dict[str, str]:
    """Which observed addresses are in a declared hostname's current DNS results.

    The cache lookup alone is unreliable: `play.googleapis.com` round-robins
    across eight A records, and the entry for the address a connection used can
    be absent by the time the query runs, which produced false failures.

    This narrows that gap but does not close the attribution question. Being in
    a declared hostname's address set means the observation is *consistent with*
    that declaration - not that the child contacted that hostname. Anything else
    sharing the address and port would look identical here.
    """
    mapping: dict[str, str] = {}
    for hostname in hostnames:
        try:
            infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError):
            continue
        for info in infos:
            address = str(info[4][0])
            if address in addresses:
                mapping.setdefault(address, hostname)
    return mapping


def dns_inference_for(
    addresses: set[str],
    declared: set[str] | None = None,
    timeout: float = POWERSHELL_TIMEOUT_MAX,
) -> dict[str, str]:
    """Attach a *candidate* name to each observed address, or leave it unnamed.

    The result is DNS inference, not observed attribution: this check never sees
    the child's DNS lookup and never inspects TLS SNI. An address that neither
    the cache nor a declared hostname accounts for stays unnamed, and an unnamed
    address is treated as undeclared - so a DNS failure fails closed. The
    converse does **not** hold: a match is not proof of the hostname contacted.
    """
    if not addresses:
        return {}
    mapping = _dns_cache_reverse(addresses, timeout)
    unresolved = addresses - set(mapping)
    if unresolved and declared:
        mapping.update(_forward_resolve(declared, unresolved))
    return mapping


def load_allowlist() -> list[dict[str, Any]]:
    with ALLOWLIST_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)["allowed"]


# --------------------------------------------------------------- orchestration


def _pump(stream: Any, sink: queue.Queue[str | None]) -> None:
    """Drain a child pipe into a queue so the parent never blocks on it."""
    try:
        for line in iter(stream.readline, ""):
            sink.put(line.rstrip("\r\n"))
    except (ValueError, OSError):  # pipe closed under us during teardown
        pass
    finally:
        sink.put(None)


def watch_child(
    argv_builder: Callable[[int], list[str]],
    *,
    overall_timeout: float = OVERALL_TIMEOUT,
    drain_seconds: float = DRAIN_SECONDS,
    poll_interval: float = POLL_INTERVAL,
    cwd: Path = REPO_ROOT,
    connection_query: Callable[..., set[Connection]] = query_connections,
) -> ProbeOutcome:
    """Run a child and poll Windows about it, independently of its output.

    Child stdout and stderr are drained by reader threads, so polling proceeds
    on its own cadence and a connection that opens and closes while the child is
    silent is still seen.

    One monotonic deadline bounds child startup, imports, model initialisation,
    inference, teardown, the drain, and every PowerShell query - each query's
    timeout is clamped to what is left, and a poll is not started at all without
    `MIN_QUERY_BUDGET` remaining. Killing and reaping the child happens after
    the deadline and is separately bounded by `CHILD_REAP_TIMEOUT`.
    """
    outcome = ProbeOutcome()
    deadline = Deadline(overall_timeout)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    accepted: socket.socket | None = None
    child: subprocess.Popen[str] | None = None
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.05)
        canary_port = int(listener.getsockname()[1])
        outcome.canary_port = canary_port

        try:
            child = subprocess.Popen(
                argv_builder(canary_port),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(cwd),
                bufsize=1,
            )
        except (OSError, ValueError) as exc:
            # A bad interpreter path, a missing cwd, a malformed argv. Report it
            # as an observation failure rather than a traceback.
            outcome.fatal = (ObserverFailure.CHILD_SPAWN_FAILED, _redact(str(exc))[:400])
            return outcome

        out_q: queue.Queue[str | None] = queue.Queue()
        err_q: queue.Queue[str | None] = queue.Queue()
        for stream, sink in ((child.stdout, out_q), (child.stderr, err_q)):
            threading.Thread(target=_pump, args=(stream, sink), daemon=True).start()

        drain_until: float | None = None
        stdout_closed = False

        while True:
            if deadline.expired():
                outcome.timed_out = True
                break
            if drain_until is not None and time.monotonic() >= drain_until:
                break

            # --- child output, consumed without ever blocking the poll loop ---
            while True:
                try:
                    line = out_q.get_nowait()
                except queue.Empty:
                    break
                if line is None:
                    stdout_closed = True
                    break
                outcome.log.append(line)
                if line.startswith("PID ") and outcome.child_pid is None:
                    with contextlib.suppress(IndexError, ValueError):
                        outcome.child_pid = int(line.split()[1])
                elif line == "READY":
                    outcome.reached_ready = True
                    drain_until = time.monotonic() + drain_seconds
            while True:
                try:
                    err = err_q.get_nowait()
                except queue.Empty:
                    break
                if err is None:
                    break
                if len(outcome.stderr_tail) < 400:
                    outcome.stderr_tail.append(err)

            # --- accept the canary connection if the child has made it ---
            if accepted is None:
                with contextlib.suppress(TimeoutError, OSError):
                    accepted, _addr = listener.accept()

            # --- poll Windows, on our own cadence and inside the deadline ---
            if outcome.child_pid is not None:
                if deadline.remaining() < MIN_QUERY_BUDGET:
                    # Not enough budget to ask honestly. Stop and say so.
                    outcome.timed_out = True
                    break
                try:
                    connections = connection_query(
                        outcome.child_pid, deadline.query_timeout()
                    )
                except ObserverError as exc:
                    # Any failure is an unobserved interval. Record it; the
                    # decision layer refuses to pass on it either way. Kinds
                    # that cannot recover stop the loop immediately.
                    outcome.failed_polls.append((exc.kind, exc.detail))
                    if exc.kind in (
                        ObserverFailure.EXECUTABLE_MISSING,
                        ObserverFailure.QUERY_FAILED,
                    ):
                        outcome.fatal = (exc.kind, exc.detail)
                        break
                else:
                    outcome.successful_polls += 1
                    outcome.all_connections |= connections
                    if not outcome.canary_seen and canary_port:
                        outcome.canary_seen = any(
                            c.is_loopback and c.remote_port == canary_port
                            for c in connections
                        )

            # --- child gone? finish the drain, then stop ---
            if child.poll() is not None:
                outcome.child_returncode = child.returncode
                if drain_until is None:
                    drain_until = time.monotonic() + min(drain_seconds, 2.0)
            elif stdout_closed and drain_until is None:
                drain_until = time.monotonic() + min(drain_seconds, 2.0)

            time.sleep(min(poll_interval, max(0.0, deadline.remaining())))

        # Final drain. A child that exits almost immediately can still have
        # lines in flight when the loop ends, and reporting "never reported its
        # pid" when it did would send whoever reads this down the wrong path.
        for source, sink in ((out_q, outcome.log), (err_q, outcome.stderr_tail)):
            while True:
                try:
                    item = source.get(timeout=0.2)
                except queue.Empty:
                    break
                if item is None:
                    break
                if sink is outcome.log:
                    outcome.log.append(item)
                    if item.startswith("PID ") and outcome.child_pid is None:
                        with contextlib.suppress(IndexError, ValueError):
                            outcome.child_pid = int(item.split()[1])
                    elif item == "READY":
                        outcome.reached_ready = True
                elif len(outcome.stderr_tail) < 400:
                    outcome.stderr_tail.append(item)
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=CHILD_REAP_TIMEOUT)
            outcome.child_returncode = child.returncode
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    with contextlib.suppress(OSError):
                        stream.close()
        if accepted is not None:
            with contextlib.suppress(OSError):
                accepted.close()
        with contextlib.suppress(OSError):
            listener.close()
    return outcome


def build_child_argv(stage: str, canary_port: int) -> list[str]:
    argv = [sys.executable, "-c", _CHILD_SOURCE, stage, str(canary_port)]
    if stage == "full":
        argv += [str(LANDMARKER), str(SESSION_DWELL_SECONDS)]
    return argv


def run_probe(stage: str, **kwargs: Any) -> ProbeOutcome:
    return watch_child(lambda port: build_child_argv(stage, port), **kwargs)


# ------------------------------------------------------------------- decision


@dataclass
class Decision:
    exit_code: int
    headline: str
    notes: list[str] = field(default_factory=list)
    external: list[dict[str, Any]] = field(default_factory=list)
    undeclared: list[dict[str, Any]] = field(default_factory=list)
    missing_expected: list[str] = field(default_factory=list)


def decide(
    stage: str,
    outcome: ProbeOutcome,
    allowed: list[dict[str, Any]],
    names: dict[str, str],
) -> Decision:
    """Turn an observation into an exit code. Pure - no I/O, fully testable."""
    notes: list[str] = []

    # ---- 1. Was the observer trustworthy for the WHOLE run? Nothing else
    # matters until that is settled, and a gap anywhere is disqualifying.
    if outcome.fatal is not None:
        kind, detail = outcome.fatal
        return Decision(2, f"CANNOT OBSERVE: {kind.value}", [detail] if detail else [])
    if outcome.child_pid is None:
        return Decision(
            2,
            "CANNOT OBSERVE: the child never reported its pid",
            ["Without the child's real pid there is nothing to poll."],
        )
    if not outcome.reached_ready:
        detail = f"child exit code {outcome.child_returncode}"
        if outcome.timed_out:
            detail = "child never reached READY before the overall deadline"
        return Decision(2, "CANNOT OBSERVE: the child failed before READY", [detail])
    if outcome.successful_polls == 0:
        kinds = {k.value for k, _ in outcome.failed_polls}
        return Decision(
            2,
            "CANNOT OBSERVE: no OS query ever succeeded",
            sorted(kinds) or ["no polls were attempted"],
        )
    if not outcome.canary_seen:
        return Decision(
            2,
            "CANNOT OBSERVE: the observer-health canary was never seen",
            [
                "The child held a loopback connection open, and Windows never "
                "reported it under the child's pid.",
                "The observer is not proven to work, so no PASS can be trusted.",
            ],
        )
    if outcome.failed_polls:
        kinds = sorted({k.name for k, _ in outcome.failed_polls})
        return Decision(
            2,
            "CANNOT OBSERVE: at least one OS query failed, leaving an unwatched interval",
            [
                f"{len(outcome.failed_polls)} of "
                f"{len(outcome.failed_polls) + outcome.successful_polls} queries failed "
                f"({', '.join(kinds)}).",
                "Polls that succeeded before and after a gap say nothing about the "
                "gap itself, so this is indeterminate rather than clean.",
            ],
        )
    if outcome.timed_out:
        return Decision(
            2,
            "CANNOT OBSERVE: the overall deadline expired before observation finished",
            [
                "The pid, READY, and the canary may all look healthy, but the run "
                "was cut short, so the observation is incomplete.",
                "Raise --timeout if the environment is legitimately slower.",
            ],
        )

    # ---- 2. Classify what was observed. Names here are DNS *inference*.
    allowed_pairs = {(e["hostname"], e["port"]) for e in allowed}
    external: list[dict[str, Any]] = []
    undeclared: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, int]] = set()
    for conn in sorted(outcome.external, key=lambda c: (c.remote_address, c.remote_port)):
        candidate = names.get(conn.remote_address)
        record = {
            "address": conn.remote_address,
            "port": conn.remote_port,
            "dns_candidate": candidate,
        }
        external.append(record)
        if candidate is None or (candidate, conn.remote_port) not in allowed_pairs:
            undeclared.append(record)
        else:
            seen_pairs.add((candidate, conn.remote_port))

    if undeclared:
        return Decision(
            1,
            "FAIL: undeclared outbound destination(s) observed.",
            notes,
            external,
            undeclared,
        )

    # ---- 3. A non-empty allowlist in FULL mode is an expectation, not just a
    # permission. If a declared endpoint should have been observable and was
    # not, that is indeterminate, and indeterminate is not PASS.
    missing = [
        f"{e['hostname']}:{e['port']}"
        for e in allowed
        if (e["hostname"], e["port"]) not in seen_pairs
    ]
    if stage == "full" and missing:
        return Decision(
            1,
            "INDETERMINATE: a declared destination was expected but not observed.",
            notes
            + [
                "FULL mode drives the exact sequence known to trigger it, so this "
                "is not a pass.",
                "Either the behaviour genuinely stopped - update "
                "scripts/network_allowlist.json and ADR-0005 to say so - or the "
                "probe no longer exercises the trigger.",
                "The observer itself is proven healthy by the loopback canary, so "
                "this is a real change, not a blind check.",
            ],
            external,
            missing_expected=missing,
        )

    return Decision(0, "PASS: no undeclared outbound destination observed.", notes, external)


# ----------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OS-level outbound-network check")
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    parser.add_argument(
        "--timeout",
        type=float,
        default=OVERALL_TIMEOUT,
        help=f"overall monotonic budget in seconds (default {OVERALL_TIMEOUT:.0f})",
    )
    args = parser.parse_args(argv)

    if sys.platform != "win32":
        print("CANNOT OBSERVE: this check requires Windows (Get-NetTCPConnection).")
        return 2

    stage = "full" if LANDMARKER.exists() else "imports"

    print("=" * 72)
    print("OS-LEVEL OUTBOUND NETWORK CHECK")
    print("=" * 72)
    if stage == "full":
        print("mode: FULL - imports + a real MediaPipe session including teardown")
    else:
        print("mode: IMPORTS ONLY - model weights absent, so the MediaPipe session")
        print("      stage is skipped. This catches a dependency that phones home")
        print("      on import, but it does NOT cover the session-teardown upload,")
        print("      and no result here should be read as covering it.")
        print("      Run scripts/fetch_models.py for the full check.")

    budget = Deadline(args.timeout)
    outcome = run_probe(stage, overall_timeout=args.timeout)
    allowed = load_allowlist()
    names = dns_inference_for(
        {c.remote_address for c in outcome.external},
        declared={entry["hostname"] for entry in allowed},
        timeout=max(MIN_QUERY_BUDGET, budget.query_timeout()),
    )
    decision = decide(stage, outcome, allowed, names)

    print("\nobserver health:")
    print(f"  child pid                : {outcome.child_pid}")
    print(f"  successful OS queries    : {outcome.successful_polls}")
    print(f"  failed OS queries        : {len(outcome.failed_polls)}")
    print(
        f"  loopback canary observed : {'YES' if outcome.canary_seen else 'NO'}"
        f"  (port {outcome.canary_port})"
    )
    print(f"  child reached READY      : {'YES' if outcome.reached_ready else 'NO'}")
    print(f"  overall deadline expired : {'YES' if outcome.timed_out else 'no'}")

    print(f"\nexternal endpoints observed (fact: IP:port): {len(decision.external)}")
    for record in decision.external:
        name = record["dns_candidate"] or "(no DNS candidate)"
        marker = "UNDECLARED" if record in decision.undeclared else "declared"
        print(f"  [{marker:^10}] {record['address']}:{record['port']}  ~ {name}")
    if not decision.external:
        print("  (none)")
    if decision.external:
        print(
            "  '~ name' is DNS INFERENCE, not the hostname the child was observed to\n"
            "  contact. This check reads IP and port only - it never sees the child's\n"
            "  DNS lookup and never inspects TLS SNI. Another service sharing a\n"
            "  declared IP and port would be indistinguishable here."
        )

    print("\ndeclared allowlist:")
    for entry in allowed:
        print(f"  {entry['hostname']}:{entry['port']}  <- {entry['source']}")
    if not allowed:
        print("  (empty)")

    if outcome.failed_polls:
        print("\nobserver query failures:")
        for kind, detail in outcome.failed_polls[:10]:
            print(f"  {kind.name}: {detail[:160]}")

    if decision.exit_code == 2 and outcome.stderr_tail:
        print("\nchild stderr (tail, local paths redacted):")
        for line in outcome.stderr_tail[-15:]:
            print(f"  {_redact(line)[:200]}")

    if args.json:
        print(
            "\n"
            + json.dumps(
                {
                    "mode": stage,
                    "exit_code": decision.exit_code,
                    "headline": decision.headline,
                    "observer": {
                        "child_pid": outcome.child_pid,
                        "successful_polls": outcome.successful_polls,
                        "failed_polls": [k.name for k, _ in outcome.failed_polls],
                        "canary_seen": outcome.canary_seen,
                        "reached_ready": outcome.reached_ready,
                        "timed_out": outcome.timed_out,
                    },
                    "external": decision.external,
                    "undeclared": decision.undeclared,
                    "missing_expected": decision.missing_expected,
                    "name_attribution": "dns-inference-only; not observed SNI",
                },
                indent=2,
            )
        )

    print("\n" + "=" * 72)
    print(decision.headline)
    for note in decision.notes:
        print(f"  - {note}")
    if decision.exit_code == 1 and decision.undeclared:
        print()
        print("Something in the dependency tree contacted a host this project has")
        print("not investigated. Do not add it to the allowlist to make this pass.")
        print("Investigate it first - destination, trigger, what is transmitted,")
        print("and whether it can be disabled - the way ADR-0005 documents the")
        print("existing entry. Then decide whether it is acceptable at all.")
    if decision.exit_code == 0 and decision.external:
        print()
        print("NOTE: this is not 'network silent'. The destinations above are")
        print("      declared and tolerated, not absent. Phase 3 requires this")
        print("      list to be empty - see ADR-0005, blocker B17.")
    return decision.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
