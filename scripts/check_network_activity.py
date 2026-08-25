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
the runtime, and the *parent* asks Windows which outbound TCP connections that
child owns, via `Get-NetTCPConnection -OwningProcess <child pid>`. Remote IPs
are resolved back to hostnames from the read-only DNS cache, and the result is
compared against `scripts/network_allowlist.json`.

What it proves, and what it does not
------------------------------------
It proves *where* traffic goes. It says nothing about payload contents - it
observes connection endpoints, not bytes. It is a detector, not a proof of
absence: a connection that opens and closes entirely between two polls could be
missed, which is why it polls continuously rather than sampling.

Safety
------
Read-only. No firewall, proxy, certificate, registry, or service change. No
camera is opened and no biometric data is read: the child runs synthetic frames
only.

Windows-only, because it depends on `Get-NetTCPConnection`. On other platforms
it skips with a clear message rather than silently passing.

Usage
-----
    python scripts/check_network_activity.py [--json]

Exit codes: 0 = no undeclared destination observed, 1 = undeclared destination
observed, 2 = the check could not run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST_PATH = Path(__file__).resolve().parent / "network_allowlist.json"
MODELS_DIR = REPO_ROOT / "models"
LANDMARKER = MODELS_DIR / "face_landmarker.task"

LOCAL_ADDRESSES = frozenset({"0.0.0.0", "::", "127.0.0.1", "::1"})

# How long to keep watching after the child says it has finished its work. The
# MediaPipe upload is triggered by session teardown and is asynchronous; measured
# latency from close() to an established connection is ~1s.
DRAIN_SECONDS = 8.0
POLL_INTERVAL = 0.15

# How long the child holds a MediaPipe session open before tearing it down.
#
# Measured: the upload happens even at a dwell of 0.0s, so this is not required
# to make the trigger fire. It is a small margin against a session so short that
# teardown races setup, and it costs a second. It is deliberately not presented
# as a threshold - there is no evidence for one.
SESSION_DWELL_SECONDS = 1.0


# --------------------------------------------------------------------- child
# Runs in a separate process so its PID owns only its own connections. Prints
# READY once the runtime has been exercised, then waits to be told to exit.
_CHILD_SOURCE = """
import os, sys, time

# Report our REAL pid before anything else. Popen.pid is NOT reliable here:
# some virtualenv layouts (uv, and console-script shims generally) install a
# trampoline python.exe that launches the actual interpreter as a separate
# process. Polling the trampoline's pid finds no connections and the check
# passes vacuously - which is exactly how this check first fooled itself.
print("PID %d" % os.getpid(), flush=True)

stage = sys.argv[1]

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
    landmarker_path = sys.argv[2]
    opts = mp_vision.FaceLandmarkerOptions(
        base_options=mp_python.BaseOptions(model_asset_path=landmarker_path),
        output_face_blendshapes=True,
        num_faces=1,
    )
    dwell = float(sys.argv[3])
    lm = mp_vision.FaceLandmarker.create_from_options(opts)
    # Synthetic frame only. No camera, no biometric data.
    frame = numpy.zeros((240, 320, 3), dtype=numpy.uint8)
    lm.detect(mp.Image(image_format=mp.ImageFormat.SRGB, data=frame))
    time.sleep(dwell)   # a too-short session is not reported upstream at all
    lm.close()          # <-- this is what triggers the telemetry upload
    print("SESSION_DONE", flush=True)

print("READY", flush=True)
# Stay alive so the parent can observe our connections; the parent kills us.
time.sleep(120)
"""


def _powershell(command: str, timeout: int = 60) -> str:
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout


def outbound_connections(pid: int) -> set[tuple[str, int]]:
    """Remote (address, port) pairs owned by `pid`, excluding loopback."""
    excluded = ",".join(f"'{a}'" for a in sorted(LOCAL_ADDRESSES))
    out = _powershell(
        f"Get-NetTCPConnection -OwningProcess {pid} -ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.RemoteAddress -notin @({excluded}) }} | "
        'ForEach-Object { "$($_.RemoteAddress) $($_.RemotePort)" }'
    )
    found: set[tuple[str, int]] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            found.add((parts[0], int(parts[1])))
    return found


def dns_names_for(addresses: set[str]) -> dict[str, str]:
    """Map each IP back to a hostname using the read-only DNS client cache.

    This is how the destination is named rather than guessed. An IP with no
    cache entry stays unresolved - reported as the bare IP, never invented.
    """
    if not addresses:
        return {}
    out = _powershell(
        "Get-DnsClientCache -ErrorAction SilentlyContinue | "
        "Select-Object Entry,Data | ConvertTo-Json -Compress"
    )
    try:
        entries: Any = json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        return {}
    if isinstance(entries, dict):
        entries = [entries]

    mapping: dict[str, str] = {}
    for entry in entries:
        data = str(entry.get("Data", ""))
        name = str(entry.get("Entry", ""))
        if data in addresses and name:
            mapping.setdefault(data, name)
    return mapping


def load_allowlist() -> list[dict[str, Any]]:
    with ALLOWLIST_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)["allowed"]


def run_probe(stage: str) -> tuple[set[tuple[str, int]], list[str]]:
    """Run the child and watch its connections. Returns (endpoints, child log)."""
    argv = [sys.executable, "-c", textwrap.dedent(_CHILD_SOURCE), stage]
    if stage == "full":
        argv += [str(LANDMARKER), str(SESSION_DWELL_SECONDS)]

    child = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        cwd=str(REPO_ROOT),
    )
    observed: set[tuple[str, int]] = set()
    log: list[str] = []
    try:
        assert child.stdout is not None

        # The child's own pid, not Popen.pid - see the note in _CHILD_SOURCE.
        first = child.stdout.readline().strip()
        if not first.startswith("PID "):
            log.append(first)
            return observed, log
        target_pid = int(first.split()[1])
        log.append(f"child pid {target_pid} (Popen reported {child.pid})")

        # Watch while the child works. Poll between reads so a connection that
        # opens mid-stage is caught, not just one that survives to the end.
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            line = child.stdout.readline()
            if not line:
                break
            log.append(line.strip())
            observed |= outbound_connections(target_pid)
            if line.strip() == "READY":
                break

        drain_until = time.monotonic() + DRAIN_SECONDS
        while time.monotonic() < drain_until:
            observed |= outbound_connections(target_pid)
            time.sleep(POLL_INTERVAL)
    finally:
        child.kill()
        child.wait(timeout=30)
    return observed, log


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("SKIP: this check requires Windows (Get-NetTCPConnection).")
        return 2

    have_models = LANDMARKER.exists()
    stage = "full" if have_models else "imports"

    print("=" * 72)
    print("OS-LEVEL OUTBOUND NETWORK CHECK")
    print("=" * 72)
    if have_models:
        print("mode: FULL - imports + a real MediaPipe session including teardown")
    else:
        print("mode: IMPORTS ONLY - model weights absent, so the MediaPipe session")
        print("      stage is skipped. This still catches a dependency that phones")
        print("      home on import, but it does NOT cover the session-teardown")
        print("      upload. Run scripts/fetch_models.py for the full check.")

    observed, log = run_probe(stage)
    if "READY" not in log:
        print("\nERROR: the probe child did not reach READY. Log:")
        for line in log:
            print(f"  {line}")
        return 2

    names = dns_names_for({address for address, _ in observed})
    allowed = load_allowlist()
    allowed_pairs = {(entry["hostname"], entry["port"]) for entry in allowed}

    resolved: list[dict[str, Any]] = []
    undeclared: list[dict[str, Any]] = []
    for address, port in sorted(observed):
        hostname = names.get(address)
        record = {"address": address, "port": port, "hostname": hostname}
        resolved.append(record)
        if hostname is None or (hostname, port) not in allowed_pairs:
            undeclared.append(record)

    print(f"\nobserved outbound endpoints: {len(resolved)}")
    for record in resolved:
        name = record["hostname"] or "(unresolved - no DNS cache entry)"
        marker = "UNDECLARED" if record in undeclared else "declared"
        print(f"  [{marker:^10}] {name}  {record['address']}:{record['port']}")
    if not resolved:
        print("  (none)")

    print("\ndeclared allowlist:")
    for entry in allowed:
        print(f"  {entry['hostname']}:{entry['port']}  <- {entry['source']}")

    if args.json:
        print("\n" + json.dumps(
            {"mode": stage, "observed": resolved, "undeclared": undeclared},
            indent=2,
        ))

    # Guard against a vacuous pass. In FULL mode the probe deliberately drives
    # the exact sequence known to trigger the declared upload, so observing
    # nothing means either the behaviour genuinely stopped - which is good news
    # that must be reflected in the allowlist and ADR-0005 - or the probe no
    # longer exercises the trigger, in which case this check is asleep.
    if stage == "full":
        if resolved:
            print("")
            print("check liveness: OK - the probe observed real traffic, so it is")
            print("                genuinely watching, not passing vacuously.")
        else:
            print("")
            print("check liveness: WARNING - FULL mode observed nothing at all.")
            print("                Either the declared telemetry stopped (update")
            print("                scripts/network_allowlist.json and ADR-0005), or")
            print("                the probe stopped exercising the trigger and this")
            print("                check is no longer proving anything. Investigate")
            print("                before trusting a PASS here.")

    print("\n" + "=" * 72)
    if undeclared:
        print("FAIL: undeclared outbound destination(s) observed.")
        print()
        print("Something in the dependency tree contacted a host this project has")
        print("not investigated. Do not add it to the allowlist to make this pass.")
        print("Investigate it first - destination, trigger, what is transmitted,")
        print("and whether it can be disabled - the way ADR-0005 documents the")
        print("existing entry. Then decide whether it is acceptable at all.")
        return 1

    print("PASS: no undeclared outbound destination observed.")
    if resolved:
        print()
        print("NOTE: this is not 'network silent'. The destinations above are")
        print("      declared and tolerated, not absent. Phase 3 requires this")
        print("      list to be empty - see ADR-0005, blocker B17.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
