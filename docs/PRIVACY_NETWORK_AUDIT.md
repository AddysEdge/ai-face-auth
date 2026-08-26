# Privacy and network audit: MediaPipe telemetry

**Date:** 2026-08-25
**Scope:** Phase 1 runtime dependencies only. No Windows authentication state,
no registry, no firewall, no proxy, no certificate, and no service was changed
to produce this report.
**Method:** synthetic inputs only. No camera was opened, and no biometric data
was captured, read, or transmitted at any point in this investigation.

---

## 0. Summary

The project claimed, in several places, that it "runs entirely offline" with
"no network access required at runtime". **That claim was false.**

`mediapipe` - used by this project only for the passive-liveness / blendshape
path - links a Google-internal telemetry client into its shipped native binary
and uploads usage metrics to `https://play.googleapis.com/log`.

This is **documented, intended, upstream behaviour**, not a bug and not a
compromise. It is covered by the MediaPipe Terms of Service, and the MediaPipe
maintainers have stated explicitly that **no opt-out API will be provided**.

It is also **pre-existing**. It was not introduced by any dependency bump in
this repository; it was introduced upstream between MediaPipe 0.10.21 and
0.10.35 and was simply never noticed here. The defect this audit closes is a
**documentation and privacy-disclosure defect**, not a regression.

Every inaccurate offline claim has been retracted in this change. The decision
about what to do next - replace MediaPipe, build it from source, or narrow the
product's offline requirement - is recorded as an **open decision** in
[ADR-0005](adr/0005-mediapipe-telemetry-and-the-offline-claim.md). It is
deliberately not decided here.

**Phase 3's stricter requirement is unchanged.** The Phase 3 verifier service
is still specified as having *no network access at all*
(`docs/PHASE2_SECURITY_REVIEW.md` section 3.4, ADR-0002 section 5.3). This
finding does not relax that; it makes it a gating question, because a service
that cannot reach the network cannot ship MediaPipe as-is.

---

## 1. What was observed

### 1.1 Destination

| Property | Value |
|---|---|
| Hostname | `play.googleapis.com` |
| Path | `/log` (full endpoint `https://play.googleapis.com/log`) |
| Port / protocol | 443 / TLS |
| Observed IPs | `172.217.112.4`, `172.217.113.4`, `172.217.119.4` |
| Service | Google **Clearcut** logging (the Play services logging backend) |

The hostname was **not** guessed from the IP. It was established two ways that
agree:

1. **Live DNS-cache capture.** `Get-DnsClientCache` (read-only) taken during a
   run shows every observed IP as an A record of `play.googleapis.com`:

   ```
   entry=play.googleapis.com  data=172.217.112.4  type=1
   entry=play.googleapis.com  data=172.217.113.4  type=1
   entry=play.googleapis.com  data=172.217.119.4  type=1
   ... (8 A records + 8 AAAA records, round-robin)
   ```

   The varying last octet across runs is ordinary round-robin over one
   hostname, which is why the IP alone looked unstable.

2. **The endpoint is a literal string in the shipped binary.**
   `mediapipe/tasks/c/libmediapipe.dll` contains, contiguously:

   ```
   wireless/android/play/playlog/cplusplus/clearcut_logger.cc
   wireless/android/play/playlog/cplusplus/ion_http_client.cc
   https://play.googleapis.com/log
   wireless/android/play/playlog/cplusplus/portable_clearcut_uploader.cc
   Timed out waiting for Clearcut upload to complete.
   Failed to send to clearcut:
   ```

### 1.2 Which call triggers it, and when

Measured with `Get-NetTCPConnection -OwningProcess <own pid>` - the process's
*own* OS-level connections, polled around each step.

| Step | Outbound TCP |
|---|---|
| process start | none |
| `import mediapipe`, `import mediapipe.tasks` | none |
| `FaceLandmarker.create_from_options(...)` | none |
| `detect()` x4 on synthetic frames | none |
| **`landmarker.close()`** | **`play.googleapis.com:443` Established** |

**The trigger is session teardown (`close()`), not inference.** Polling for a
full 25 s after `create_from_options()` and again for 25 s after the first
`detect()` produced no connection in either case; `close()` produced one
immediately in both.

It fires **even when `detect()` is never called at all** - creating and closing
a landmarker with zero inference still uploads. This matches the schema in
section 1.3: a `SolutionSessionStart` / `SolutionSessionEnd` pair is reported
per session regardless of how much work the session did.

> **Correction to an earlier record.** The review comment on PR #3 attributed
> the connection to `detect()`. That was wrong, and it was wrong because the
> probe wrapped `detect()` in a `with` block, so `close()` ran inside the same
> measurement step. The attribution is corrected here; the *conclusion* of that
> review - that the behaviour is pre-existing and unchanged by the bump - was
> and remains correct.

### 1.3 What is transmitted

Extracted from the protobuf descriptors embedded in `libmediapipe.dll`
(`third_party/mediapipe/util/analytics/mediapipe_log_extension.proto` and
`mediapipe_logging_enums.proto`). This is the **complete MediaPipe telemetry
extension schema**. It is *not* the complete TLS payload: the extension is
carried inside a Clearcut envelope that was not decrypted (see the limitation
immediately after the schema).

```
MediaPipeLogExtension
├── system_info: SystemInfo
│     platform            (PLATFORM_WINDOWS | ANDROID | IOS | LINUX | MAC)
│     app_id
│     app_version
│     mediapipe_version
│     host_version
│     host_environment    (HOST_ENVIRONMENT_PYTHON | ANDROID | IOS | WEB)
└── solution_event: SolutionEvent
      solution_name       (e.g. TASKS_FACELANDMARKER, TASKS_FACEDETECTOR, ...)
      event_name          (EVENT_START | EVENT_INVOCATONS | EVENT_END | EVENT_ERROR)
      one of event_details:
        ├── session_start      { mode, graph_name, init_latency_ms }
        ├── invocation_report  { mode, pipeline_average_latency_ms,
        │                        pipeline_peak_latency_ms, elapsed_time_ms,
        │                        dropped, invocation_count[] }
        ├── session_end        { invocation_report }
        ├── session_clone      { mode, graph_name, init_latency_ms }
        └── error_details      { error_code }
```

For this project that resolves to, per session: platform Windows, host
environment Python, the MediaPipe version, `TASKS_FACELANDMARKER`, the graph
name, init latency, invocation count, and latency statistics.

**No field exists in this extracted MediaPipe extension for image data, video
frames, landmarks, blendshapes, embeddings, or any biometric content.** That is
what the binary evidence establishes, and it is the limit of what it
establishes.

The broader conclusion - that input data is not sent to Google at all - is
**Google's statement, not this audit's finding**. It rests on the maintainer's
reply on the record ([mediapipe#6291](https://github.com/google-ai-edge/mediapipe/issues/6291#issuecomment-4896121772)) and on the [MediaPipe Terms of Service](https://developers.google.com/edge/mediapipe/legal/tos). Binary inspection cannot prove what an encrypted payload contains; it
can only show that the schema the extension is built from has nowhere to put
biometric content. The two agree, which is worth something - but they are
different kinds of evidence and are not merged here.

**Identifiers - stated precisely.** The MediaPipe extension carries `app_id`
and version strings. It does **not** carry a username, machine name, or a
MediaPipe-generated stable device ID. However, the extension is wrapped in a
Clearcut `LogRequest` envelope (`clientanalytics.proto`), and the binary also
links Clearcut's compliance/identity protos, including a
`signed_out_state.zwieback_token` field. **Whether the envelope populates any
client or device identifier was not determined**, because doing so would
require decrypting TLS, which was out of scope for this audit and would have
required installing a certificate. This limit is stated rather than papered
over: the extension schema above is proven; the envelope contents are not.

**Nothing here establishes that the telemetry is anonymous**, and this audit
does not claim it is. `app_id` plus version and platform strings is not a
person, but it is not nothing either, and the envelope was not characterised.

### 1.4 Frequency, persistence, and retry

- **One TLS connection per process.** The first session end establishes it; it
  stays `Established` and is reused. A second `FaceLandmarker` created and
  closed in the same process did not open a second connection.
- **It persists after the landmarker is closed** and remained `Established`
  through the full idle observation window, up to process exit.
- **Retry/backoff exists.** The uploader carries the strings
  `Timed out waiting for Clearcut upload to complete.`,
  `Not valid for uploading until: `, `Failed sending LogRequest to clearcut
  backend: `, and a `CLEARCUT_LOG_LOSS` log source - i.e. it retries with
  server-directed backoff and separately reports its own dropped-log counts.
  The exact retry schedule was not characterised; doing so would require
  blocking the host, which this audit deliberately did not do.
- **The number of individual log uploads was not counted.** Requests are
  multiplexed over one TLS connection and are not individually observable at
  the socket layer.

### 1.5 Why the existing Python-level check could not see this

Python-level socket patching (overriding `socket.socket.connect` and friends)
recorded **zero** attempts across every run, in every version combination
tested. The connection is made from native code inside `libmediapipe.dll` using
its own HTTP client, which never enters CPython's `socket` module.

**Python-level socket interception is therefore not a valid offline check for
this project.** That is why the regression check added in this change
(section 4) is an OS-level one.

---

## 2. Is there an official opt-out?

**No.** This was checked at the API level, at the binary level, and against
upstream's own statements.

### 2.1 Official documentation confirms the behaviour

MediaPipe's Terms of Service, *Privacy* section (last modified 2026-04-07):

> "MediaPipe Solution APIs will contact Google servers from time to time in
> order to receive things like bug fixes, updated models, and hardware
> accelerator compatibility information."

> "MediaPipe Solution APIs also send metrics about the performance and
> utilization of the APIs in your app to Google."

with the collected categories listed as *Engagement* ("SDK usage/downloads,
installs, and session counts"), *Usage & Performance* ("Inference counts and
hardware-level performance metrics"), *Application & Input Metadata* ("App ID
and general characteristics of processed media"), and *System Environment*
("Host system and version").

And, on input data:

> "processing of the input data (e.g. images, video, text) fully happens
> on-device, and MediaPipe does not send that input data to Google servers."

So the network activity is documented and intended. What was *not* documented
anywhere this project would have seen it - and what this repository got wrong -
is that it happens at all.

### 2.2 Upstream has explicitly refused to add an opt-out

[google-ai-edge/mediapipe#6291](https://github.com/google-ai-edge/mediapipe/issues/6291),
"Mediapipe now includes undocumented telemetry" (opened 2026-05-07, closed as
completed 2026-07-06). MediaPipe maintainer `schmidt-sebastian`, 2026-07-06:

> "We are not adding an official API to disable this data collection [...] You
> can build the SDK from source, which will not include telemetry, or you can
> block access to the host."

The same reply states that Google will never send input data to its servers,
and gives the Terms of Service as where the collection was always disclosed.
([Permalink to the comment](https://github.com/google-ai-edge/mediapipe/issues/6291#issuecomment-4896121772).)

That is the definitive answer to "is there an officially supported opt-out":
there is not, by deliberate upstream policy.

### 2.3 What was checked and ruled out

| Candidate | Result |
|---|---|
| A documented environment variable | **None exists.** No `MEDIAPIPE_*` telemetry or opt-out variable appears in the binary, and none is documented. |
| A Python API option | **None.** `BaseOptions` exposes only `model_asset_path`, `model_asset_buffer`, `delegate`. Nothing under `mediapipe/tasks/python/` references logging, analytics, or telemetry. |
| A Python-level flag | **None.** No analytics or telemetry code exists at the Python layer at all; it is entirely inside `libmediapipe.dll`. |
| The public `TasksStatsLogger` / `TasksStatsDummyLogger` interface | Documented for the **Java/Android** API only. It is not reachable from the Python wheel, whose Clearcut client is selected internally by `clearcut_factory/logging_factory.cc` at build time. |

**No undocumented environment variable has been invented, guessed, or set.**
Searching the binary turns up `CLEARCUT_*` strings, but those are entries in
Clearcut's `log_source_enum` - log *source names*, not configuration knobs.
Setting one would do nothing, and presenting one as a fix would be dishonest.

**IP blocking was not adopted as a remedy.** Upstream offers it as a workaround
and it does work, but it is a per-machine firewall change, not a property of
this software; it would leave the repository free to keep claiming "offline"
while relying on every user to have configured their host correctly. This audit
treats "offline" as a claim the code must earn, not one the user must arrange.

---

## 3. What changed in this repository

### 3.1 Claims retracted

Every statement asserting or implying that this project makes no network
connections has been corrected, not deleted - each site now states the actual
behaviour and points here.

| File | Was |
|---|---|
| `README.md` (intro) | "A local, offline, webcam-based..." |
| `README.md` ("What this project does") | "Runs entirely offline... no network access required at runtime." |
| `pyproject.toml` (`description`) | "Local, offline Windows face-authentication MVP..." |
| `src/faceauth/__init__.py` (docstring) | "Local, offline Windows face-authentication MVP." |
| `docs/ACCEPTANCE_AUDIT.md` | "Works fully offline / Yes / No network call added anywhere..." |
| `docs/PHASE2_SECURITY_REVIEW.md` section 7 | "Works fully offline; no network calls added." |
| `docs/RESEARCH.md` sections 1, 21, Comparison | "must work fully offline" / "A local, offline, standalone Python application" / "violates the offline requirement" |

The replacement wording used throughout is deliberately uniform:

> All face detection, embedding, and matching run locally on CPU; no image,
> frame, template, or embedding ever leaves the machine. It is **not**
> network-silent: the bundled MediaPipe binary uploads usage telemetry to
> `play.googleapis.com`, which upstream provides no supported way to disable.
> See `docs/PRIVACY_NETWORK_AUDIT.md`.

### 3.2 What was added

| File | What it is |
|---|---|
| `docs/PRIVACY_NETWORK_AUDIT.md` | This report |
| `docs/adr/0005-...md` | The open decision: replace MediaPipe, rebuild it, or narrow the claim |
| `scripts/check_network_activity.py` | The OS-level regression check (section 4) |
| `scripts/network_allowlist.json` | The declared destinations, each with its justification |
| `tests/test_network_activity.py` | Tests for the check, including that it cannot pass vacuously |
| `SECURITY.md` "What leaves this machine" | A plain statement of what is and is not transmitted |
| `.github/workflows/ci.yml` | Runs the check on every push |

### 3.3 What was strengthened, not weakened

| File | Change |
|---|---|
| `docs/PHASE2_ACCEPTANCE_CRITERIA.md` | New Phase 3 entry criterion **B17**, and the identifier list updated to include it |
| `docs/PHASE2_SECURITY_REVIEW.md` section 3.4 | The "no network access" requirement is restated as unchanged **and** flagged as a blocker the current dependency set cannot meet |
| `docs/adr/0002-...md` section 5.3 | The "Network: None. Deny all outbound." row now points at B17 |
| `README.md`, `CONTRIBUTING.md`, `.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/feature_request.yml`, `docs/ACCEPTANCE_AUDIT.md` | Every current-facing Phase 3 gate reference now reads *"every Part B entry criterion, including B4a, B16, and B17"*. Statements that `B1-B15` omits "two" criteria corrected to three. Explicitly historical Phase 2 records were left as they are. |

### 3.4 What was deliberately left alone

`docs/PHASE2_SECURITY_REVIEW.md` section 3.4 and ADR-0002 section 5.3 specify
that the Phase 3 verifier service runs with **no network access**. That
requirement is **unchanged and unweakened**. This finding does not soften it -
it turns it into a gate, tracked as Phase 3 entry criterion B17, because the
current MediaPipe dependency cannot satisfy it.

`docs/RESEARCH.md`'s rejection of cloud/API-key recognition is also unchanged
in substance. Sending face images to a third party for recognition, and a
vendor SDK uploading its own latency counters, are not the same thing, and the
rejection is now argued on the grounds that actually apply.

---

## 4. The OS-level network regression check

`scripts/check_network_activity.py`, driven by `tests/test_network_activity.py`,
exists so this cannot silently regress or silently worsen.

**Why OS-level.** As established in section 1.5, Python socket interception
cannot see this connection at all. A check built on `socket` patching would have
passed cleanly for the entire life of this defect - and did.

### 4.1 How it works

A child process exercises the project's import surface and - when model weights
are present - a real MediaPipe session including teardown. The **parent** asks
Windows which TCP connections that child owns, resolves each remote address to
a hostname via the read-only DNS cache, and compares the result against
`scripts/network_allowlist.json`.

Child stdout and stderr are drained by reader threads while the parent polls on
its **own cadence**, under a single monotonic deadline. Polling is therefore not
driven by child output: a connection that opens and closes while the child is
silent is still seen, and a hung import, model initialisation, teardown, or
reader cannot hang the check. Cleanup always kills and reaps the child and
closes the sockets.

### 4.2 Why it cannot pass vacuously

The dangerous failure of a check like this is not a wrong answer - it is a
confident PASS from an observer that saw nothing because it was broken. Three
things prevent that.

**Every OS query is checked, and failure is never silence.** A missing
PowerShell executable, a non-zero exit, a timeout, a cmdlet-reported error, and
output lacking the success sentinel are five distinct outcomes, none of which
can become "no connections". Queries run under `-ErrorAction Stop` inside a
try/catch that emits `STATUS OK` or `STATUS ERR`, so the query separately
reports whether it itself succeeded. The whole connection table is fetched and
filtered on `OwningProcess`, because passing `-OwningProcess` directly throws
`ObjectNotFound` when a process owns no connections - which would make "zero
connections" indistinguishable from "the query failed".

**An independent health canary must be observed before any PASS.** The parent
opens a loopback listener; the child connects to it and holds the connection
open for the whole run. Windows must report that connection under the child's
self-reported PID. If it does not, the observer is not proven to work and the
check exits 2 regardless of what else it saw. The canary needs no external
service and changes no system configuration, it is evaluated separately from
outbound destinations, and loopback can never enter the external allowlist.

**A declared endpoint that goes missing is not a pass.** In FULL mode the
allowlist is an *expectation*, not merely a permission list: the probe drives
the exact sequence known to trigger the declared upload, so not observing it is
indeterminate and reported as such. When the dependency is eventually removed
and the allowlist is intentionally empty, zero external endpoints pass - because
the canary proves observer health independently of whether any external traffic
exists at all.

Exit codes: **0** clean, **1** an undeclared destination or a FULL-mode
expectation mismatch, **2** could not reliably observe.

### 4.3 Naming an address without a racy lookup

A destination is only "declared" if it can be named, and naming it purely from
the DNS client cache turned out to be unreliable. `play.googleapis.com`
round-robins across eight A records, and the cache entry for the particular
address a connection used can be absent or expired by the time the query runs.
Measured over eight rapid consecutive runs, that produced **one false
"undeclared destination" failure** - the endpoint was observed correctly and
then reported as unknown.

The fix resolves in both directions. The cache is still consulted first. Any
address it does not account for is checked against what the *declared*
hostnames currently resolve to, which is not racy in the same way: it asks what
the name resolves to now, and an observed address either is in that set or is
not.

This only ever confirms an address as belonging to a name **already on the
allowlist**. It cannot invent a name for an address that is not, so it does not
weaken the fail-closed property: an address that neither the cache nor a
declared hostname accounts for stays unresolved, and unresolved is treated as
undeclared. Eight consecutive runs after the fix: eight passes.

### 4.4 The trap that defeated the first version

The parent must poll the child's *real* PID, which is not necessarily
`Popen.pid`. Several virtualenv layouts - `uv`-created environments among them -
install a trampoline `python.exe` that launches the actual interpreter as a
*separate process*. `Popen.pid` is then the stub, which owns no sockets, so the
poll returns nothing and the check reports a clean PASS while the connection is
happening in plain sight. **The first working version of this check did exactly
that.** The child now prints `PID <os.getpid()>` as its first line and the
parent polls that.

That failure is also why the canary exists. Polling the right PID fixed the
symptom; only an independent proof that the observer can see *something*
prevents the next variant of the same mistake.

### 4.5 Honest limits, stated up front

- It observes **TCP connection endpoints**, not payloads. It proves *where*
  traffic goes, never *what* is in it.
- It is **Windows-only**, because it depends on `Get-NetTCPConnection`.
- In CI, model weights are deliberately not committed, so the MediaPipe session
  stage is skipped and only the **import surface** is exercised. That is still a
  genuine regression check - a dependency that phones home on import fails it -
  but it does **not** cover the session-teardown upload, and no CI result should
  be read as covering it. The full check runs locally where weights are present,
  and the check prints which mode it ran in rather than claiming a stronger
  result than it earned. Observer health is proven in both modes.
- A connection shorter than the poll interval could still be missed. The check
  polls continuously rather than sampling once, but it is a detector, not a
  proof of absence.
- Naming a destination depends on DNS. An address that neither the cache nor a
  declared hostname accounts for is reported as unresolved and treated as
  undeclared, which fails the check. That is the intended direction to fail in,
  but it does mean a DNS outage surfaces as a failure rather than as a skip.

---

## 5. The interim state, and the decision that is still open

These are two different things, and this report keeps them apart.

**The interim state - already applied, and mandatory.** Every false claim is
retracted and the actual behaviour is documented. This was never contingent on
the decision below, and it is **not a fix**: it makes the documentation true,
it does not change what the software does. It does **not** clear B17.

**The Phase 3 resolution - open.** Making the verification path genuinely
network-silent requires one of two options, and neither has been selected:

- **Option A - replace MediaPipe.** Costs a reimplementation of the liveness
  path plus the security evaluation that a spoof-resistance control needs.
- **Option B - build MediaPipe from source without telemetry.** Keeps liveness
  quality unchanged. Costs Bazel build complexity, provenance and
  reproducibility work, maintenance across upstream releases, and a recurring
  obligation to re-verify telemetry absence on every rebuild.

Both can make the software network-silent; neither is disqualified in
principle. The trade-off, and a recommendation that is deliberately not applied,
are in [ADR-0005](adr/0005-mediapipe-telemetry-and-the-offline-claim.md),
recorded as **Proposed / open** and tracked in
[issue #6](https://github.com/AddysEdge/ai-face-auth/issues/6). Phase 3 cannot
start while it is unresolved.

---

## 6. Reproducing this

The one-off probes used here were written outside the repository and are not
committed, because they are diagnostics rather than project code. The committed
`scripts/check_network_activity.py` reproduces the core observation. The binary
evidence in sections 1.1 and 1.3 is reproducible directly:

```bash
# endpoint
grep -a -o "https://play.googleapis.com/log" \
  <site-packages>/mediapipe/tasks/c/libmediapipe.dll

# telemetry schema
grep -a -o -E "[a-z_/]*mediapipe/util/analytics/[a-z0-9_]*\.proto" \
  <site-packages>/mediapipe/tasks/c/libmediapipe.dll
```

**Versions this was established against:** `mediapipe==1.0.1`,
`onnxruntime==1.29.0`, Windows 11, CPython 3.12.13. The same behaviour was
confirmed under `mediapipe==1.0.0` / `onnxruntime==1.28.0`, which is the basis
for calling it pre-existing.
