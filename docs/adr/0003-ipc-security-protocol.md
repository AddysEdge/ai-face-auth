# ADR-0003: IPC security protocol between the credential provider and the verification service

- **Status:** Accepted (Phase 2 review).
- **Date:** 2026-08-24
- **Phase:** 2. The **protocol contract, state machine, parser, and fail-closed
  rules are implemented** in `native/` as an inert, normal-desktop library plus
  a fake client/server pair. **No Windows service, no Credential Provider, and
  no privileged endpoint is created by any of it.** The named-pipe endpoint
  described in section 5.2 is a *design*; the shipped fake transport creates a
  pipe owned by the running user, for protocol testing only.
- **Decision status:** **GO** (the design and the inert scaffold). Activation is
  gated on ADR-0001 and ADR-0002.

---

## 1. Context

ADR-0002 splits the system into a thin credential provider inside LogonUI and a
Session 0 verification service. Everything security-relevant now depends on the
channel between them: it decides whose "yes" the provider believes.

The channel is the single most attractive target in the design. An attacker who
can inject, replay, or redirect a `VerifyResult` gets the same effect as
defeating the camera, without needing a face.

## 2. Requirements

### 2.1 Content prohibitions (absolute)

The protocol **must never** carry, in any encoding, at any layer:

- raw camera frames, cropped faces, thumbnails, or any image data;
- face embeddings or any derived biometric feature vector;
- biometric templates;
- Windows passwords, password hashes, or anything derived from a password;
- certificates or private keys;
- TPM secrets or key material;
- reusable authentication assertions or bearer tokens.

The parser enforces this structurally: **there is no field in any message that
can hold arbitrary bytes of unbounded length.** Every opaque field is a
short, length-capped identifier.

### 2.2 Result properties (absolute)

A verification result must be:

| Property | Meaning |
|---|---|
| **Short-lived** | Carries an explicit expiry; useless after it. |
| **Single-use** | Consuming it once marks it spent. A second consume fails. |
| **Request-bound** | Echoes the exact `request_id` of the request that produced it. |
| **Identity-bound** | Echoes the exact `account_binding` of that request. |
| **Nonce-bound** | Echoes the exact `nonce` of that request. |
| **Deadline-bound** | Rejected if the client's own locally-derived, monotonic deadline has passed. |

Any mismatch on any of these is a hard `DENY`, not a retry.

### 2.3 Behavioural requirements

| # | Requirement |
|---|---|
| R1 | Fail closed. Every error, timeout, malformed input, and unexpected state is a DENY. There is no "unknown, so allow". |
| R2 | Versioned. An unknown protocol version is rejected, never best-effort parsed. |
| R3 | Bounded. Every message has a maximum size checked before allocation. |
| R4 | Replay-resistant. Duplicate request IDs and reused nonces are rejected server-side. |
| R5 | Explicit state machine. Any message arriving in a state that does not accept it is a protocol error and terminates the exchange. |
| R6 | Mutually authenticated at the OS level (section 5.2), not by a shared secret in the protocol. |
| R7 | Privacy-safe diagnostics. The same denylist discipline as Phase 1's `SecurityLogger`. |
| R8 | The **client** is deadline-bounded and its transport reads are bounded, so the provider tile fails over to another credential rather than hanging - regardless of what the server is doing. The **server's backend call is NOT bounded** in version 1: a hung synchronous backend holds its worker and the concurrency gate until it returns (section 5.9). **In-flight cancellation is explicitly OUT of scope for version 1** - see section 5.8. Bounding the server side is criterion B16. |

## 3. Evidence from official sources

Retrieved 2026-08-24.

### E1 - The default named-pipe security descriptor is unacceptable

> "If *lpSecurityAttributes* is **NULL**, the named pipe gets a default security
> descriptor and the handle cannot be inherited. The ACLs in the default
> security descriptor for a named pipe grant full control to the LocalSystem
> account, administrators, and the creator owner. **They also grant read access
> to members of the Everyone group and the anonymous account.**"

*Source:* `learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createnamedpipea`

**Reading.** A default-SD pipe is readable by Everyone and by anonymous. The
endpoint **must** be created with an explicit security descriptor. This is the
single most important implementation rule in this ADR.

### E2 - `FILE_FLAG_FIRST_PIPE_INSTANCE` prevents endpoint squatting

> "If you attempt to create multiple instances of a pipe with this flag,
> creation of the first instance succeeds, but creation of the next instance
> fails with **ERROR_ACCESS_DENIED**."

*Source:* same page.

**Reading.** Without it, a process that wins the race can create the pipe first
and the real server silently attaches to *someone else's* endpoint. With it,
the server fails loudly instead - which, per R1, is the correct outcome.

### E3 - Remote clients can be rejected at creation

`PIPE_REJECT_REMOTE_CLIENTS` - "Connections from remote clients are
automatically rejected."

*Source:* same page.

### E4 - The service has a nameable, restricted identity

Per-service SIDs (`NT SERVICE\SvcName`, `SERVICE_SID_TYPE_RESTRICTED`) are the
documented mechanism for controlling "access to the objects a service uses,
instead of relying on the use of the LocalSystem account"
(`learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_sid_info`;
quoted in full in ADR-0002 E4). This is what the pipe SDDL names.

## 4. Considered alternatives

| # | Alternative | Verdict |
|---|---|---|
| C1 | Named pipe with an explicit SDDL | **Selected.** Documented identity model, synchronous request/response, OS-enforced ACL, no listening socket. |
| C2 | Localhost TCP socket | **Rejected.** No OS-level peer identity, reachable by every local process, needs an application-layer authentication scheme this design is trying to avoid. |
| C3 | ALPC | **Rejected.** The documented public surface is thin; the practical surface is not. |
| C4 | COM / RPC | **Rejected for Phase 2.** Larger surface, registration requirements, and harder to reason about from a pre-logon client. Reconsider only with a specific justification. |
| C5 | Shared memory + event | **Rejected.** Would make it easy to pass frame-sized buffers - the opposite of requirement 2.1. The narrow pipe is a *feature*. |
| C6 | Text/JSON messages | **Rejected.** Unbounded, ambiguous, and encourages adding fields. A fixed binary layout with hard caps makes 2.1 checkable by inspection. |
| C7 | Application-layer MAC/shared secret over the channel | **Rejected as the primary control.** It moves the problem to key storage on a machine where both endpoints are local. OS ACLs are the right primitive (R6). Revisit only if a specific threat survives section 5.2. |

## 5. Decision

### 5.1 Wire format, version 1

All integers little-endian. Fixed 16-byte header:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` | `0x31504146` (`"FAP1"`) |
| 4 | 2 | `protocol_version` | 1 |
| 6 | 2 | `message_type` | see below |
| 8 | 4 | `payload_length` | `<= 4096`, checked **before** allocation |
| 12 | 4 | `reserved` | must be 0; nonzero is a protocol error |

Message types: `1 VerifyRequest`, `2 VerifyResult`, `4 ProtocolError`.
**Type `3` is RESERVED and permanently unassigned in version 1** - it held a
`CancelRequest` in an earlier draft; see section 5.8 for why that was removed
rather than kept. A message of type 3 is rejected as `UnknownMessageType`.

**No absolute timestamp appears anywhere in this format.** Durations are
bounded, relative milliseconds, and each side derives its own deadline from its
own monotonic clock. Section 5.1a explains why.

Opaque fields are length-prefixed (`uint16` length, then bytes) and capped
individually.

**`VerifyRequest`** (client -> server)

| Field | Type | Notes |
|---|---|---|
| `request_id` | 16 bytes | Cryptographically random, unique per request. |
| `nonce` | 32 bytes | Cryptographically random, never reused. |
| `account_binding` | opaque, 1..128 bytes | An opaque handle for the Windows identity being verified. **Not** a password, not a template, not a secret - a stable local identifier. |
| `session_id` | `uint32` | Logon session the request belongs to. |
| `desktop_binding` | opaque, 0..64 bytes | Opaque desktop/station discriminator. |
| `requested_lifetime_ms` | `uint32` | **Relative** duration, `1..kMaxRequestLifetimeMs` (30 s). Zero or over-max fails to parse. The server clamps it again and starts its own deadline; the client's clock is never trusted. |
| `flags` | `uint32` | Reserved; must be 0. |

**`VerifyResult`** (server -> client)

| Field | Type | Notes |
|---|---|---|
| `request_id` | 16 bytes | Must equal the request's. |
| `nonce` | 32 bytes | Must equal the request's. |
| `account_binding` | opaque | Must equal the request's. |
| `outcome` | `uint8` | `0` = deny, `1` = allow. |
| `reason_code` | `uint16` | Coarse, non-identifying. |
| `result_ttl_ms` | `uint32` | **Relative** duration, `<= kMaxResultValidityMs` (5 s); over-max fails to parse. The client clamps it to the smaller of this, the protocol maximum, and its own remaining request window - so it can only ever shorten validity. |

**`ProtocolError`** (either direction): `request_id` (16 bytes, may be all
zero) + `error_code` (`uint16`).

Note what is *absent*: there is no free-form field, no blob, no image, no
vector, no string of unbounded length, no absolute timestamp, and no field that
could carry a credential. Requirement 2.1 is enforced by the format itself.

### 5.1a Time base: monotonic and relative, never wall-clock

An earlier draft serialized Unix wall-clock deadlines. That was wrong. System
time can jump backwards or forwards - NTP correction, a user changing the
clock, a VM resuming from a snapshot, a dual-boot machine disagreeing about the
RTC. A backwards jump would silently *extend* a "short-lived" result; a
forwards jump would expire a request that had barely started. Either turns a
security control into a liability.

The rules, all implemented and tested in `native/`:

1. The **client** starts its own monotonic deadline **before** sending, from
   its own clock.
2. The request carries only `requested_lifetime_ms`, a bounded relative value.
3. The **server** validates that lifetime against the protocol maximum and
   starts its **own** monotonic deadline on arrival.
4. **Replay-cache entries expire against the server's monotonic clock.**
5. The result carries only `result_ttl_ms`, a bounded relative value.
6. The client caps result validity at
   `min(received TTL, kMaxResultValidityMs, its own remaining request window)`.
   **A result can only ever shorten the client's window, never extend it.**
7. Neither endpoint trusts a peer-supplied absolute timestamp, because none is
   sent.
8. `steady_clock` epoch values are **never** serialized: their origin is
   implementation-defined and meaningless to another process, so comparing two
   processes' values would silently reintroduce the same class of bug.
9. **Every window is half-open:**

   ```
   valid    when now <  deadline
   expired  when now >= deadline
   ```

   A deadline instant is already too late, and a zero-length window is
   therefore never usable - a result with `result_ttl_ms == 0` can never be
   consumed. Requests, results, and replay-cache entries all follow the same
   rule. A mixture would leave a one-millisecond seam where two components
   disagreed about whether something was still alive, and the dangerous
   direction of that disagreement is the one where replay protection lapses
   before the request it protects.

Consequence: a wall-clock change cannot extend or shorten request or result
validity, because no wall clock is consulted at any point.

### 5.2 Endpoint identity and access control

| Property | Value |
|---|---|
| Endpoint | `\\.\pipe\<vendor>-faceauth-verify-v1` |
| Created by | The verification service only, at start, with `FILE_FLAG_FIRST_PIPE_INSTANCE` (E2). |
| Security descriptor | **Explicit. Never NULL** (E1). |
| DACL | `NT AUTHORITY\SYSTEM`: read/write/connect. `NT SERVICE\FaceAuthVerifier` (E4): full. **Nobody else.** No `Everyone`, no `Anonymous`, no `Authenticated Users`, no `INTERACTIVE`. |
| Owner | The service SID. |
| SACL | Mandatory-label `SI` at System integrity, so lower-integrity processes cannot write. |
| Remote | `PIPE_REJECT_REMOTE_CLIENTS` (E3). |
| Mode | Message mode, `PIPE_TYPE_MESSAGE \| PIPE_READMODE_MESSAGE`, so message framing is not a parser responsibility alone. |
| Instances | Bounded (see section 5.6). |
| Server -> client check | The server verifies the connected client's token before processing: `ImpersonateNamedPipeClient` -> check the client SID is `SYSTEM` -> `RevertToSelf`. |
| Client -> server check | The client verifies the *server* end's identity before sending anything, so it cannot be lured into talking to a squatter. |

**Stated limitation, not glossed over.** LogonUI runs as SYSTEM, and so does
every other SYSTEM process on the machine. A pipe ACL that admits SYSTEM admits
*all* of them. Named-pipe ACLs therefore prove "a SYSTEM process", not
"LogonUI". An attacker already running as SYSTEM can speak this protocol.

That is an accepted residual risk, on the following grounds: an attacker with
SYSTEM already owns the machine and does not need to defeat a logon tile to do
anything. The protocol's job is to stop *non*-SYSTEM local processes,
network peers, and replayed traffic - not to defend against an attacker who has
already won. This limitation is recorded rather than mitigated with a scheme
that would only look stronger.

### 5.3 State machines

**Client:** `Idle` -> `AwaitingResult` -> (`ResultAvailable` -> `Consumed`) |
`Abandoned` | `Failed`.

`Abandoned` is **local only**: the client stops waiting and sends nothing. It
is not cancellation and is not described as such anywhere (section 6).

- `Idle`: only `SendRequest` is legal.
- `AwaitingResult`: accepts `VerifyResult`, `ProtocolError`, `Cancel`, timeout,
  disconnect. A second `VerifyRequest` is an invalid transition.
- `ResultAvailable`: exactly one `Consume()` succeeds. It checks
  request_id/nonce/account_binding/expiry and then moves to `Consumed`.
- `Consumed`, `Cancelled`, `Failed` are terminal. Every operation on a terminal
  state fails.

**Server:** `Idle` -> `Processing` -> `Responded` | `Failed`.

- `Idle`: accepts `VerifyRequest`. A `VerifyResult` arriving at the server is an
  invalid transition.
- `Processing`: accepts deadline expiry and disconnect. There is no cancellation message in version 1 (section 6).
- `Responded`, `Cancelled`, `Failed` are terminal.

**Any invalid transition is `InvalidStateTransition`, is reported once as a
`ProtocolError`, and terminates the exchange. It is never ignored and never
retried.**

### 5.4 Threat table

| # | Threat | Control | Residual risk |
|---|---|---|---|
| T1 | Rogue local process connects to the endpoint | Explicit DACL (E1), SYSTEM+service SID only, System-integrity SACL | A SYSTEM-level attacker still qualifies (section 5.2). |
| T2 | Endpoint squatting - attacker creates the pipe first | `FILE_FLAG_FIRST_PIPE_INSTANCE` (E2); the client validates the server end before sending | If the service fails to start, the name is unowned; the client must fail closed rather than connect to whatever appears. |
| T3 | Remote connection | `PIPE_REJECT_REMOTE_CLIENTS` (E3) | none material |
| T4 | Replay of a captured `VerifyResult` | Nonce + `request_id` echo checks client-side; server-side seen-set for both | Bounded seen-set (section 5.6); entries expire with their deadlines. |
| T5 | Result substitution - a valid result for user A used to log in user B | `account_binding` echo checked before consume | The binding is only as good as how the provider derives it (Q1). |
| T6 | Result reuse - one successful verification unlocks twice | Single-use consume; terminal `Consumed` state | An in-process attacker who can reach the object before consume; out of scope at this layer. |
| T7 | TOCTOU between "verified" and "credential submitted" | Short monotonic result TTL; the provider must submit within that window or discard; the result is consumed immediately before serialization, not held | **Real and irreducible.** A gap always exists between the biometric decision and the credential submission. Shrinking the window narrows it; it cannot be closed. Recorded, not hidden. |
| T8 | Confused deputy - a low-privilege process makes the provider verify on its behalf | The provider is only ever driven by LogonUI in a real logon scenario; the request carries `session_id` and `desktop_binding` and the service rejects mismatches | Depends on those bindings being derived correctly (Q1). |
| T9 | Malformed / hostile message | Magic + version + reserved + length checks before allocation; strict field parsing with no tolerance | none material |
| T10 | Truncated message | Explicit length checks at every field read; short reads are `TruncatedMessage` | none material |
| T11 | Oversized message | `payload_length > 4096` rejected **before** allocating | none material |
| T12 | Unknown protocol version | Rejected with `UnsupportedVersion`; never parsed best-effort (R2) | none material |
| T13 | Resource-exhaustion DoS | Bounded instances, bounded in-flight requests, bounded seen-set, bounded read sizes, per-connection deadlines | An attacker that can occupy the allowed connections degrades the tile; the tile then fails over to another provider (ADR-0002 R6). |
| T14 | Slow-loris / hang | Every read/write has a deadline; the state machine has an absolute request deadline | none material |
| T15 | Service restart mid-request | Client sees disconnect, moves to `Failed`, DENY. In-flight server state is not persisted - a restart voids everything | Correct by construction: a restarted service must never honour a pre-restart request. |
| T16 | Client disconnect mid-request | Server abandons the exchange and drops state at its next I/O boundary; the post-verification deadline check stops a late decision producing an Allow | A synchronous v1 server does not notice until the backend returns. A verification already running still finishes, still holding its worker and the concurrency gate - the deadline check bounds the decision, not the call. See sections 5.8 and 5.9, and criterion B16. |
| T17 | Concurrent requests | `ConcurrencyGate` (thread-safe) admits one in-flight verification; a `ServerSession` constructed with a gate holds it across `verify()`, so a second concurrent session is rejected with `Busy` rather than queued. Proven by `server_sessions_sharing_a_gate_cannot_verify_concurrently`, which uses a backend that genuinely blocks inside `verify()`. | The gate is a counting primitive, not a production accept loop: it models admission control only, and says nothing about queueing or fairness. A legitimate second user is refused, not queued. |
| T18 | Log-based leakage | Privacy-safe diagnostics (section 5.5) | Correlation from timing/counts remains possible; treated as acceptable. |

### 5.5 Diagnostics and privacy

Mirrors Phase 1's `SecurityLogger` discipline (`src/faceauth/logging_utils.py`)
in the native layer:

- Only `string` / `int64` / `bool` field values. There is no way to pass a
  buffer.
- A field-name denylist (`password`, `secret`, `embedding`, `template`,
  `image`, `frame`, `biometric`, `nonce`, `pin`, `key`, `certificate`) rejects
  the event outright rather than redacting it, so a mistake is loud.
- Identifiers are emitted as a short truncated hex prefix, never in full, so a
  log cannot be used to reconstruct a `request_id` and mount T4.
- Outcomes are logged as coarse reason codes. No similarity scores, no
  thresholds, no per-attempt biometric telemetry.
- The verification service logs *that* a verification happened and its coarse
  outcome. It never logs why the face did or did not match.

### 5.6 Limits (normative)

| Limit | Value |
|---|---|
| Max payload | 4096 bytes |
| Max total message | 4112 bytes |
| Max opaque field | 128 bytes (`account_binding`), 64 bytes (`desktop_binding`) |
| Max concurrent connections | 4 |
| Max in-flight verifications | 1 |
| Max request lifetime | 30 s (hard cap, regardless of requested deadline) |
| Result validity | 5 s, and never longer than the request deadline |
| Replay seen-set | 1024 entries, evicted by expiry then by age |
| Per-connection idle timeout | 5 s |

### 5.7 Fail-closed rules (normative)

1. Anything not explicitly an `outcome == allow` in a fully validated,
   unexpired, unconsumed, correctly bound `VerifyResult` is a **DENY**.
2. A parse failure is a DENY, never a retry.
3. A timeout is a DENY and releases the tile so another provider can be used.
4. A disconnect is a DENY.
5. An invalid state transition is a DENY and terminates the exchange.
6. An unknown `reason_code` in an otherwise-valid result is still evaluated on
   `outcome` alone; unknown reasons never upgrade a deny.
7. An unknown protocol version is a DENY.
8. When in doubt, DENY. There is no code path whose default is allow.

### 5.8 Cancellation is deferred to Phase 3, not half-implemented

**Version 1 has no cancellation message, and nothing in this repository claims
otherwise.**

An earlier draft defined a `CancelRequest` (message type 3). It was removed,
because it could not have worked. A version-1 `ServerSession` handles a request
by calling `IVerificationBackend::verify()` **synchronously**; while that call
is running the server is not reading its transport, so a cancellation could
only ever have been observed *between* requests - which is not cancellation of
anything. Keeping the message would have meant advertising a control the
implementation did not provide, which is precisely the class of defect this
review exists to remove.

What version 1 provides instead:

- **`ClientSession::abandon()`** - the client stops waiting and moves to a
  terminal `Abandoned` state. **Client abandonment is local and sends nothing.
  The server remains unaware. A synchronous in-flight backend continues holding
  its worker and concurrency gate until it returns. The post-verification
  deadline check prevents a late decision from producing `Allow`, but it does
  not bound or interrupt the backend call. B16 requires the Phase 3 design to
  make the call itself genuinely bounded and cancellable.**
  `abandoning_a_client_leaves_the_server_untouched` and
  `a_synchronous_backend_holds_its_worker_until_it_returns` assert those two
  uncomfortable halves in the native suite.
- **A bounded CLIENT deadline plus bounded transport reads**, which is what
  actually stops the provider tile hanging: the client stops waiting on its own
  schedule and fails over to another credential tile regardless of what the
  server is doing. This is a property of the client alone - it does **not**
  mean the server side is bounded (R8, section 5.9).

**Phase 3 requirement.** Real in-flight cancellation needs all of:

1. an asynchronous or event-loop server that can read its transport while a
   verification is running;
2. a cancellable verification backend (the camera capture and the pipeline both
   need cancellation points);
3. a new message type and therefore a **protocol version bump** - type 3 stays
   reserved until then;
4. state-machine transitions for "cancelled mid-verification" on both sides,
   with the same fail-closed guarantees as every other terminal state.

None of that exists in Phase 2, and none of it should be added before ADR-0002's
blockers clear.

### 5.9 The server deadline is enforced AFTER the backend returns

An earlier revision recorded the server's deadline on arrival and then never
looked at the clock again. That is not a deadline; it is a note. A backend that
overran its window still produced an `Allow`, and the result's TTL was computed
from the *original* lifetime rather than from what was actually left - handing
the client a window the server no longer had.

Version 1 now checks **twice**, against two separate readings of the server's
own monotonic clock:

1. **On arrival** - the request's lifetime is validated and clamped, and the
   server's own deadline is set from its own clock.
2. **On completion** - a *fresh* reading is taken after `verify()` returns. If
   `completion >= deadline`, the exchange fails closed with `RequestExpired`
   and **no `VerifyResult` is emitted at all** - the client receives a
   `ProtocolError`, so a stale decision can never be mistaken for a live one.

The result TTL is then
`min(kMaxResultValidityMs, deadline - completion)` - what is genuinely left,
never the original lifetime.

`ErrorCode::RequestExpired` is used for both checks deliberately.
`ErrorCode::Timeout` is reserved for transport-level waits (a read that
produced nothing), so the two remain distinguishable in diagnostics.

**The honest limitation.** This bounds the *decision*, not the *call*. In
version 1 `IVerificationBackend::verify()` is invoked **synchronously**, so
while it runs:

- the calling thread is held until it returns;
- the concurrency gate stays held (it is released by an RAII guard on every
  exit, including an exception, but not before the call finishes);
- `ServerSession::on_timeout()` cannot preempt it - nothing is reading the
  transport, and no other code in the session is running.

A backend that hangs forever therefore still hangs its worker. The
post-verification check guarantees such a backend can never produce an `Allow`;
it does not guarantee the worker comes back. Making the call itself bounded and
interruptible requires an asynchronous or otherwise preemptible service design
and a cancellable backend, which is **entry criterion B16** and Phase 3 work.

### 5.10 Backend exceptions are contained at the session boundary

`IVerificationBackend` is the least trustworthy interface in the design - it is
where camera and ML code would eventually live. If it throws:

- the exception is caught at the `ServerSession` boundary and never escapes;
- the session fails closed with `ErrorCode::InternalError`;
- a valid `ProtocolError` reply is produced, and **no `Allow` is emitted**;
- the session is left in the terminal `Failed` state;
- the concurrency gate is released by its RAII guard as the stack unwinds, so
  `in_flight()` returns to zero and admission control is not wedged for the
  rest of the machine's uptime.

A manual acquire/release pair leaked the gate on any non-local exit, which
would have meant a single misbehaving backend permanently blocking every
subsequent verification. That is why the guard is RAII rather than a pair of
calls.

## 6. What is implemented in Phase 2, and what is not

**Implemented** (`native/`, inert, normal desktop, no privileges):

- The versioned wire contract and its limits.
- Strict serialization and parsing with explicit truncation/oversize/version
  handling.
- Both state machines with invalid-transition detection.
- Cryptographically random `request_id`/`nonce` generation
  (`BCryptGenRandom` on Windows).
- Replay detection (duplicate request IDs, reused nonces).
- Deadline handling against an injectable **monotonic** clock, checked on
  arrival **and again after the backend returns**, with half-open windows
  (section 5.9).
- Result TTL computed from the time genuinely remaining at completion.
- Backend exceptions contained, failing closed with the concurrency gate
  released by an RAII guard (section 5.10).
- Local client abandonment (no message sent).
- Thread-safe replay cache and a thread-safe concurrency gate that a
  `ServerSession` really does hold across its verification.
- Single-use, request/identity/nonce/deadline-bound result consumption.
- Privacy-safe structured diagnostics.
- A fake client and a fake server using **opaque test identities and simulated
  allow/deny outcomes only**, whose output is explicitly labelled
  `PROTOCOL-TEST RESULT (NOT A WINDOWS AUTHENTICATION DECISION)`.
- A Windows named-pipe transport with **genuinely bounded** connect, read, and
  write, using `FILE_FLAG_OVERLAPPED`, per-operation `OVERLAPPED` structures
  with manual-reset events, `GetOverlappedResultEx` for the bounded wait, and
  `CancelIoEx` plus a blocking drain on expiry. `close()` never calls
  `FlushFileBuffers`, which would wait on the peer.
- Inert interface declarations marking the future provider/service boundaries.

**Not implemented, deliberately:**

- No `ICredentialProvider` implementation, no COM registration, no CLSID.
- No Windows service, no SCM interaction.
- No credential serialization; no `KERB_*` structure is constructed anywhere.
- No TPM, NCrypt, or certificate access.
- No camera access in the native code.
- No SDDL construction for a *privileged* endpoint. The fake transport's pipe
  is owned by the running user and is for protocol testing only; section 5.2's
  service SDDL, service SID, System-integrity label, and
  `ImpersonateNamedPipeClient` token check are a specification for Phase 3.
- **No in-flight cancellation** (section 5.8).
- **No bound on the backend CALL itself** - only on the decision it produces
  (section 5.9). A synchronous backend that hangs holds its worker and the
  concurrency gate until it returns.
- No production accept loop, connection queue, or fairness policy.

## 7. Security implications

1. The narrow, fixed-size format makes the content prohibitions in 2.1
   auditable by reading one header file rather than by trusting a policy.
2. Fail-closed is a property of the state machine, not of scattered error
   handling: every terminal state other than a validated allow is a deny.
3. The design's honest weak point is stated in section 5.2 (SYSTEM-level peers)
   and section 5.4 T7 (TOCTOU). Both are recorded as accepted residual risk.
4. Diagnostics reject rather than redact, so a privacy mistake fails visibly in
   tests instead of silently shipping.

## 8. Deployment limitations

- The endpoint's ACL depends on the per-service SID existing, which depends on
  the service being installed with a restricted SID type (ADR-0002). Not done
  in Phase 2.
- Message-mode pipes cap a single message; the 4 KB limit is deliberate and
  must not be raised to accommodate new fields. Adding a field means a new
  protocol version.
- Any protocol change is a version bump. Version 1 is frozen once Phase 3
  starts.

## 9. Unresolved questions

| # | Question | Owner phase |
|---|---|---|
| Q1 | How exactly is `account_binding` derived, so it is stable, non-secret, non-guessable-as-an-authorization, and genuinely tied to one Windows identity? A raw SID is stable but enumerable; a random per-enrollment handle is better but needs its own mapping store. | 3 |
| Q2 | Is `session_id` + `desktop_binding` sufficient to bind a request to the real logon desktop, and what are they at the moment LogonUI is running? | 3 |
| Q3 | Should the client require a code-signature check of the server binary in addition to the ACL, given section 5.2's SYSTEM limitation? | 3 |
| Q4 | What is the right result-validity window once real end-to-end latency is measured (ADR-0002 B2)? 5 s is a placeholder. | 3 |
| Q5 | What does the asynchronous/interruptible server shape look like that makes in-flight cancellation possible (sections 5.8 and 5.9), what bounds the backend call itself, and what protocol version introduces it? See entry criterion B16. | 3 |

## 10. Status

**GO** for the design and the inert scaffold. Activation is blocked on
ADR-0001 (a real credential) and ADR-0002 (B1, B2).
