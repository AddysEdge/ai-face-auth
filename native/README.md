# `native/` - Phase 2 IPC contract scaffold

**This is not a Credential Provider. This is not a Windows service. Nothing
here performs, requests, or reports a Windows authentication decision.**

It is an inert, normal-desktop C++ implementation of the versioned IPC contract
specified in [`../docs/adr/0003-ipc-security-protocol.md`](../docs/adr/0003-ipc-security-protocol.md),
plus a fake client/server pair that exercises every failure path in that
contract. It exists so the protocol's security properties can be reviewed and
tested now, before any privileged component is written.

## What is here

| Path | Purpose |
|---|---|
| `include/faceauth/ipc/protocol.hpp` | Version-1 message set, limits, error codes |
| `include/faceauth/ipc/wire.hpp`, `src/wire.cpp` | Strict serialization and parsing |
| `include/faceauth/ipc/state_machine.hpp`, `src/state_machine.cpp` | Client and server state machines, concurrency admission |
| `include/faceauth/ipc/replay_cache.hpp`, `src/replay_cache.cpp` | Duplicate request-ID and nonce-replay rejection |
| `include/faceauth/ipc/random.hpp`, `src/random.cpp` | CSPRNG request IDs and nonces (`BCryptGenRandom` on Windows) |
| `include/faceauth/ipc/clock.hpp` | Injectable **monotonic** clock. No wall clock takes part in any security decision |
| `include/faceauth/ipc/diagnostics.hpp`, `src/diagnostics.cpp` | Privacy-safe structured events with a field denylist |
| `include/faceauth/ipc/boundaries.hpp` | **Inert** interface declarations marking the future provider/service boundaries |
| `include/faceauth/ipc/transport.hpp`, `src/transport_*.cpp` | In-memory transport, and a user-owned loopback named pipe |
| `include/faceauth/ipc/fake_peer.hpp`, `src/fake_peer.cpp` | Fake client and fake server |
| `tools/fake_peer_main.cpp` | `faceauth_ipc_fake` - runs one protocol exchange |
| `tests/test_protocol.cpp` | 70 protocol test cases |
| `tests/test_named_pipe.cpp` | 8 Windows named-pipe test cases, all with CTest timeouts |

## What is deliberately absent

No `ICredentialProvider` implementation. No COM registration, CLSID, or `.reg`
file. No credential provider filter. No service, SCM code, or installer. No
credential serialization - no `KERB_*` structure is constructed anywhere. No
TPM, NCrypt, CNG, or certificate access. No camera access. No registry read or
write. No undocumented API. No Microsoft sample code copied or adapted.

The full exclusion list is in
[`../docs/PHASE2_ACCEPTANCE_CRITERIA.md`](../docs/PHASE2_ACCEPTANCE_CRITERIA.md)
Part C.

## Requirements

- Windows x64
- MSVC (Visual Studio 2022 Build Tools or newer, "Desktop development with C++")
- CMake 3.21 or newer
- C++20

No third-party runtime dependencies. On Windows the only extra libraries are OS
components already present: `bcrypt` (CSPRNG) and `advapi32` (the SDDL helper
used by the user-owned test pipe).

## Build and test

From the repository root.

### x64 Debug

```powershell
cmake -S native -B native/build -A x64
cmake --build native/build --config Debug
ctest --test-dir native/build -C Debug --output-on-failure
```

### x64 Release

```powershell
cmake --build native/build --config Release
ctest --test-dir native/build -C Release --output-on-failure
```

Warnings are errors by default (`/W4 /permissive- /WX`). To build with warnings
non-fatal while iterating:

```powershell
cmake -S native -B native/build -A x64 -DFACEAUTH_WARNINGS_AS_ERRORS=OFF
```

`native/build/` is gitignored. No build output, object file, executable, or
debug symbol is ever committed.

### Running the fake peers directly

```powershell
native\build\Debug\faceauth_ipc_fake.exe --memory        # scripted ALLOW
native\build\Debug\faceauth_ipc_fake.exe --memory-deny   # scripted DENY
native\build\Debug\faceauth_ipc_fake.exe --pipe          # user-owned loopback named pipe
```

Every outcome printed is labelled
`PROTOCOL-TEST RESULT (NOT A WINDOWS AUTHENTICATION DECISION)`.

## About the named-pipe mode

`--pipe` creates a pipe named `faceauth-phase2-PROTOCOL-TEST-<pid>`, owned by
the invoking user, in that user's own session. It is created with:

- an **explicit** security descriptor (`D:P(A;;GA;;;<current-user-SID>)`) - never
  the NULL default, whose ACLs per Microsoft's own `CreateNamedPipe`
  documentation "grant read access to members of the Everyone group and the
  anonymous account";
- `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a squatter causes a loud failure rather
  than a silent hijack;
- `PIPE_REJECT_REMOTE_CLIENTS`;
- message-mode framing.

**This is not the Phase 3 endpoint.** The privileged endpoint specified in
ADR-0003 section 5.2 - created by a service, DACL limited to `SYSTEM` and
`NT SERVICE\FaceAuthVerifier`, System-integrity mandatory label, with an
`ImpersonateNamedPipeClient` token check - is a Phase 3 deliverable, and
building it here would mean creating the very endpoint this phase must not
create.

## Test coverage

The Phase 2 brief's required native test list maps to these CTest cases:

| Required | Test |
|---|---|
| Valid request/response flow | `protocol.valid_request_response_flow` |
| Denied verification | `protocol.denied_verification_is_reported_as_deny` |
| Malformed messages | `protocol.malformed_message_is_rejected` |
| Truncated messages | `protocol.truncated_message_is_rejected` |
| Unknown protocol versions | `protocol.unknown_protocol_version_is_rejected` |
| Oversized messages | `protocol.oversized_message_is_rejected_before_allocation` |
| Duplicate request IDs | `protocol.duplicate_request_id_is_rejected` |
| Reserved/removed message type | `protocol.reserved_message_type_3_is_rejected` |
| Replayed nonces | `protocol.replayed_nonce_is_rejected` |
| Expired requests | `protocol.expired_request_is_rejected_by_server`, `protocol.expired_result_cannot_be_consumed`, `protocol.result_arriving_after_the_deadline_is_rejected` |
| Monotonic-only expiry | `protocol.wire_format_carries_no_absolute_timestamp`, `protocol.client_deadline_is_derived_from_its_own_monotonic_clock`, `protocol.server_deadline_is_derived_from_its_own_monotonic_clock`, `protocol.result_ttl_cannot_extend_the_client_deadline`, `protocol.expiry_advances_only_with_the_injected_monotonic_clock` |
| Timeouts | `protocol.client_timeout_denies`, `protocol.server_timeout_while_idle_is_an_invalid_transition`, and the whole `named_pipe.*` group for real bounded I/O |
| Cancellation | **Not implemented - deliberately deferred.** See "Cancellation is deferred" below. `protocol.client_can_abandon_locally_without_sending_anything` and `protocol.abandoning_a_client_leaves_the_server_untouched` document what version 1 actually does. |
| Invalid state transitions | `protocol.client_invalid_state_transition`, `protocol.server_invalid_state_transition`, `protocol.client_rejects_a_request_message_from_the_server`, `protocol.server_rejects_a_result_message_from_the_client` |
| Client disconnect | `protocol.server_handles_client_disconnect`, `protocol.mid_request_disconnect_denies` |
| Server disconnect | `protocol.client_handles_server_disconnect` |
| Concurrent requests | `protocol.concurrency_gate_admits_only_the_configured_number_simultaneously` (8 real threads released together), `protocol.server_sessions_sharing_a_gate_cannot_verify_concurrently` (two sessions, a backend that genuinely blocks inside `verify()`), `protocol.replay_cache_is_safe_under_concurrent_observers` |
| Incorrect identity binding | `protocol.result_with_wrong_identity_binding_is_rejected`, `protocol.result_with_wrong_request_id_is_rejected`, `protocol.result_with_wrong_nonce_is_rejected` |
| Reuse of a successful result | `protocol.successful_result_cannot_be_reused` |

Plus service-restart behaviour, replay-cache eviction and its fail-closed full
state, result-lifetime capping, opaque-field length caps, CSPRNG quality, and
the privacy properties of the diagnostics layer.

**Totals on Windows:** 70 named protocol tests + 8 named-pipe tests + 1
aggregate entry (`protocol.all_registered_tests`) + 3 fake-peer entries =
**82 CTest entries**. On a non-Windows host the 8 named-pipe entries and 1
fake-peer entry are not registered, leaving 73.

The lists in `CMakeLists.txt` are generated from, and cross-checked against, the
`FACEAUTH_TEST(...)` declarations in the sources - a test that exists in a
source file but is missing from the list is caught by
`protocol.all_registered_tests`, which runs everything the binary knows about.

## Bounded I/O is a tested property, not a claim

An earlier version of the named-pipe transport ignored the caller's timeout
entirely and used blocking `ConnectNamedPipe`/`ReadFile`/`WriteFile`. Its tests
passed, because none of them ever faced an unresponsive peer.

Every operation now uses `FILE_FLAG_OVERLAPPED` with its own `OVERLAPPED` and a
manual-reset event, waits with `GetOverlappedResultEx` (a real millisecond
bound), and on expiry calls `CancelIoEx` for that exact operation followed by a
blocking `GetOverlappedResult` drain - because Microsoft documents that
`CancelIoEx` "does not wait for all canceled operations to complete" and that
the `OVERLAPPED` must not be freed or reused until they have. `close()` never
calls `FlushFileBuffers`, which waits for the peer to drain.

The `named_pipe.*` tests each create a peer that deliberately does nothing, and
assert both the `Timeout`/`Disconnected` result **and** that the call returned
inside a sane bound. Every one carries a CTest `TIMEOUT` property, so a
regression that reintroduced blocking I/O fails the run instead of hanging it.

## Cancellation is deferred, not implemented

Protocol version 1 has **no cancellation message**, and message type 3 is
permanently reserved. A v1 server calls its verification backend synchronously,
so it cannot read a cancellation while verifying - the message could only ever
have been handled between requests, which is not cancellation of anything.

What exists instead is `ClientSession::abandon()`: the client stops waiting
locally and sends nothing; the server's own monotonic deadline releases its
side. `protocol.abandoning_a_client_leaves_the_server_untouched` asserts the
uncomfortable half of that honestly - a verification already in flight still
runs to completion.

Real in-flight cancellation needs an asynchronous server, a cancellable
backend, and a protocol version bump. See ADR-0003 section 5.8 and entry
criterion B16.

## The concurrency gate: what it does and does not model

`ConcurrencyGate` is a small, thread-safe counting gate. A `ServerSession`
constructed with one really does acquire it before verifying and release it
afterwards, so two concurrent sessions sharing a gate cannot both run a
verification - `protocol.server_sessions_sharing_a_gate_cannot_verify_concurrently`
proves it with a backend that blocks inside `verify()`.

It does **not** model a production accept loop, a queue, or any fairness
policy. Those are Phase 3 concerns, and this scaffold does not claim them.

## Provenance and licensing

All code in this directory is original work for this repository, licensed under
the repository's MIT licence. **No Microsoft sample code was copied or
adapted.** Where Microsoft documentation is relied on for a factual claim about
Windows behaviour, the claim is quoted and cited inline in the relevant ADR
under `../docs/adr/`, not reproduced as code.
