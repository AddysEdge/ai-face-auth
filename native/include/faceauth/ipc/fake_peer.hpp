// Fake client and fake server, for protocol testing on the normal desktop.
//
// THESE ARE NOT AUTHENTICATION COMPONENTS.
//
//   * The "identity" is an opaque test string supplied by the caller. It is
//     not a Windows account, not a SID, and is never resolved against one.
//   * The outcome comes from a scripted IVerificationBackend. No camera is
//     opened, no image is captured, no face is compared, and no biometric code
//     is reachable from here.
//   * Every outcome is reported as a PROTOCOL-TEST RESULT, never as a Windows
//     authentication decision. See kProtocolTestResultLabel.
//
// Their only job is to prove the contract in ADR-0003 behaves as specified,
// including all of its failure paths.
//
// Both take a MonotonicClock. No wall clock is involved anywhere.

#ifndef FACEAUTH_IPC_FAKE_PEER_HPP
#define FACEAUTH_IPC_FAKE_PEER_HPP

#include <cstdint>
#include <string>

#include "faceauth/ipc/boundaries.hpp"
#include "faceauth/ipc/clock.hpp"
#include "faceauth/ipc/diagnostics.hpp"
#include "faceauth/ipc/protocol.hpp"
#include "faceauth/ipc/replay_cache.hpp"
#include "faceauth/ipc/state_machine.hpp"
#include "faceauth/ipc/transport.hpp"

namespace faceauth::ipc {

inline constexpr const char* kProtocolTestResultLabel =
    "PROTOCOL-TEST RESULT (NOT A WINDOWS AUTHENTICATION DECISION)";

struct FakeClientResult {
    bool completed = false;
    Outcome outcome = Outcome::Deny;
    ErrorCode error = ErrorCode::None;
    ClientState final_state = ClientState::Idle;
};

struct FakeClientOptions {
    // Opaque test identity. Never a Windows account name, never a SID.
    std::string test_identity = "opaque-test-identity-a";
    std::uint32_t session_id = 0;
    std::string test_desktop = "opaque-test-desktop";

    // Relative, bounded. Not a point in time.
    std::uint32_t requested_lifetime_ms = 10000;

    std::uint32_t receive_timeout_ms = 3000;
    std::uint32_t send_timeout_ms = 3000;

    // Stop waiting locally, without sending anything. Version 1 has no
    // cancellation message; see MessageType in protocol.hpp.
    bool abandon_after_send = false;
};

// Drives one full client exchange over `transport`. Returns a DENY on every
// error path, without exception.
FakeClientResult run_fake_client(Transport& transport, const FakeClientOptions& options,
                                 MonotonicClock& mono_clock, DiagnosticSink& diagnostics);

// Serves exactly one exchange over `transport`. `gate` is optional; when
// supplied it is applied around the verification, so two concurrent fake
// servers sharing one gate genuinely contend.
ErrorCode run_fake_server(Transport& transport, IVerificationBackend& backend,
                          ReplayCache& replay_cache, MonotonicClock& mono_clock,
                          DiagnosticSink& diagnostics, std::uint32_t receive_timeout_ms = 3000,
                          ConcurrencyGate* gate = nullptr);

// Converts an opaque test identity string into the wire binding. Exposed so
// tests can construct a deliberately mismatched binding.
OpaqueBinding to_binding(const std::string& text);

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_FAKE_PEER_HPP
