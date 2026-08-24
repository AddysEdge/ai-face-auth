// Explicit protocol state machines (ADR-0003 section 5.3).
//
// Fail-closed is a property of these state machines rather than of scattered
// error handling: every terminal state except a validated, consumed ALLOW
// means DENY. There is no state, and no transition, whose default is allow.
//
// Neither class performs I/O. They consume and produce encoded messages, which
// keeps them deterministically testable and keeps transport concerns (pipes,
// timeouts, disconnects) out of the security logic.

#ifndef FACEAUTH_IPC_STATE_MACHINE_HPP
#define FACEAUTH_IPC_STATE_MACHINE_HPP

#include <cstdint>
#include <vector>

#include "faceauth/ipc/boundaries.hpp"
#include "faceauth/ipc/protocol.hpp"
#include "faceauth/ipc/replay_cache.hpp"

namespace faceauth::ipc {

enum class ClientState {
    Idle,
    AwaitingResult,
    ResultAvailable,
    Consumed,
    Cancelled,
    Failed,
};

enum class ServerState {
    Idle,
    Processing,
    Responded,
    Cancelled,
    Failed,
};

const char* to_string(ClientState state);
const char* to_string(ServerState state);

// ---------------------------------------------------------------------------
// Client side - what a Phase 3 credential provider would drive.
// ---------------------------------------------------------------------------
class ClientSession {
public:
    ClientSession(RequestId request_id, Nonce nonce, OpaqueBinding account_binding,
                  std::uint32_t session_id, OpaqueBinding desktop_binding,
                  std::uint64_t deadline_unix_ms);

    ClientState state() const { return state_; }
    ErrorCode last_error() const { return last_error_; }
    const VerifyRequest& request() const { return request_; }

    // Idle -> AwaitingResult. Produces the encoded VerifyRequest.
    ErrorCode start(std::vector<std::uint8_t>& out_message);

    // Feeds one inbound message. Validates binding immediately: a result whose
    // request_id, nonce, or account_binding does not match this session is an
    // IdentityMismatch and terminates the session, never a retry.
    ErrorCode on_message(const std::vector<std::uint8_t>& message, std::uint64_t now_unix_ms);

    ErrorCode on_timeout(std::uint64_t now_unix_ms);
    ErrorCode on_peer_disconnect();

    // AwaitingResult -> Cancelled. Produces the encoded CancelRequest.
    ErrorCode cancel(std::vector<std::uint8_t>& out_message);

    // The single-use gate. Succeeds exactly once, and only from
    // ResultAvailable with an unexpired result. Every other call fails.
    ErrorCode consume(std::uint64_t now_unix_ms, Outcome& out_outcome);

private:
    ErrorCode fail(ErrorCode error);

    VerifyRequest request_{};
    VerifyResult result_{};
    ClientState state_ = ClientState::Idle;
    ErrorCode last_error_ = ErrorCode::None;
};

// ---------------------------------------------------------------------------
// Server side - what a Phase 3 verification service would drive.
// ---------------------------------------------------------------------------
class ServerSession {
public:
    ServerSession(IVerificationBackend& backend, ReplayCache& replay_cache);

    ServerState state() const { return state_; }
    ErrorCode last_error() const { return last_error_; }

    // Handles one inbound message and, where a reply is due, writes the encoded
    // reply into `out_message`. Every rejection produces a ProtocolError reply
    // and moves to a terminal state; nothing is silently ignored.
    ErrorCode on_message(const std::vector<std::uint8_t>& message, std::uint64_t now_unix_ms,
                         std::vector<std::uint8_t>& out_message);

    ErrorCode on_timeout(std::uint64_t now_unix_ms, std::vector<std::uint8_t>& out_message);
    ErrorCode on_peer_disconnect();

private:
    ErrorCode fail(ErrorCode error, const RequestId& request_id,
                   std::vector<std::uint8_t>& out_message);

    IVerificationBackend& backend_;
    ReplayCache& replay_cache_;
    VerifyRequest active_request_{};
    ServerState state_ = ServerState::Idle;
    ErrorCode last_error_ = ErrorCode::None;
};

// A machine-wide admission control for concurrent verifications
// (ADR-0002 section 5.6: one camera, one verification at a time).
class ConcurrencyGate {
public:
    explicit ConcurrencyGate(std::size_t max_in_flight = kMaxInFlightVerifications)
        : max_in_flight_(max_in_flight) {}

    // Returns ErrorCode::Busy when a verification is already in flight. A
    // second request is rejected outright rather than queued behind a camera
    // lock, so the logon screen never waits on another user's attempt.
    ErrorCode acquire();
    void release();

    std::size_t in_flight() const { return in_flight_; }

private:
    std::size_t max_in_flight_;
    std::size_t in_flight_ = 0;
};

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_STATE_MACHINE_HPP
