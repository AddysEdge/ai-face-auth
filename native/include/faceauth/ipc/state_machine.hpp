// Explicit protocol state machines (ADR-0003 section 5.3).
//
// Fail-closed is a property of these state machines rather than of scattered
// error handling: every terminal state except a validated, consumed ALLOW
// means DENY. There is no state, and no transition, whose default is allow.
//
// Neither class performs I/O. They consume and produce encoded messages, which
// keeps them deterministically testable and keeps transport concerns (pipes,
// timeouts, disconnects) out of the security logic.
//
// TIME BASE - the important part.
//
// Every `now_steady_ms` argument is the CALLER'S OWN monotonic clock reading
// (clock.hpp). Neither side ever receives, sends, or trusts an absolute
// timestamp:
//
//   * The client starts its own deadline before sending, from its own clock.
//   * The request carries only a bounded, relative `requested_lifetime_ms`.
//   * The server clamps that lifetime and starts its OWN deadline on arrival.
//   * The result carries only a bounded, relative `result_ttl_ms`.
//   * The client caps result validity by the smaller of its own remaining
//     request lifetime, the received TTL, and the protocol maximum - so a
//     result can only ever SHORTEN the client's window, never extend it.
//
// A wall-clock jump therefore cannot lengthen or shorten either side's
// enforced validity, because no wall clock is consulted at any point.
//
// EXPIRY IS HALF-OPEN, EVERYWHERE.
//
//     valid    when now <  deadline
//     expired  when now >= deadline
//
// So a deadline instant is already too late, and a zero-length window is
// never usable. Requests, results, and replay-cache entries all follow this
// rule; a mixture would leave a one-millisecond seam where two components
// disagreed about whether something was still alive.

#ifndef FACEAUTH_IPC_STATE_MACHINE_HPP
#define FACEAUTH_IPC_STATE_MACHINE_HPP

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

#include "faceauth/ipc/boundaries.hpp"
#include "faceauth/ipc/clock.hpp"
#include "faceauth/ipc/protocol.hpp"
#include "faceauth/ipc/replay_cache.hpp"

namespace faceauth::ipc {

enum class ClientState {
    Idle,
    AwaitingResult,
    ResultAvailable,
    Consumed,
    // The client stopped waiting. Purely local: protocol version 1 has no
    // cancellation message, so nothing is sent and the server is not told.
    // The server's own deadline cleans its side up. See MessageType in
    // protocol.hpp for why real cancellation is deferred to Phase 3.
    Abandoned,
    Failed,
};

enum class ServerState {
    Idle,
    Processing,
    Responded,
    Failed,
};

const char* to_string(ClientState state);
const char* to_string(ServerState state);

// ---------------------------------------------------------------------------
// Client side - what a Phase 3 credential provider would drive.
// ---------------------------------------------------------------------------
class ClientSession {
public:
    // `requested_lifetime_ms` is a relative duration. It is clamped to
    // kMaxRequestLifetimeMs; a zero value is rejected at start().
    ClientSession(RequestId request_id, Nonce nonce, OpaqueBinding account_binding,
                  std::uint32_t session_id, OpaqueBinding desktop_binding,
                  std::uint32_t requested_lifetime_ms);

    ClientState state() const { return state_; }
    ErrorCode last_error() const { return last_error_; }
    const VerifyRequest& request() const { return request_; }

    // Idle -> AwaitingResult. Starts this client's own monotonic deadline from
    // `now_steady_ms` BEFORE producing the encoded VerifyRequest, so the
    // window is already running when the message goes out.
    ErrorCode start(std::uint64_t now_steady_ms, std::vector<std::uint8_t>& out_message);

    // Feeds one inbound message. Validates binding immediately: a result whose
    // request_id, nonce, or account_binding does not match this session is an
    // IdentityMismatch and terminates the session, never a retry.
    ErrorCode on_message(const std::vector<std::uint8_t>& message, std::uint64_t now_steady_ms);

    ErrorCode on_timeout(std::uint64_t now_steady_ms);
    ErrorCode on_peer_disconnect();

    // Local-only abandonment. Sends nothing - version 1 has no cancel message.
    ErrorCode abandon();

    // The single-use gate. Succeeds exactly once, and only from
    // ResultAvailable with an unexpired result. Every other call fails.
    ErrorCode consume(std::uint64_t now_steady_ms, Outcome& out_outcome);

    // Test/observability accessors for the locally derived deadlines. These
    // are this process's monotonic values and are never serialized.
    std::uint64_t request_deadline_steady_ms() const { return request_deadline_steady_ms_; }
    std::uint64_t result_deadline_steady_ms() const { return result_deadline_steady_ms_; }

private:
    ErrorCode fail(ErrorCode error);

    VerifyRequest request_{};
    VerifyResult result_{};
    ClientState state_ = ClientState::Idle;
    ErrorCode last_error_ = ErrorCode::None;
    std::uint64_t request_deadline_steady_ms_ = 0;
    std::uint64_t result_deadline_steady_ms_ = 0;
};

// ---------------------------------------------------------------------------
// Server side - what a Phase 3 verification service would drive.
// ---------------------------------------------------------------------------
class ConcurrencyGate;

class ServerSession {
public:
    // The session reads time from `clock` itself rather than being told what
    // time it is. That is deliberate: the deadline has to be re-checked AFTER
    // the backend returns, and a caller-supplied "now" captured before the
    // verification started cannot express that. `gate` is optional; when
    // supplied the session holds it across the verification.
    ServerSession(IVerificationBackend& backend, ReplayCache& replay_cache,
                  MonotonicClock& clock, ConcurrencyGate* gate = nullptr);

    ServerState state() const { return state_; }
    ErrorCode last_error() const { return last_error_; }

    // Handles one inbound message and, where a reply is due, writes the encoded
    // reply into `out_message`. Every rejection produces a ProtocolError reply
    // and moves to a terminal state; nothing is silently ignored.
    //
    // The deadline is enforced TWICE: once on arrival, and again after the
    // backend returns. A verification that overran its window can therefore
    // never produce an Allow - see ADR-0003 section 5.9.
    ErrorCode on_message(const std::vector<std::uint8_t>& message,
                         std::vector<std::uint8_t>& out_message);

    // Transport-level: no message arrived while the session was waiting.
    //
    // THIS CANNOT INTERRUPT A RUNNING VERIFICATION. In protocol version 1 the
    // backend is called synchronously, so while it runs, this session is not
    // reading anything and nobody is in a position to call this. It exists for
    // the "waited for a request and none came" case only. A backend that hangs
    // holds its worker thread and the concurrency gate until it returns; the
    // post-verification deadline check bounds the *decision*, not the *call*.
    // Making the call itself interruptible is Phase 3 work (criterion B16).
    ErrorCode on_timeout(std::vector<std::uint8_t>& out_message);

    ErrorCode on_peer_disconnect();

    // This session's own monotonic deadline, set on arrival. Never serialized.
    std::uint64_t request_deadline_steady_ms() const { return request_deadline_steady_ms_; }

private:
    ErrorCode fail(ErrorCode error, const RequestId& request_id,
                   std::vector<std::uint8_t>& out_message);

    IVerificationBackend& backend_;
    ReplayCache& replay_cache_;
    MonotonicClock& clock_;
    ConcurrencyGate* gate_;
    VerifyRequest active_request_{};
    ServerState state_ = ServerState::Idle;
    ErrorCode last_error_ = ErrorCode::None;
    std::uint64_t request_deadline_steady_ms_ = 0;
};

// Machine-wide admission control for concurrent verifications
// (ADR-0002 section 5.6: one camera, one verification at a time).
//
// SCOPE OF THE CLAIM: this is a small, thread-safe counting gate. When a
// ServerSession is constructed with one, that session really does acquire it
// before verifying and release it afterwards, so two concurrent sessions
// sharing a gate cannot both run a verification. What it does NOT model is a
// production service's connection accept loop, queueing, or fairness - those
// are Phase 3 concerns.
class ConcurrencyGate {
public:
    explicit ConcurrencyGate(std::size_t max_in_flight = kMaxInFlightVerifications)
        : max_in_flight_(max_in_flight) {}

    ConcurrencyGate(const ConcurrencyGate&) = delete;
    ConcurrencyGate& operator=(const ConcurrencyGate&) = delete;

    // Returns ErrorCode::Busy when the configured number of verifications is
    // already in flight. A second request is rejected outright rather than
    // queued behind a camera lock, so the logon screen never waits on another
    // user's attempt.
    ErrorCode acquire();
    void release();

    std::size_t in_flight() const;

private:
    mutable std::mutex mutex_;
    std::size_t max_in_flight_;
    std::size_t in_flight_ = 0;
};

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_STATE_MACHINE_HPP
