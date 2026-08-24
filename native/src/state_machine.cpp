#include "faceauth/ipc/state_machine.hpp"

#include <utility>

#include "faceauth/ipc/wire.hpp"

namespace faceauth::ipc {
namespace {

RequestId zero_request_id() {
    RequestId id{};
    id.fill(0u);
    return id;
}

std::vector<std::uint8_t> make_error_reply(const RequestId& request_id, ErrorCode error) {
    ProtocolErrorMessage message{};
    message.request_id = request_id;
    message.error_code = error;
    return encode(message);
}

}  // namespace

const char* to_string(ClientState state) {
    switch (state) {
        case ClientState::Idle: return "Idle";
        case ClientState::AwaitingResult: return "AwaitingResult";
        case ClientState::ResultAvailable: return "ResultAvailable";
        case ClientState::Consumed: return "Consumed";
        case ClientState::Cancelled: return "Cancelled";
        case ClientState::Failed: return "Failed";
    }
    return "Unknown";
}

const char* to_string(ServerState state) {
    switch (state) {
        case ServerState::Idle: return "Idle";
        case ServerState::Processing: return "Processing";
        case ServerState::Responded: return "Responded";
        case ServerState::Cancelled: return "Cancelled";
        case ServerState::Failed: return "Failed";
    }
    return "Unknown";
}

// ---------------------------------------------------------------------------
// ClientSession
// ---------------------------------------------------------------------------

ClientSession::ClientSession(RequestId request_id, Nonce nonce, OpaqueBinding account_binding,
                             std::uint32_t session_id, OpaqueBinding desktop_binding,
                             std::uint64_t deadline_unix_ms) {
    request_.request_id = request_id;
    request_.nonce = nonce;
    request_.account_binding = std::move(account_binding);
    request_.session_id = session_id;
    request_.desktop_binding = std::move(desktop_binding);
    request_.deadline_unix_ms = deadline_unix_ms;
    request_.flags = 0u;
}

ErrorCode ClientSession::fail(ErrorCode error) {
    state_ = ClientState::Failed;
    last_error_ = error;
    return error;
}

ErrorCode ClientSession::start(std::vector<std::uint8_t>& out_message) {
    if (state_ != ClientState::Idle) {
        return fail(ErrorCode::InvalidStateTransition);
    }
    out_message = encode(request_);
    if (out_message.empty()) {
        return fail(ErrorCode::InternalError);
    }
    state_ = ClientState::AwaitingResult;
    return ErrorCode::None;
}

ErrorCode ClientSession::on_message(const std::vector<std::uint8_t>& message,
                                    std::uint64_t now_unix_ms) {
    if (state_ != ClientState::AwaitingResult) {
        return fail(ErrorCode::InvalidStateTransition);
    }

    const DecodeResult decoded = decode_message(message);
    if (!decoded.ok()) {
        return fail(decoded.error);
    }

    switch (decoded.message.type) {
        case MessageType::VerifyResult: {
            const VerifyResult& result = decoded.message.result;
            // Request-to-result, nonce, and identity binding are all checked
            // here, before the result is ever exposed to a caller.
            if (!constant_time_equal(result.request_id.data(), request_.request_id.data(),
                                     kRequestIdBytes) ||
                !constant_time_equal(result.nonce.data(), request_.nonce.data(), kNonceBytes) ||
                result.account_binding.size() != request_.account_binding.size() ||
                !constant_time_equal(result.account_binding.data(),
                                     request_.account_binding.data(),
                                     request_.account_binding.size())) {
                return fail(ErrorCode::IdentityMismatch);
            }
            if (now_unix_ms > request_.deadline_unix_ms) {
                return fail(ErrorCode::RequestExpired);
            }
            result_ = result;
            state_ = ClientState::ResultAvailable;
            return ErrorCode::None;
        }
        case MessageType::ProtocolError:
            return fail(decoded.message.error.error_code);
        case MessageType::VerifyRequest:
        case MessageType::CancelRequest:
            // A client never receives these. Receiving one means the peer is
            // not what it claims to be.
            return fail(ErrorCode::InvalidStateTransition);
    }
    return fail(ErrorCode::UnknownMessageType);
}

ErrorCode ClientSession::on_timeout(std::uint64_t now_unix_ms) {
    (void)now_unix_ms;
    if (state_ != ClientState::AwaitingResult) {
        return fail(ErrorCode::InvalidStateTransition);
    }
    return fail(ErrorCode::Timeout);
}

ErrorCode ClientSession::on_peer_disconnect() {
    if (state_ == ClientState::Consumed) {
        // Already finished; a disconnect afterwards is not an error.
        return ErrorCode::None;
    }
    return fail(ErrorCode::PeerDisconnected);
}

ErrorCode ClientSession::cancel(std::vector<std::uint8_t>& out_message) {
    if (state_ != ClientState::AwaitingResult && state_ != ClientState::ResultAvailable) {
        return fail(ErrorCode::InvalidStateTransition);
    }
    CancelRequest message{};
    message.request_id = request_.request_id;
    out_message = encode(message);
    if (out_message.empty()) {
        return fail(ErrorCode::InternalError);
    }
    state_ = ClientState::Cancelled;
    last_error_ = ErrorCode::Cancelled;
    return ErrorCode::None;
}

ErrorCode ClientSession::consume(std::uint64_t now_unix_ms, Outcome& out_outcome) {
    out_outcome = Outcome::Deny;

    if (state_ == ClientState::Consumed) {
        // Single-use: the second attempt to spend a result always fails.
        last_error_ = ErrorCode::ResultAlreadyConsumed;
        return ErrorCode::ResultAlreadyConsumed;
    }
    if (state_ != ClientState::ResultAvailable) {
        return fail(ErrorCode::InvalidStateTransition);
    }
    if (now_unix_ms > result_.expires_unix_ms || now_unix_ms > request_.deadline_unix_ms) {
        return fail(ErrorCode::RequestExpired);
    }

    state_ = ClientState::Consumed;
    last_error_ = ErrorCode::None;
    out_outcome = result_.outcome;
    return ErrorCode::None;
}

// ---------------------------------------------------------------------------
// ServerSession
// ---------------------------------------------------------------------------

ServerSession::ServerSession(IVerificationBackend& backend, ReplayCache& replay_cache)
    : backend_(backend), replay_cache_(replay_cache) {}

ErrorCode ServerSession::fail(ErrorCode error, const RequestId& request_id,
                              std::vector<std::uint8_t>& out_message) {
    state_ = ServerState::Failed;
    last_error_ = error;
    out_message = make_error_reply(request_id, error);
    return error;
}

ErrorCode ServerSession::on_message(const std::vector<std::uint8_t>& message,
                                    std::uint64_t now_unix_ms,
                                    std::vector<std::uint8_t>& out_message) {
    out_message.clear();

    const DecodeResult decoded = decode_message(message);
    if (!decoded.ok()) {
        // The request_id is unknown for an unparseable message, so the error
        // reply carries a zeroed one rather than guessing.
        return fail(decoded.error, zero_request_id(), out_message);
    }

    switch (decoded.message.type) {
        case MessageType::VerifyRequest: {
            if (state_ != ServerState::Idle) {
                return fail(ErrorCode::InvalidStateTransition, decoded.message.request.request_id,
                            out_message);
            }
            const VerifyRequest& request = decoded.message.request;

            if (request.deadline_unix_ms <= now_unix_ms) {
                return fail(ErrorCode::RequestExpired, request.request_id, out_message);
            }
            // A caller cannot buy itself an unbounded window by asking for one.
            if (request.deadline_unix_ms - now_unix_ms > kMaxRequestLifetimeMs) {
                return fail(ErrorCode::LimitExceeded, request.request_id, out_message);
            }

            const ErrorCode replay = replay_cache_.observe(request.request_id, request.nonce,
                                                           request.deadline_unix_ms, now_unix_ms);
            if (replay != ErrorCode::None) {
                return fail(replay, request.request_id, out_message);
            }

            active_request_ = request;
            state_ = ServerState::Processing;

            const VerificationDecision decision = backend_.verify(request, now_unix_ms);

            VerifyResult result{};
            result.request_id = request.request_id;
            result.nonce = request.nonce;
            result.account_binding = request.account_binding;
            result.outcome = decision.outcome;
            result.reason_code = decision.reason_code;
            // Short-lived, and never outliving the request that produced it.
            const std::uint64_t validity_end = now_unix_ms + kMaxResultValidityMs;
            result.expires_unix_ms =
                (validity_end < request.deadline_unix_ms) ? validity_end : request.deadline_unix_ms;

            out_message = encode(result);
            if (out_message.empty()) {
                return fail(ErrorCode::InternalError, request.request_id, out_message);
            }
            state_ = ServerState::Responded;
            last_error_ = ErrorCode::None;
            return ErrorCode::None;
        }
        case MessageType::CancelRequest: {
            if (state_ != ServerState::Processing) {
                return fail(ErrorCode::InvalidStateTransition, decoded.message.cancel.request_id,
                            out_message);
            }
            if (!constant_time_equal(decoded.message.cancel.request_id.data(),
                                     active_request_.request_id.data(), kRequestIdBytes)) {
                return fail(ErrorCode::IdentityMismatch, decoded.message.cancel.request_id,
                            out_message);
            }
            state_ = ServerState::Cancelled;
            last_error_ = ErrorCode::Cancelled;
            return ErrorCode::Cancelled;
        }
        case MessageType::VerifyResult:
        case MessageType::ProtocolError:
            // A server never receives these from a well-behaved client.
            return fail(ErrorCode::InvalidStateTransition, zero_request_id(), out_message);
    }
    return fail(ErrorCode::UnknownMessageType, zero_request_id(), out_message);
}

ErrorCode ServerSession::on_timeout(std::uint64_t now_unix_ms,
                                    std::vector<std::uint8_t>& out_message) {
    (void)now_unix_ms;
    out_message.clear();
    if (state_ != ServerState::Processing) {
        return fail(ErrorCode::InvalidStateTransition, zero_request_id(), out_message);
    }
    return fail(ErrorCode::Timeout, active_request_.request_id, out_message);
}

ErrorCode ServerSession::on_peer_disconnect() {
    // Whatever was in flight is abandoned. Nothing is persisted, so a later
    // reconnect - or a service restart - can never resume it (ADR-0003 T15).
    state_ = ServerState::Failed;
    last_error_ = ErrorCode::PeerDisconnected;
    active_request_ = VerifyRequest{};
    return ErrorCode::PeerDisconnected;
}

// ---------------------------------------------------------------------------
// ConcurrencyGate
// ---------------------------------------------------------------------------

ErrorCode ConcurrencyGate::acquire() {
    if (in_flight_ >= max_in_flight_) {
        return ErrorCode::Busy;
    }
    ++in_flight_;
    return ErrorCode::None;
}

void ConcurrencyGate::release() {
    if (in_flight_ > 0u) {
        --in_flight_;
    }
}

}  // namespace faceauth::ipc
