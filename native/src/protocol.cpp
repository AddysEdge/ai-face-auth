#include "faceauth/ipc/protocol.hpp"

namespace faceauth::ipc {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

}  // namespace

const char* to_string(MessageType value) {
    switch (value) {
        case MessageType::VerifyRequest: return "VerifyRequest";
        case MessageType::VerifyResult: return "VerifyResult";
        case MessageType::CancelRequest: return "CancelRequest";
        case MessageType::ProtocolError: return "ProtocolError";
    }
    return "Unknown";
}

const char* to_string(Outcome value) {
    switch (value) {
        case Outcome::Deny: return "deny";
        case Outcome::Allow: return "allow";
    }
    return "unknown";
}

const char* to_string(ErrorCode value) {
    switch (value) {
        case ErrorCode::None: return "None";
        case ErrorCode::MalformedMessage: return "MalformedMessage";
        case ErrorCode::TruncatedMessage: return "TruncatedMessage";
        case ErrorCode::UnsupportedVersion: return "UnsupportedVersion";
        case ErrorCode::MessageTooLarge: return "MessageTooLarge";
        case ErrorCode::DuplicateRequestId: return "DuplicateRequestId";
        case ErrorCode::ReplayedNonce: return "ReplayedNonce";
        case ErrorCode::RequestExpired: return "RequestExpired";
        case ErrorCode::Timeout: return "Timeout";
        case ErrorCode::Cancelled: return "Cancelled";
        case ErrorCode::InvalidStateTransition: return "InvalidStateTransition";
        case ErrorCode::PeerDisconnected: return "PeerDisconnected";
        case ErrorCode::IdentityMismatch: return "IdentityMismatch";
        case ErrorCode::ResultAlreadyConsumed: return "ResultAlreadyConsumed";
        case ErrorCode::Busy: return "Busy";
        case ErrorCode::VerificationFailed: return "VerificationFailed";
        case ErrorCode::InternalError: return "InternalError";
        case ErrorCode::UnknownMessageType: return "UnknownMessageType";
        case ErrorCode::LimitExceeded: return "LimitExceeded";
    }
    return "Unknown";
}

std::string hex_prefix(const std::uint8_t* data, std::size_t length, std::size_t prefix_bytes) {
    if (data == nullptr) {
        return std::string{};
    }
    const std::size_t count = (prefix_bytes < length) ? prefix_bytes : length;
    std::string out;
    out.reserve(count * 2u);
    for (std::size_t i = 0; i < count; ++i) {
        out.push_back(kHexDigits[(data[i] >> 4) & 0x0Fu]);
        out.push_back(kHexDigits[data[i] & 0x0Fu]);
    }
    return out;
}

std::string hex_prefix(const RequestId& id, std::size_t prefix_bytes) {
    return hex_prefix(id.data(), id.size(), prefix_bytes);
}

bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t length) {
    if (a == nullptr || b == nullptr) {
        return false;
    }
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < length; ++i) {
        diff = static_cast<std::uint8_t>(diff | static_cast<std::uint8_t>(a[i] ^ b[i]));
    }
    return diff == 0;
}

bool operator==(const VerifyRequest& lhs, const VerifyRequest& rhs) {
    return lhs.request_id == rhs.request_id && lhs.nonce == rhs.nonce &&
           lhs.account_binding == rhs.account_binding && lhs.session_id == rhs.session_id &&
           lhs.desktop_binding == rhs.desktop_binding &&
           lhs.deadline_unix_ms == rhs.deadline_unix_ms && lhs.flags == rhs.flags;
}

bool operator==(const VerifyResult& lhs, const VerifyResult& rhs) {
    return lhs.request_id == rhs.request_id && lhs.nonce == rhs.nonce &&
           lhs.account_binding == rhs.account_binding && lhs.outcome == rhs.outcome &&
           lhs.reason_code == rhs.reason_code && lhs.expires_unix_ms == rhs.expires_unix_ms;
}

}  // namespace faceauth::ipc
