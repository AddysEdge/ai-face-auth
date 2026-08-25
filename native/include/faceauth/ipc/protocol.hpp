// Versioned IPC contract for the (not yet implemented) FaceAuth verification
// channel. See docs/adr/0003-ipc-security-protocol.md for the specification
// this file implements and for the threat model it is built against.
//
// SCOPE NOTE - read before changing anything here.
//
// Nothing in this library talks to Windows authentication. It implements a
// message contract and a state machine, and it is exercised only by the fake
// client/server pair in tools/, on the normal desktop, with opaque test
// identities and simulated outcomes.
//
// The message set below deliberately has NO free-form field, NO blob, and NO
// unbounded-length value. That is a security property, not an oversight: it is
// what makes "this channel can never carry a frame, an embedding, a template,
// a password, a PIN, a certificate, a key, or a reusable assertion" checkable
// by reading one header instead of by trusting a policy document. Adding such
// a field would require a protocol version bump and a fresh security review.
//
// NO ABSOLUTE TIMESTAMP APPEARS ON THE WIRE. Lifetimes are bounded, relative
// millisecond durations, and each side derives its own deadline from its own
// monotonic clock. See clock.hpp for why.

#ifndef FACEAUTH_IPC_PROTOCOL_HPP
#define FACEAUTH_IPC_PROTOCOL_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace faceauth::ipc {

// "FAP1" read as a little-endian uint32.
inline constexpr std::uint32_t kMagic = 0x31504146u;
inline constexpr std::uint16_t kProtocolVersion = 1u;

inline constexpr std::size_t kHeaderBytes = 16u;
inline constexpr std::size_t kMaxPayloadBytes = 4096u;
inline constexpr std::size_t kMaxMessageBytes = kHeaderBytes + kMaxPayloadBytes;

inline constexpr std::size_t kRequestIdBytes = 16u;
inline constexpr std::size_t kNonceBytes = 32u;
inline constexpr std::size_t kMaxAccountBindingBytes = 128u;
inline constexpr std::size_t kMaxDesktopBindingBytes = 64u;

// Normative limits from ADR-0003 section 5.6. All durations are relative
// milliseconds, enforced against a local monotonic clock.
inline constexpr std::uint32_t kMaxRequestLifetimeMs = 30000u;
inline constexpr std::uint32_t kMaxResultValidityMs = 5000u;
inline constexpr std::size_t kReplayCacheCapacity = 1024u;
inline constexpr std::size_t kMaxConcurrentConnections = 4u;
inline constexpr std::size_t kMaxInFlightVerifications = 1u;
inline constexpr std::uint32_t kIdleTimeoutMs = 5000u;

enum class MessageType : std::uint16_t {
    VerifyRequest = 1,
    VerifyResult = 2,
    // 3 is RESERVED and permanently unassigned in protocol version 1.
    //
    // It held a CancelRequest in an earlier draft. That was removed rather
    // than kept, because a version-1 server processes a request synchronously
    // and therefore cannot read a cancellation while a verification is in
    // flight - so the message could only ever have been handled between
    // requests, which is not cancellation. Shipping it would have meant
    // claiming a control that did not exist.
    //
    // Real in-flight cancellation is a Phase 3 requirement and needs a
    // protocol version bump plus a concurrent server. See ADR-0003 section 6.
    // A message of type 3 is rejected as UnknownMessageType.
    ProtocolError = 4,
};

// Deliberately not named "Granted"/"Denied": these are protocol-test outcomes,
// never Windows authentication decisions.
enum class Outcome : std::uint8_t {
    Deny = 0,
    Allow = 1,
};

enum class ErrorCode : std::uint16_t {
    None = 0,
    MalformedMessage = 1,
    TruncatedMessage = 2,
    UnsupportedVersion = 3,
    MessageTooLarge = 4,
    DuplicateRequestId = 5,
    ReplayedNonce = 6,
    RequestExpired = 7,
    Timeout = 8,
    Abandoned = 9,
    InvalidStateTransition = 10,
    PeerDisconnected = 11,
    IdentityMismatch = 12,
    ResultAlreadyConsumed = 13,
    Busy = 14,
    VerificationFailed = 15,
    InternalError = 16,
    UnknownMessageType = 17,
    LimitExceeded = 18,
};

const char* to_string(MessageType value);
const char* to_string(Outcome value);
const char* to_string(ErrorCode value);

using RequestId = std::array<std::uint8_t, kRequestIdBytes>;
using Nonce = std::array<std::uint8_t, kNonceBytes>;

// An opaque, length-capped identifier. NOT a secret, NOT a credential, NOT a
// biometric value. See ADR-0003 Q1 for how a real account binding would be
// derived in Phase 3.
using OpaqueBinding = std::vector<std::uint8_t>;

struct VerifyRequest {
    RequestId request_id{};
    Nonce nonce{};
    OpaqueBinding account_binding{};
    std::uint32_t session_id = 0;
    OpaqueBinding desktop_binding{};

    // A bounded RELATIVE duration, not a point in time. The client asks for at
    // most this long; the server independently clamps it and starts its own
    // monotonic deadline on arrival. Neither side trusts the other's clock.
    std::uint32_t requested_lifetime_ms = 0;

    std::uint32_t flags = 0;
};

struct VerifyResult {
    RequestId request_id{};
    Nonce nonce{};
    OpaqueBinding account_binding{};
    Outcome outcome = Outcome::Deny;
    std::uint16_t reason_code = 0;

    // Again relative, not absolute. The client clamps this to
    // kMaxResultValidityMs AND to its own already-running request deadline, so
    // a result can only ever shorten the client's window, never extend it.
    std::uint32_t result_ttl_ms = 0;
};

struct ProtocolErrorMessage {
    RequestId request_id{};
    ErrorCode error_code = ErrorCode::InternalError;
};

// Returns a short lowercase hex prefix of an identifier, for diagnostics only.
// Full identifiers are never logged: a log that contained a whole request_id
// or nonce would itself become a replay aid (ADR-0003 section 5.5).
std::string hex_prefix(const std::uint8_t* data, std::size_t length,
                       std::size_t prefix_bytes = 4);

std::string hex_prefix(const RequestId& id, std::size_t prefix_bytes = 4);

bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t length);

bool operator==(const VerifyRequest& lhs, const VerifyRequest& rhs);
bool operator==(const VerifyResult& lhs, const VerifyResult& rhs);

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_PROTOCOL_HPP
