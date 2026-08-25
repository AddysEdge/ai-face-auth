// Strict serialization and parsing for the version-1 wire format.
//
// Parsing rules, in the order they are applied (ADR-0003 section 5.1):
//   1. at least kHeaderBytes present            -> else TruncatedMessage
//   2. magic matches                            -> else MalformedMessage
//   3. protocol_version == kProtocolVersion     -> else UnsupportedVersion
//   4. message_type is known                    -> else UnknownMessageType
//      (type 3 is reserved and unassigned in v1, so it lands here too)
//   5. reserved == 0                            -> else MalformedMessage
//   6. payload_length <= kMaxPayloadBytes       -> else MessageTooLarge
//                                                  (checked BEFORE allocating)
//   7. total size matches header exactly        -> else Truncated/Malformed
//   8. every field read is bounds-checked       -> else TruncatedMessage
//
// There is no lenient path, no "best effort" parse, and no tolerance for
// trailing bytes. A message that is not exactly right is rejected, and every
// rejection is a DENY upstream.

#ifndef FACEAUTH_IPC_WIRE_HPP
#define FACEAUTH_IPC_WIRE_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#include "faceauth/ipc/protocol.hpp"

namespace faceauth::ipc {

struct MessageHeader {
    std::uint32_t magic = 0;
    std::uint16_t protocol_version = 0;
    std::uint16_t message_type = 0;
    std::uint32_t payload_length = 0;
    std::uint32_t reserved = 0;
};

// A decoded message. Exactly one of the three bodies is meaningful, selected
// by `type`. A tagged union would be tidier; three plain members keep the type
// trivially inspectable in a debugger and cost nothing at this size.
struct DecodedMessage {
    MessageType type = MessageType::ProtocolError;
    VerifyRequest request{};
    VerifyResult result{};
    ProtocolErrorMessage error{};
};

struct DecodeResult {
    ErrorCode error = ErrorCode::None;
    DecodedMessage message{};

    bool ok() const { return error == ErrorCode::None; }
};

// Encoders. Each returns an empty vector if the message violates a limit
// (for example an over-long account_binding), which callers must treat as an
// internal error rather than sending a truncated message.
std::vector<std::uint8_t> encode(const VerifyRequest& message);
std::vector<std::uint8_t> encode(const VerifyResult& message);
std::vector<std::uint8_t> encode(const ProtocolErrorMessage& message);

// Parses only the fixed header. Used by a transport that must know how many
// payload bytes to read before reading them, and to reject an oversized
// declared length before any allocation happens.
ErrorCode decode_header(const std::uint8_t* data, std::size_t length, MessageHeader& out);

DecodeResult decode_message(const std::uint8_t* data, std::size_t length);
DecodeResult decode_message(const std::vector<std::uint8_t>& bytes);

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_WIRE_HPP
