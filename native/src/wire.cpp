#include "faceauth/ipc/wire.hpp"

#include <cstring>

namespace faceauth::ipc {
namespace {

void put_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
    }
}

void put_bytes(std::vector<std::uint8_t>& out, const std::uint8_t* data, std::size_t length) {
    out.insert(out.end(), data, data + length);
}

// Length-prefixed opaque field. The cap is enforced by the caller before this
// is reached; encoding an over-long field is an internal error, not a
// truncation.
void put_opaque(std::vector<std::uint8_t>& out, const OpaqueBinding& value) {
    put_u16(out, static_cast<std::uint16_t>(value.size()));
    if (!value.empty()) {
        put_bytes(out, value.data(), value.size());
    }
}

// A cursor that can only move forward and never past the end. Every read
// returns false rather than reading out of bounds, and the caller turns that
// into TruncatedMessage.
class Reader {
public:
    Reader(const std::uint8_t* data, std::size_t length) : data_(data), length_(length) {}

    bool read_u8(std::uint8_t& out) {
        if (remaining() < 1u) return false;
        out = data_[offset_++];
        return true;
    }

    bool read_u16(std::uint16_t& out) {
        if (remaining() < 2u) return false;
        out = static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[offset_]) |
                                         (static_cast<std::uint16_t>(data_[offset_ + 1]) << 8));
        offset_ += 2u;
        return true;
    }

    bool read_u32(std::uint32_t& out) {
        if (remaining() < 4u) return false;
        std::uint32_t value = 0;
        for (std::size_t i = 0; i < 4u; ++i) {
            value |= static_cast<std::uint32_t>(data_[offset_ + i]) << (8u * i);
        }
        offset_ += 4u;
        out = value;
        return true;
    }

    bool read_u64(std::uint64_t& out) {
        if (remaining() < 8u) return false;
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 8u; ++i) {
            value |= static_cast<std::uint64_t>(data_[offset_ + i]) << (8u * i);
        }
        offset_ += 8u;
        out = value;
        return true;
    }

    bool read_fixed(std::uint8_t* out, std::size_t count) {
        if (remaining() < count) return false;
        std::memcpy(out, data_ + offset_, count);
        offset_ += count;
        return true;
    }

    // `max_length` is checked before any allocation, so a hostile length
    // prefix cannot make us reserve memory.
    bool read_opaque(OpaqueBinding& out, std::size_t max_length) {
        std::uint16_t declared = 0;
        if (!read_u16(declared)) return false;
        if (static_cast<std::size_t>(declared) > max_length) return false;
        if (remaining() < static_cast<std::size_t>(declared)) return false;
        out.assign(data_ + offset_, data_ + offset_ + declared);
        offset_ += declared;
        return true;
    }

    std::size_t remaining() const { return length_ - offset_; }
    bool exhausted() const { return offset_ == length_; }

private:
    const std::uint8_t* data_;
    std::size_t length_;
    std::size_t offset_ = 0;
};

void put_header(std::vector<std::uint8_t>& out, MessageType type, std::size_t payload_length) {
    put_u32(out, kMagic);
    put_u16(out, kProtocolVersion);
    put_u16(out, static_cast<std::uint16_t>(type));
    put_u32(out, static_cast<std::uint32_t>(payload_length));
    put_u32(out, 0u);
}

std::vector<std::uint8_t> frame(MessageType type, const std::vector<std::uint8_t>& payload) {
    if (payload.size() > kMaxPayloadBytes) {
        return {};
    }
    std::vector<std::uint8_t> out;
    out.reserve(kHeaderBytes + payload.size());
    put_header(out, type, payload.size());
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

bool is_known_type(std::uint16_t raw) {
    return raw == static_cast<std::uint16_t>(MessageType::VerifyRequest) ||
           raw == static_cast<std::uint16_t>(MessageType::VerifyResult) ||
           raw == static_cast<std::uint16_t>(MessageType::CancelRequest) ||
           raw == static_cast<std::uint16_t>(MessageType::ProtocolError);
}

bool is_known_error_code(std::uint16_t raw) {
    return raw <= static_cast<std::uint16_t>(ErrorCode::LimitExceeded);
}

}  // namespace

std::vector<std::uint8_t> encode(const VerifyRequest& message) {
    if (message.account_binding.empty() ||
        message.account_binding.size() > kMaxAccountBindingBytes ||
        message.desktop_binding.size() > kMaxDesktopBindingBytes) {
        return {};
    }
    std::vector<std::uint8_t> payload;
    put_bytes(payload, message.request_id.data(), message.request_id.size());
    put_bytes(payload, message.nonce.data(), message.nonce.size());
    put_opaque(payload, message.account_binding);
    put_u32(payload, message.session_id);
    put_opaque(payload, message.desktop_binding);
    put_u64(payload, message.deadline_unix_ms);
    put_u32(payload, message.flags);
    return frame(MessageType::VerifyRequest, payload);
}

std::vector<std::uint8_t> encode(const VerifyResult& message) {
    if (message.account_binding.empty() ||
        message.account_binding.size() > kMaxAccountBindingBytes) {
        return {};
    }
    std::vector<std::uint8_t> payload;
    put_bytes(payload, message.request_id.data(), message.request_id.size());
    put_bytes(payload, message.nonce.data(), message.nonce.size());
    put_opaque(payload, message.account_binding);
    payload.push_back(static_cast<std::uint8_t>(message.outcome));
    put_u16(payload, message.reason_code);
    put_u64(payload, message.expires_unix_ms);
    return frame(MessageType::VerifyResult, payload);
}

std::vector<std::uint8_t> encode(const CancelRequest& message) {
    std::vector<std::uint8_t> payload;
    put_bytes(payload, message.request_id.data(), message.request_id.size());
    return frame(MessageType::CancelRequest, payload);
}

std::vector<std::uint8_t> encode(const ProtocolErrorMessage& message) {
    std::vector<std::uint8_t> payload;
    put_bytes(payload, message.request_id.data(), message.request_id.size());
    put_u16(payload, static_cast<std::uint16_t>(message.error_code));
    return frame(MessageType::ProtocolError, payload);
}

ErrorCode decode_header(const std::uint8_t* data, std::size_t length, MessageHeader& out) {
    if (data == nullptr || length < kHeaderBytes) {
        return ErrorCode::TruncatedMessage;
    }
    Reader reader(data, kHeaderBytes);
    MessageHeader header{};
    if (!reader.read_u32(header.magic) || !reader.read_u16(header.protocol_version) ||
        !reader.read_u16(header.message_type) || !reader.read_u32(header.payload_length) ||
        !reader.read_u32(header.reserved)) {
        return ErrorCode::TruncatedMessage;
    }
    if (header.magic != kMagic) {
        return ErrorCode::MalformedMessage;
    }
    if (header.protocol_version != kProtocolVersion) {
        return ErrorCode::UnsupportedVersion;
    }
    if (!is_known_type(header.message_type)) {
        return ErrorCode::UnknownMessageType;
    }
    if (header.reserved != 0u) {
        return ErrorCode::MalformedMessage;
    }
    // Checked before the caller allocates a payload buffer of this size.
    if (static_cast<std::size_t>(header.payload_length) > kMaxPayloadBytes) {
        return ErrorCode::MessageTooLarge;
    }
    out = header;
    return ErrorCode::None;
}

DecodeResult decode_message(const std::uint8_t* data, std::size_t length) {
    DecodeResult result{};
    MessageHeader header{};
    const ErrorCode header_error = decode_header(data, length, header);
    if (header_error != ErrorCode::None) {
        result.error = header_error;
        return result;
    }

    const std::size_t expected_total = kHeaderBytes + static_cast<std::size_t>(header.payload_length);
    if (length < expected_total) {
        result.error = ErrorCode::TruncatedMessage;
        return result;
    }
    if (length > expected_total) {
        // Trailing bytes are never tolerated: an unread tail is exactly where
        // a smuggled payload would live.
        result.error = ErrorCode::MalformedMessage;
        return result;
    }

    Reader reader(data + kHeaderBytes, static_cast<std::size_t>(header.payload_length));
    result.message.type = static_cast<MessageType>(header.message_type);

    switch (result.message.type) {
        case MessageType::VerifyRequest: {
            VerifyRequest& message = result.message.request;
            if (!reader.read_fixed(message.request_id.data(), message.request_id.size()) ||
                !reader.read_fixed(message.nonce.data(), message.nonce.size()) ||
                !reader.read_opaque(message.account_binding, kMaxAccountBindingBytes) ||
                !reader.read_u32(message.session_id) ||
                !reader.read_opaque(message.desktop_binding, kMaxDesktopBindingBytes) ||
                !reader.read_u64(message.deadline_unix_ms) || !reader.read_u32(message.flags)) {
                result.error = ErrorCode::TruncatedMessage;
                return result;
            }
            if (message.account_binding.empty()) {
                result.error = ErrorCode::MalformedMessage;
                return result;
            }
            if (message.flags != 0u) {
                // Reserved. An unknown flag must never be ignored.
                result.error = ErrorCode::MalformedMessage;
                return result;
            }
            break;
        }
        case MessageType::VerifyResult: {
            VerifyResult& message = result.message.result;
            std::uint8_t outcome_raw = 0;
            if (!reader.read_fixed(message.request_id.data(), message.request_id.size()) ||
                !reader.read_fixed(message.nonce.data(), message.nonce.size()) ||
                !reader.read_opaque(message.account_binding, kMaxAccountBindingBytes) ||
                !reader.read_u8(outcome_raw) || !reader.read_u16(message.reason_code) ||
                !reader.read_u64(message.expires_unix_ms)) {
                result.error = ErrorCode::TruncatedMessage;
                return result;
            }
            if (message.account_binding.empty()) {
                result.error = ErrorCode::MalformedMessage;
                return result;
            }
            // Anything that is not exactly Allow is a Deny. There is no
            // "unrecognised, therefore permissive" branch anywhere.
            if (outcome_raw != static_cast<std::uint8_t>(Outcome::Allow) &&
                outcome_raw != static_cast<std::uint8_t>(Outcome::Deny)) {
                result.error = ErrorCode::MalformedMessage;
                return result;
            }
            message.outcome = static_cast<Outcome>(outcome_raw);
            break;
        }
        case MessageType::CancelRequest: {
            CancelRequest& message = result.message.cancel;
            if (!reader.read_fixed(message.request_id.data(), message.request_id.size())) {
                result.error = ErrorCode::TruncatedMessage;
                return result;
            }
            break;
        }
        case MessageType::ProtocolError: {
            ProtocolErrorMessage& message = result.message.error;
            std::uint16_t code_raw = 0;
            if (!reader.read_fixed(message.request_id.data(), message.request_id.size()) ||
                !reader.read_u16(code_raw)) {
                result.error = ErrorCode::TruncatedMessage;
                return result;
            }
            if (!is_known_error_code(code_raw)) {
                result.error = ErrorCode::MalformedMessage;
                return result;
            }
            message.error_code = static_cast<ErrorCode>(code_raw);
            break;
        }
    }

    if (!reader.exhausted()) {
        result.error = ErrorCode::MalformedMessage;
        return result;
    }
    return result;
}

DecodeResult decode_message(const std::vector<std::uint8_t>& bytes) {
    return decode_message(bytes.data(), bytes.size());
}

}  // namespace faceauth::ipc
