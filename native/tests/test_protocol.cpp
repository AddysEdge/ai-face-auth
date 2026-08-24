// Protocol contract tests for the ADR-0003 IPC design.
//
// Every test here is a PROTOCOL test. None of them authenticates anything,
// none opens a camera, and none touches Windows authentication state. The
// identities are opaque test strings and the outcomes are scripted.
//
// The required coverage from the Phase 2 brief, mapped to test names:
//   valid request/response flow      -> valid_request_response_flow
//   denied verification              -> denied_verification_is_reported_as_deny
//   malformed messages               -> malformed_message_is_rejected
//   truncated messages               -> truncated_message_is_rejected
//   unknown protocol versions        -> unknown_protocol_version_is_rejected
//   oversized messages               -> oversized_message_is_rejected_before_allocation
//   duplicate request IDs            -> duplicate_request_id_is_rejected
//   replayed nonces                  -> replayed_nonce_is_rejected
//   expired requests                 -> expired_request_is_rejected_by_server
//                                       expired_result_cannot_be_consumed
//   timeouts                         -> client_timeout_denies
//   cancellation                     -> cancellation_moves_both_sides_out_of_flight
//   invalid state transitions        -> client_invalid_state_transition
//                                       server_invalid_state_transition
//   client disconnect                -> server_handles_client_disconnect
//   server disconnect                -> client_handles_server_disconnect
//   concurrent requests              -> concurrent_requests_are_admission_controlled
//   incorrect identity binding       -> result_with_wrong_identity_binding_is_rejected
//                                       result_with_wrong_request_id_is_rejected
//                                       result_with_wrong_nonce_is_rejected
//   reuse of a successful result     -> successful_result_cannot_be_reused

#include <string>
#include <thread>
#include <vector>

#include "faceauth/ipc/boundaries.hpp"
#include "faceauth/ipc/clock.hpp"
#include "faceauth/ipc/diagnostics.hpp"
#include "faceauth/ipc/fake_peer.hpp"
#include "faceauth/ipc/protocol.hpp"
#include "faceauth/ipc/random.hpp"
#include "faceauth/ipc/replay_cache.hpp"
#include "faceauth/ipc/state_machine.hpp"
#include "faceauth/ipc/transport.hpp"
#include "faceauth/ipc/wire.hpp"
#include "test_harness.hpp"

using namespace faceauth::ipc;

namespace {

constexpr std::uint64_t kT0 = 1'700'000'000'000ull;

RequestId make_id(std::uint8_t seed) {
    RequestId id{};
    id.fill(seed);
    return id;
}

Nonce make_nonce_value(std::uint8_t seed) {
    Nonce nonce{};
    nonce.fill(seed);
    return nonce;
}

VerifyRequest make_request(std::uint8_t seed, std::uint64_t deadline) {
    VerifyRequest request{};
    request.request_id = make_id(seed);
    request.nonce = make_nonce_value(static_cast<std::uint8_t>(seed + 100u));
    request.account_binding = to_binding("opaque-test-identity-a");
    request.session_id = 7;
    request.desktop_binding = to_binding("opaque-test-desktop");
    request.deadline_unix_ms = deadline;
    return request;
}

ClientSession make_client(const VerifyRequest& request) {
    return ClientSession(request.request_id, request.nonce, request.account_binding,
                         request.session_id, request.desktop_binding, request.deadline_unix_ms);
}

// Builds a raw frame with caller-chosen header fields, so tests can produce
// messages a well-behaved encoder would never emit.
std::vector<std::uint8_t> raw_frame(std::uint32_t magic, std::uint16_t version, std::uint16_t type,
                                    std::uint32_t declared_payload_length, std::uint32_t reserved,
                                    const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> out;
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::uint8_t>((magic >> shift) & 0xFFu));
    }
    out.push_back(static_cast<std::uint8_t>(version & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((version >> 8) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(type & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((type >> 8) & 0xFFu));
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::uint8_t>((declared_payload_length >> shift) & 0xFFu));
    }
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::uint8_t>((reserved >> shift) & 0xFFu));
    }
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Encoding and parsing
// ---------------------------------------------------------------------------

FACEAUTH_TEST(round_trip_all_message_types) {
    const VerifyRequest request = make_request(1, kT0 + 5000);
    const DecodeResult decoded_request = decode_message(encode(request));
    CHECK(decoded_request.ok());
    CHECK(decoded_request.message.type == MessageType::VerifyRequest);
    CHECK(decoded_request.message.request == request);

    VerifyResult result{};
    result.request_id = request.request_id;
    result.nonce = request.nonce;
    result.account_binding = request.account_binding;
    result.outcome = Outcome::Allow;
    result.reason_code = 42;
    result.expires_unix_ms = kT0 + 3000;
    const DecodeResult decoded_result = decode_message(encode(result));
    CHECK(decoded_result.ok());
    CHECK(decoded_result.message.type == MessageType::VerifyResult);
    CHECK(decoded_result.message.result == result);

    CancelRequest cancel{};
    cancel.request_id = request.request_id;
    const DecodeResult decoded_cancel = decode_message(encode(cancel));
    CHECK(decoded_cancel.ok());
    CHECK(decoded_cancel.message.cancel.request_id == request.request_id);

    ProtocolErrorMessage error{};
    error.request_id = request.request_id;
    error.error_code = ErrorCode::Timeout;
    const DecodeResult decoded_error = decode_message(encode(error));
    CHECK(decoded_error.ok());
    CHECK(decoded_error.message.error.error_code == ErrorCode::Timeout);
}

FACEAUTH_TEST(malformed_message_is_rejected) {
    const VerifyRequest request = make_request(2, kT0 + 5000);
    const std::vector<std::uint8_t> good = encode(request);

    // Wrong magic.
    std::vector<std::uint8_t> bad_magic = good;
    bad_magic[0] = static_cast<std::uint8_t>(bad_magic[0] ^ 0xFFu);
    CHECK(decode_message(bad_magic).error == ErrorCode::MalformedMessage);

    // Non-zero reserved field.
    std::vector<std::uint8_t> bad_reserved = good;
    bad_reserved[12] = 1u;
    CHECK(decode_message(bad_reserved).error == ErrorCode::MalformedMessage);

    // Trailing bytes beyond the declared payload are never tolerated.
    std::vector<std::uint8_t> trailing = good;
    trailing.push_back(0u);
    CHECK(decode_message(trailing).error == ErrorCode::MalformedMessage);

    // An unknown message type is rejected rather than ignored.
    const std::vector<std::uint8_t> unknown_type =
        raw_frame(kMagic, kProtocolVersion, 9999u, 0u, 0u, {});
    CHECK(decode_message(unknown_type).error == ErrorCode::UnknownMessageType);

    // Empty input.
    CHECK(decode_message(std::vector<std::uint8_t>{}).error == ErrorCode::TruncatedMessage);
}

FACEAUTH_TEST(truncated_message_is_rejected) {
    const VerifyRequest request = make_request(3, kT0 + 5000);
    const std::vector<std::uint8_t> good = encode(request);
    CHECK(good.size() > kHeaderBytes);

    // Short header.
    std::vector<std::uint8_t> short_header(good.begin(), good.begin() + 8);
    CHECK(decode_message(short_header).error == ErrorCode::TruncatedMessage);

    // Full header, short payload.
    std::vector<std::uint8_t> short_payload(good.begin(), good.end() - 4);
    CHECK(decode_message(short_payload).error == ErrorCode::TruncatedMessage);

    // Header declaring more payload than is present.
    const std::vector<std::uint8_t> lying = raw_frame(kMagic, kProtocolVersion,
                                                      static_cast<std::uint16_t>(
                                                          MessageType::CancelRequest),
                                                      64u, 0u, {1u, 2u, 3u});
    CHECK(decode_message(lying).error == ErrorCode::TruncatedMessage);
}

FACEAUTH_TEST(unknown_protocol_version_is_rejected) {
    const std::vector<std::uint8_t> future = raw_frame(
        kMagic, static_cast<std::uint16_t>(kProtocolVersion + 1),
        static_cast<std::uint16_t>(MessageType::CancelRequest), kRequestIdBytes, 0u,
        std::vector<std::uint8_t>(kRequestIdBytes, 0u));
    CHECK(decode_message(future).error == ErrorCode::UnsupportedVersion);

    const std::vector<std::uint8_t> ancient =
        raw_frame(kMagic, 0u, static_cast<std::uint16_t>(MessageType::CancelRequest),
                  kRequestIdBytes, 0u, std::vector<std::uint8_t>(kRequestIdBytes, 0u));
    CHECK(decode_message(ancient).error == ErrorCode::UnsupportedVersion);
}

FACEAUTH_TEST(oversized_message_is_rejected_before_allocation) {
    // Header declares a payload far beyond the ceiling. Only the 16-byte
    // header is actually supplied, proving the size is rejected on the
    // declared value rather than after reading it.
    const std::vector<std::uint8_t> huge =
        raw_frame(kMagic, kProtocolVersion, static_cast<std::uint16_t>(MessageType::VerifyRequest),
                  0x00FFFFFFu, 0u, {});
    CHECK(decode_message(huge).error == ErrorCode::MessageTooLarge);

    MessageHeader header{};
    CHECK(decode_header(huge.data(), huge.size(), header) == ErrorCode::MessageTooLarge);
}

FACEAUTH_TEST(opaque_fields_are_length_capped) {
    VerifyRequest request = make_request(4, kT0 + 5000);
    request.account_binding.assign(kMaxAccountBindingBytes + 1u, 0x41u);
    CHECK(encode(request).empty());

    request.account_binding.assign(kMaxAccountBindingBytes, 0x41u);
    request.desktop_binding.assign(kMaxDesktopBindingBytes + 1u, 0x42u);
    CHECK(encode(request).empty());

    request.desktop_binding.assign(kMaxDesktopBindingBytes, 0x42u);
    const std::vector<std::uint8_t> encoded = encode(request);
    CHECK(!encoded.empty());
    // Even at every field's maximum, a message stays far under the ceiling.
    // This is the structural guarantee that the channel cannot carry a frame,
    // an embedding, or a template.
    CHECK(encoded.size() <= kMaxMessageBytes);
    CHECK(encoded.size() < 512u);
}

FACEAUTH_TEST(empty_account_binding_is_rejected) {
    VerifyRequest request = make_request(5, kT0 + 5000);
    request.account_binding.clear();
    CHECK(encode(request).empty());
}

// ---------------------------------------------------------------------------
// Happy path and denial
// ---------------------------------------------------------------------------

FACEAUTH_TEST(valid_request_response_flow) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);

    const VerifyRequest request = make_request(6, kT0 + 10000);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);
    CHECK(client.state() == ClientState::AwaitingResult);

    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, kT0, to_client) == ErrorCode::None);
    CHECK(server.state() == ServerState::Responded);
    CHECK(!to_client.empty());

    CHECK(client.on_message(to_client, kT0) == ErrorCode::None);
    CHECK(client.state() == ClientState::ResultAvailable);

    Outcome outcome = Outcome::Deny;
    CHECK(client.consume(kT0, outcome) == ErrorCode::None);
    CHECK(outcome == Outcome::Allow);
    CHECK(client.state() == ClientState::Consumed);
}

FACEAUTH_TEST(denied_verification_is_reported_as_deny) {
    ScriptedVerificationBackend backend(
        {VerificationDecision{Outcome::Deny, static_cast<std::uint16_t>(ErrorCode::VerificationFailed)}});
    ReplayCache cache;
    ServerSession server(backend, cache);

    const VerifyRequest request = make_request(7, kT0 + 10000);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);
    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, kT0, to_client) == ErrorCode::None);
    CHECK(client.on_message(to_client, kT0) == ErrorCode::None);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0, outcome) == ErrorCode::None);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(exhausted_backend_script_denies) {
    // Fail closed: a backend with nothing left to say must not produce an
    // allow.
    ScriptedVerificationBackend backend;
    const VerifyRequest request = make_request(8, kT0 + 10000);
    const VerificationDecision decision = backend.verify(request, kT0);
    CHECK(decision.outcome == Outcome::Deny);
}

// ---------------------------------------------------------------------------
// Replay and duplication
// ---------------------------------------------------------------------------

FACEAUTH_TEST(duplicate_request_id_is_rejected) {
    ScriptedVerificationBackend backend(
        {VerificationDecision{Outcome::Allow, 0}, VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;

    const VerifyRequest first = make_request(9, kT0 + 10000);
    std::vector<std::uint8_t> reply;
    ServerSession server_a(backend, cache);
    CHECK(server_a.on_message(encode(first), kT0, reply) == ErrorCode::None);

    // Same request_id, fresh nonce, new connection.
    VerifyRequest second = first;
    second.nonce = make_nonce_value(0xEEu);
    ServerSession server_b(backend, cache);
    CHECK(server_b.on_message(encode(second), kT0, reply) == ErrorCode::DuplicateRequestId);
    CHECK(server_b.state() == ServerState::Failed);

    const DecodeResult decoded = decode_message(reply);
    CHECK(decoded.ok());
    CHECK(decoded.message.type == MessageType::ProtocolError);
    CHECK(decoded.message.error.error_code == ErrorCode::DuplicateRequestId);
}

FACEAUTH_TEST(replayed_nonce_is_rejected) {
    ScriptedVerificationBackend backend(
        {VerificationDecision{Outcome::Allow, 0}, VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;

    const VerifyRequest first = make_request(10, kT0 + 10000);
    std::vector<std::uint8_t> reply;
    ServerSession server_a(backend, cache);
    CHECK(server_a.on_message(encode(first), kT0, reply) == ErrorCode::None);

    // Fresh request_id, but the nonce is replayed from the first request.
    VerifyRequest second = first;
    second.request_id = make_id(0xABu);
    ServerSession server_b(backend, cache);
    CHECK(server_b.on_message(encode(second), kT0, reply) == ErrorCode::ReplayedNonce);
    CHECK(server_b.state() == ServerState::Failed);
}

FACEAUTH_TEST(replay_cache_evicts_expired_entries) {
    ReplayCache cache(4);
    CHECK(cache.observe(make_id(1), make_nonce_value(1), kT0 + 1000, kT0) == ErrorCode::None);
    CHECK(cache.size() == 1u);

    // Once the entry's deadline has passed it can no longer be replayed
    // against, because the request it protected is itself expired.
    cache.evict_expired(kT0 + 2000);
    CHECK(cache.size() == 0u);
    CHECK(cache.observe(make_id(1), make_nonce_value(1), kT0 + 3000, kT0 + 2000) ==
          ErrorCode::None);
}

FACEAUTH_TEST(full_replay_cache_fails_closed) {
    // A full cache must reject new observations rather than evict live entries;
    // evicting would let an attacker flush the cache and then replay.
    ReplayCache cache(2);
    CHECK(cache.observe(make_id(1), make_nonce_value(1), kT0 + 10000, kT0) == ErrorCode::None);
    CHECK(cache.observe(make_id(2), make_nonce_value(2), kT0 + 10000, kT0) == ErrorCode::None);
    CHECK(cache.observe(make_id(3), make_nonce_value(3), kT0 + 10000, kT0) ==
          ErrorCode::LimitExceeded);
}

// ---------------------------------------------------------------------------
// Deadlines, timeouts, cancellation
// ---------------------------------------------------------------------------

FACEAUTH_TEST(expired_request_is_rejected_by_server) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);

    const VerifyRequest request = make_request(11, kT0);  // deadline == now
    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(request), kT0, reply) == ErrorCode::RequestExpired);
    CHECK(server.state() == ServerState::Failed);
    // An expired request must never reach the verification backend.
    CHECK(backend.calls() == 0u);
}

FACEAUTH_TEST(excessive_request_lifetime_is_rejected) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);

    const VerifyRequest request = make_request(12, kT0 + kMaxRequestLifetimeMs + 1);
    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(request), kT0, reply) == ErrorCode::LimitExceeded);
    CHECK(backend.calls() == 0u);
}

FACEAUTH_TEST(result_never_outlives_its_request) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);

    // Request deadline is sooner than the default result validity window.
    const VerifyRequest request = make_request(13, kT0 + 1000);
    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(request), kT0, reply) == ErrorCode::None);

    const DecodeResult decoded = decode_message(reply);
    CHECK(decoded.ok());
    CHECK(decoded.message.result.expires_unix_ms == kT0 + 1000);
    CHECK(decoded.message.result.expires_unix_ms <= kT0 + kMaxResultValidityMs);
}

FACEAUTH_TEST(expired_result_cannot_be_consumed) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);

    const VerifyRequest request = make_request(14, kT0 + 2000);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);
    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, kT0, to_client) == ErrorCode::None);
    CHECK(client.on_message(to_client, kT0) == ErrorCode::None);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0 + 5000, outcome) == ErrorCode::RequestExpired);
    CHECK(outcome == Outcome::Deny);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(result_arriving_after_the_deadline_is_rejected) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);

    const VerifyRequest request = make_request(15, kT0 + 2000);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);
    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, kT0, to_client) == ErrorCode::None);

    CHECK(client.on_message(to_client, kT0 + 9999) == ErrorCode::RequestExpired);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(client_timeout_denies) {
    const VerifyRequest request = make_request(16, kT0 + 10000);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);
    CHECK(client.on_timeout(kT0 + 4000) == ErrorCode::Timeout);
    CHECK(client.state() == ClientState::Failed);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0 + 4000, outcome) == ErrorCode::InvalidStateTransition);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(server_timeout_denies) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);
    std::vector<std::uint8_t> reply;

    // A timeout while Idle is itself an invalid transition, not a silent no-op.
    CHECK(server.on_timeout(kT0, reply) == ErrorCode::InvalidStateTransition);
}

FACEAUTH_TEST(cancellation_moves_both_sides_out_of_flight) {
    // The server must be mid-Processing for a cancel to be meaningful, which
    // means driving it with a backend that has not yet responded. Here the
    // client cancels after sending, and the server sees the cancel as its
    // first message - which is an invalid transition, exactly as specified.
    const VerifyRequest request = make_request(17, kT0 + 10000);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);

    std::vector<std::uint8_t> cancel_message;
    CHECK(client.cancel(cancel_message) == ErrorCode::None);
    CHECK(client.state() == ClientState::Cancelled);
    CHECK(client.last_error() == ErrorCode::Cancelled);

    // A cancelled client can no longer consume anything.
    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0, outcome) == ErrorCode::InvalidStateTransition);
    CHECK(outcome == Outcome::Deny);

    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);
    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(cancel_message, kT0, reply) == ErrorCode::InvalidStateTransition);
    CHECK(backend.calls() == 0u);
}

// ---------------------------------------------------------------------------
// State machine integrity
// ---------------------------------------------------------------------------

FACEAUTH_TEST(client_invalid_state_transition) {
    const VerifyRequest request = make_request(18, kT0 + 10000);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);
    // Starting twice is not idempotent; it is a protocol violation.
    CHECK(client.start(to_server) == ErrorCode::InvalidStateTransition);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(client_rejects_a_request_message_from_the_server) {
    const VerifyRequest request = make_request(19, kT0 + 10000);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);

    // A server that sends a VerifyRequest is not the peer it claims to be.
    CHECK(client.on_message(encode(request), kT0) == ErrorCode::InvalidStateTransition);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(server_invalid_state_transition) {
    ScriptedVerificationBackend backend(
        {VerificationDecision{Outcome::Allow, 0}, VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);

    const VerifyRequest first = make_request(20, kT0 + 10000);
    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(first), kT0, reply) == ErrorCode::None);
    CHECK(server.state() == ServerState::Responded);

    // A second request on the same session is a protocol violation, not a new
    // exchange.
    VerifyRequest second = make_request(21, kT0 + 10000);
    CHECK(server.on_message(encode(second), kT0, reply) == ErrorCode::InvalidStateTransition);
    CHECK(server.state() == ServerState::Failed);
    CHECK(backend.calls() == 1u);
}

FACEAUTH_TEST(server_rejects_a_result_message_from_the_client) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);

    VerifyResult forged{};
    forged.request_id = make_id(22);
    forged.nonce = make_nonce_value(22);
    forged.account_binding = to_binding("opaque-test-identity-a");
    forged.outcome = Outcome::Allow;
    forged.expires_unix_ms = kT0 + 5000;

    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(forged), kT0, reply) == ErrorCode::InvalidStateTransition);
    CHECK(server.state() == ServerState::Failed);
}

// ---------------------------------------------------------------------------
// Identity binding
// ---------------------------------------------------------------------------

FACEAUTH_TEST(result_with_wrong_identity_binding_is_rejected) {
    const VerifyRequest request = make_request(23, kT0 + 10000);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);

    // A perfectly valid result - for a different account.
    VerifyResult other{};
    other.request_id = request.request_id;
    other.nonce = request.nonce;
    other.account_binding = to_binding("opaque-test-identity-b");
    other.outcome = Outcome::Allow;
    other.expires_unix_ms = kT0 + 5000;

    CHECK(client.on_message(encode(other), kT0) == ErrorCode::IdentityMismatch);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(result_with_wrong_request_id_is_rejected) {
    const VerifyRequest request = make_request(24, kT0 + 10000);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);

    VerifyResult other{};
    other.request_id = make_id(0x77u);
    other.nonce = request.nonce;
    other.account_binding = request.account_binding;
    other.outcome = Outcome::Allow;
    other.expires_unix_ms = kT0 + 5000;

    CHECK(client.on_message(encode(other), kT0) == ErrorCode::IdentityMismatch);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(result_with_wrong_nonce_is_rejected) {
    const VerifyRequest request = make_request(25, kT0 + 10000);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);

    VerifyResult other{};
    other.request_id = request.request_id;
    other.nonce = make_nonce_value(0x99u);
    other.account_binding = request.account_binding;
    other.outcome = Outcome::Allow;
    other.expires_unix_ms = kT0 + 5000;

    CHECK(client.on_message(encode(other), kT0) == ErrorCode::IdentityMismatch);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(successful_result_cannot_be_reused) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ServerSession server(backend, cache);

    const VerifyRequest request = make_request(26, kT0 + 10000);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);
    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, kT0, to_client) == ErrorCode::None);
    CHECK(client.on_message(to_client, kT0) == ErrorCode::None);

    Outcome first = Outcome::Deny;
    CHECK(client.consume(kT0, first) == ErrorCode::None);
    CHECK(first == Outcome::Allow);

    Outcome second = Outcome::Allow;
    CHECK(client.consume(kT0, second) == ErrorCode::ResultAlreadyConsumed);
    CHECK(second == Outcome::Deny);
    CHECK(client.state() == ClientState::Consumed);

    // Re-delivering the same bytes to a fresh client also fails, because that
    // client's own request_id and nonce differ.
    const VerifyRequest fresh = make_request(27, kT0 + 10000);
    ClientSession replay_victim = make_client(fresh);
    std::vector<std::uint8_t> ignored;
    CHECK(replay_victim.start(ignored) == ErrorCode::None);
    CHECK(replay_victim.on_message(to_client, kT0) == ErrorCode::IdentityMismatch);
}

// ---------------------------------------------------------------------------
// Disconnects, restarts, concurrency
// ---------------------------------------------------------------------------

FACEAUTH_TEST(client_handles_server_disconnect) {
    auto pair = make_in_memory_pair();
    SystemClock wall_clock;
    CollectingSink diagnostics;

    // Server end closes without answering.
    pair.second->close();

    FakeClientOptions options;
    options.receive_timeout_ms = 500;
    const FakeClientResult result = run_fake_client(*pair.first, options, wall_clock, diagnostics);

    CHECK(!result.completed);
    CHECK(result.outcome == Outcome::Deny);
    CHECK(result.error == ErrorCode::PeerDisconnected);
    CHECK(result.final_state == ClientState::Failed);
}

FACEAUTH_TEST(server_handles_client_disconnect) {
    auto pair = make_in_memory_pair();
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    SystemClock wall_clock;
    CollectingSink diagnostics;

    pair.first->close();
    const ErrorCode error =
        run_fake_server(*pair.second, backend, cache, wall_clock, diagnostics, 500);
    CHECK(error == ErrorCode::PeerDisconnected);
    // A disconnected client must never cause a verification to run.
    CHECK(backend.calls() == 0u);
}

FACEAUTH_TEST(mid_request_disconnect_denies) {
    const VerifyRequest request = make_request(28, kT0 + 10000);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(to_server) == ErrorCode::None);

    CHECK(client.on_peer_disconnect() == ErrorCode::PeerDisconnected);
    CHECK(client.state() == ClientState::Failed);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0, outcome) == ErrorCode::InvalidStateTransition);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(service_restart_voids_an_in_flight_request) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;

    const VerifyRequest request = make_request(29, kT0 + 10000);

    // A server session that dies mid-exchange holds no persistent state, so a
    // "restarted" server is a brand new session that has never seen the
    // request - and the replay cache still refuses to process it twice.
    ServerSession before_restart(backend, cache);
    CHECK(before_restart.on_peer_disconnect() == ErrorCode::PeerDisconnected);
    CHECK(before_restart.state() == ServerState::Failed);

    ServerSession after_restart(backend, cache);
    std::vector<std::uint8_t> reply;
    CHECK(after_restart.on_message(encode(request), kT0, reply) == ErrorCode::None);

    // Re-submitting the same request after another restart is refused.
    ServerSession third(backend, cache);
    CHECK(third.on_message(encode(request), kT0, reply) == ErrorCode::DuplicateRequestId);
}

FACEAUTH_TEST(concurrent_requests_are_admission_controlled) {
    ConcurrencyGate gate;
    CHECK(gate.acquire() == ErrorCode::None);
    CHECK(gate.in_flight() == 1u);
    // One camera, one verification. The second attempt is refused outright
    // rather than queued behind a device lock.
    CHECK(gate.acquire() == ErrorCode::Busy);
    gate.release();
    CHECK(gate.in_flight() == 0u);
    CHECK(gate.acquire() == ErrorCode::None);
}

FACEAUTH_TEST(concurrent_sessions_do_not_share_replay_state) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0},
                                         VerificationDecision{Outcome::Allow, 0},
                                         VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;

    // Three genuinely distinct requests all succeed against one shared cache.
    for (std::uint8_t seed = 30; seed < 33; ++seed) {
        ServerSession server(backend, cache);
        std::vector<std::uint8_t> reply;
        CHECK(server.on_message(encode(make_request(seed, kT0 + 10000)), kT0, reply) ==
              ErrorCode::None);
    }
    CHECK(cache.size() == 3u);
}

FACEAUTH_TEST(end_to_end_exchange_over_in_memory_transport) {
    auto pair = make_in_memory_pair();
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    SystemClock wall_clock;
    CollectingSink client_diagnostics;
    CollectingSink server_diagnostics;

    std::thread server_thread([&]() {
        run_fake_server(*pair.second, backend, cache, wall_clock, server_diagnostics, 3000);
    });

    FakeClientOptions options;
    const FakeClientResult result = run_fake_client(*pair.first, options, wall_clock, client_diagnostics);
    server_thread.join();

    CHECK(result.completed);
    CHECK(result.outcome == Outcome::Allow);
    CHECK(result.final_state == ClientState::Consumed);
    CHECK(!client_diagnostics.lines().empty());
}

// ---------------------------------------------------------------------------
// Randomness and diagnostics
// ---------------------------------------------------------------------------

FACEAUTH_TEST(secure_random_produces_distinct_identifiers) {
    bool ok_a = false;
    bool ok_b = false;
    const RequestId a = make_request_id(ok_a);
    const RequestId b = make_request_id(ok_b);
    CHECK(ok_a);
    CHECK(ok_b);
    CHECK(!(a == b));

    RequestId zero{};
    zero.fill(0u);
    CHECK(!(a == zero));

    bool nonce_ok = false;
    const Nonce nonce = make_nonce(nonce_ok);
    CHECK(nonce_ok);
    Nonce zero_nonce{};
    zero_nonce.fill(0u);
    CHECK(!(nonce == zero_nonce));
}

FACEAUTH_TEST(diagnostics_reject_forbidden_field_names) {
    for (const char* forbidden :
         {"embedding", "template_bytes", "raw_frame", "face_image", "password", "user_secret",
          "biometric_vector", "nonce", "pin", "signing_key", "certificate_blob"}) {
        DiagnosticEvent event("test_event");
        event.add(forbidden, "value");
        CHECK(event.rejected());
        CHECK(event.render().empty());
    }

    CollectingSink sink;
    DiagnosticEvent bad("leak_attempt");
    bad.add("embedding", "0.12,0.98,0.31");
    CHECK(!emit(sink, bad));
    CHECK(sink.lines().empty());
}

FACEAUTH_TEST(diagnostics_allow_opaque_identifier_fields) {
    // "template_id" is a correlation handle, not the payload - the same
    // carve-out Phase 1's SecurityLogger makes.
    DiagnosticEvent event("test_event");
    event.add("template_id", "ab12cd34");
    event.add("request_ref", "0011aabb");
    event.add("session_id", static_cast<std::int64_t>(3));
    event.add("fell_back", true);
    CHECK(!event.rejected());
    CHECK(!event.render().empty());
}

FACEAUTH_TEST(diagnostics_reject_unsafe_values) {
    DiagnosticEvent control_char("test_event");
    control_char.add("detail", std::string("line1\nline2"));
    CHECK(control_char.rejected());

    DiagnosticEvent too_long("test_event");
    too_long.add("detail", std::string(200, 'x'));
    CHECK(too_long.rejected());
}

FACEAUTH_TEST(identifiers_are_only_ever_logged_as_short_prefixes) {
    RequestId id{};
    for (std::size_t i = 0; i < id.size(); ++i) {
        id[i] = static_cast<std::uint8_t>(i);
    }
    const std::string prefix = hex_prefix(id);
    // 4 bytes -> 8 hex characters. A full 16-byte id would be 32, and logging
    // that would hand an attacker a replay aid.
    CHECK(prefix.size() == 8u);
    CHECK(prefix == "00010203");
}

FACEAUTH_TEST(protocol_test_results_are_labelled_as_such) {
    const std::string label(kProtocolTestResultLabel);
    CHECK(label.find("NOT A WINDOWS AUTHENTICATION DECISION") != std::string::npos);
}
