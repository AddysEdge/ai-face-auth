// Protocol contract tests for the ADR-0003 IPC design.
//
// Every test here is a PROTOCOL test. None of them authenticates anything,
// none opens a camera, and none touches Windows authentication state. The
// identities are opaque test strings and the outcomes are scripted.
//
// Test names are meant to state exactly what is proven and nothing more. If a
// name and its body ever disagree, the name is the bug.

#include <atomic>
#include <chrono>
#include <map>
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

// An arbitrary monotonic origin. Deliberately NOT a Unix epoch value: nothing
// in the protocol has a wall-clock meaning any more.
constexpr std::uint64_t kT0 = 1'000'000ull;
constexpr std::uint32_t kLifetimeMs = 10000u;

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

VerifyRequest make_request(std::uint8_t seed, std::uint32_t lifetime_ms = kLifetimeMs) {
    VerifyRequest request{};
    request.request_id = make_id(seed);
    request.nonce = make_nonce_value(static_cast<std::uint8_t>(seed + 100u));
    request.account_binding = to_binding("opaque-test-identity-a");
    request.session_id = 7;
    request.desktop_binding = to_binding("opaque-test-desktop");
    request.requested_lifetime_ms = lifetime_ms;
    return request;
}

ClientSession make_client(const VerifyRequest& request) {
    return ClientSession(request.request_id, request.nonce, request.account_binding,
                         request.session_id, request.desktop_binding,
                         request.requested_lifetime_ms);
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
    const VerifyRequest request = make_request(1);
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
    result.result_ttl_ms = 3000;
    const DecodeResult decoded_result = decode_message(encode(result));
    CHECK(decoded_result.ok());
    CHECK(decoded_result.message.type == MessageType::VerifyResult);
    CHECK(decoded_result.message.result == result);

    ProtocolErrorMessage error{};
    error.request_id = request.request_id;
    error.error_code = ErrorCode::Timeout;
    const DecodeResult decoded_error = decode_message(encode(error));
    CHECK(decoded_error.ok());
    CHECK(decoded_error.message.error.error_code == ErrorCode::Timeout);
}

FACEAUTH_TEST(malformed_message_is_rejected) {
    const VerifyRequest request = make_request(2);
    const std::vector<std::uint8_t> good = encode(request);

    std::vector<std::uint8_t> bad_magic = good;
    bad_magic[0] = static_cast<std::uint8_t>(bad_magic[0] ^ 0xFFu);
    CHECK(decode_message(bad_magic).error == ErrorCode::MalformedMessage);

    std::vector<std::uint8_t> bad_reserved = good;
    bad_reserved[12] = 1u;
    CHECK(decode_message(bad_reserved).error == ErrorCode::MalformedMessage);

    // Trailing bytes beyond the declared payload are never tolerated.
    std::vector<std::uint8_t> trailing = good;
    trailing.push_back(0u);
    CHECK(decode_message(trailing).error == ErrorCode::MalformedMessage);

    const std::vector<std::uint8_t> unknown_type =
        raw_frame(kMagic, kProtocolVersion, 9999u, 0u, 0u, {});
    CHECK(decode_message(unknown_type).error == ErrorCode::UnknownMessageType);

    CHECK(decode_message(std::vector<std::uint8_t>{}).error == ErrorCode::TruncatedMessage);
}

FACEAUTH_TEST(reserved_message_type_3_is_rejected) {
    // Type 3 held a CancelRequest in an earlier draft. It is permanently
    // reserved and unassigned in version 1, and must never be silently
    // accepted - see MessageType in protocol.hpp for why cancellation is
    // deferred to Phase 3 rather than half-implemented here.
    const std::vector<std::uint8_t> cancel_shaped =
        raw_frame(kMagic, kProtocolVersion, 3u, static_cast<std::uint32_t>(kRequestIdBytes), 0u,
                  std::vector<std::uint8_t>(kRequestIdBytes, 0x11u));
    CHECK(decode_message(cancel_shaped).error == ErrorCode::UnknownMessageType);
}

FACEAUTH_TEST(truncated_message_is_rejected) {
    const VerifyRequest request = make_request(3);
    const std::vector<std::uint8_t> good = encode(request);
    CHECK(good.size() > kHeaderBytes);

    std::vector<std::uint8_t> short_header(good.begin(), good.begin() + 8);
    CHECK(decode_message(short_header).error == ErrorCode::TruncatedMessage);

    std::vector<std::uint8_t> short_payload(good.begin(), good.end() - 4);
    CHECK(decode_message(short_payload).error == ErrorCode::TruncatedMessage);

    const std::vector<std::uint8_t> lying =
        raw_frame(kMagic, kProtocolVersion,
                  static_cast<std::uint16_t>(MessageType::ProtocolError), 64u, 0u, {1u, 2u, 3u});
    CHECK(decode_message(lying).error == ErrorCode::TruncatedMessage);
}

FACEAUTH_TEST(unknown_protocol_version_is_rejected) {
    const std::vector<std::uint8_t> future = raw_frame(
        kMagic, static_cast<std::uint16_t>(kProtocolVersion + 1),
        static_cast<std::uint16_t>(MessageType::ProtocolError), 0u, 0u, {});
    CHECK(decode_message(future).error == ErrorCode::UnsupportedVersion);

    const std::vector<std::uint8_t> ancient =
        raw_frame(kMagic, 0u, static_cast<std::uint16_t>(MessageType::ProtocolError), 0u, 0u, {});
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
    VerifyRequest request = make_request(4);
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
    VerifyRequest request = make_request(5);
    request.account_binding.clear();
    CHECK(encode(request).empty());
}

// ---------------------------------------------------------------------------
// Relative lifetimes / no wall clock
// ---------------------------------------------------------------------------

FACEAUTH_TEST(wire_format_carries_no_absolute_timestamp) {
    // Two identical requests encoded at wildly different moments must produce
    // byte-identical output. If any wall-clock or steady-clock epoch value
    // leaked into the wire format, these would differ.
    const VerifyRequest a = make_request(40);
    const std::vector<std::uint8_t> first = encode(a);

    ManualMonotonicClock mono_clock(kT0);
    mono_clock.advance(9'999'999u);

    const VerifyRequest b = make_request(40);
    const std::vector<std::uint8_t> second = encode(b);

    CHECK(first == second);

    // And the decoded lifetime is a small relative duration, not an epoch.
    const DecodeResult decoded = decode_message(first);
    CHECK(decoded.ok());
    CHECK(decoded.message.request.requested_lifetime_ms == kLifetimeMs);
    CHECK(decoded.message.request.requested_lifetime_ms <= kMaxRequestLifetimeMs);
}

FACEAUTH_TEST(zero_or_excessive_requested_lifetime_is_rejected_on_the_wire) {
    VerifyRequest zero = make_request(41);
    zero.requested_lifetime_ms = 0u;
    // The encoder still emits it; the parser is the gate.
    const std::vector<std::uint8_t> encoded_zero = encode(zero);
    CHECK(!encoded_zero.empty());
    CHECK(decode_message(encoded_zero).error == ErrorCode::MalformedMessage);

    VerifyRequest huge = make_request(42);
    huge.requested_lifetime_ms = kMaxRequestLifetimeMs + 1u;
    CHECK(decode_message(encode(huge)).error == ErrorCode::MalformedMessage);
}

FACEAUTH_TEST(excessive_result_ttl_is_rejected_on_the_wire) {
    VerifyResult result{};
    result.request_id = make_id(43);
    result.nonce = make_nonce_value(43);
    result.account_binding = to_binding("opaque-test-identity-a");
    result.outcome = Outcome::Allow;
    result.result_ttl_ms = kMaxResultValidityMs + 1u;
    CHECK(decode_message(encode(result)).error == ErrorCode::MalformedMessage);
}

FACEAUTH_TEST(client_deadline_is_derived_from_its_own_monotonic_clock) {
    const VerifyRequest request = make_request(44);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> out;
    CHECK(client.start(kT0, out) == ErrorCode::None);
    // Started before the message left, from the client's own clock.
    CHECK(client.request_deadline_steady_ms() == kT0 + kLifetimeMs);
}

FACEAUTH_TEST(server_deadline_is_derived_from_its_own_monotonic_clock) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;

    // The server's clock reads something completely different from the
    // client's. That must not matter: it derives its own deadline on arrival,
    // from its own clock.
    const std::uint64_t server_now = kT0 + 5'000'000u;
    ManualMonotonicClock server_clock(server_now);
    ServerSession server(backend, cache, server_clock);

    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(make_request(45)), reply) == ErrorCode::None);
    CHECK(server.request_deadline_steady_ms() == server_now + kLifetimeMs);
}

FACEAUTH_TEST(result_ttl_cannot_extend_the_client_deadline) {
    const VerifyRequest request = make_request(46, 1000u);  // short client window
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> out;
    CHECK(client.start(kT0, out) == ErrorCode::None);
    CHECK(client.request_deadline_steady_ms() == kT0 + 1000u);

    // A hostile-but-well-formed result asking for the maximum TTL.
    VerifyResult result{};
    result.request_id = request.request_id;
    result.nonce = request.nonce;
    result.account_binding = request.account_binding;
    result.outcome = Outcome::Allow;
    result.result_ttl_ms = kMaxResultValidityMs;

    CHECK(client.on_message(encode(result), kT0 + 100u) == ErrorCode::None);
    // min(now + 5000, deadline 1000) == the client's own deadline. The peer's
    // TTL shortened nothing and extended nothing.
    CHECK(client.result_deadline_steady_ms() == kT0 + 1000u);

    Outcome outcome = Outcome::Deny;
    CHECK(client.consume(kT0 + 1001u, outcome) == ErrorCode::RequestExpired);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(short_result_ttl_shortens_client_validity) {
    const VerifyRequest request = make_request(47, kMaxRequestLifetimeMs);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> out;
    CHECK(client.start(kT0, out) == ErrorCode::None);

    VerifyResult result{};
    result.request_id = request.request_id;
    result.nonce = request.nonce;
    result.account_binding = request.account_binding;
    result.outcome = Outcome::Allow;
    result.result_ttl_ms = 250u;

    CHECK(client.on_message(encode(result), kT0) == ErrorCode::None);
    CHECK(client.result_deadline_steady_ms() == kT0 + 250u);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0 + 251u, outcome) == ErrorCode::RequestExpired);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(expiry_advances_only_with_the_injected_monotonic_clock) {
    // The whole security decision is driven by an injected monotonic value.
    // There is no API on either session that accepts or reads wall-clock time,
    // so a system-time jump - forwards or backwards - cannot reach it.
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    const VerifyRequest request = make_request(48, 2000u);
    ClientSession client = make_client(request);

    ManualMonotonicClock mono_clock(kT0);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(mono_clock.steady_now_ms(), to_server) == ErrorCode::None);

    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, to_client) == ErrorCode::None);
    CHECK(client.on_message(to_client, mono_clock.steady_now_ms()) == ErrorCode::None);

    Outcome outcome = Outcome::Deny;
    CHECK(client.consume(mono_clock.steady_now_ms(), outcome) == ErrorCode::None);
    CHECK(outcome == Outcome::Allow);

    // Only advancing the monotonic clock expires anything.
    ManualMonotonicClock later(kT0);
    later.advance(2001u);
    ClientSession second = make_client(make_request(49, 2000u));
    std::vector<std::uint8_t> ignored;
    CHECK(second.start(kT0, ignored) == ErrorCode::None);
    CHECK(second.on_timeout(later.steady_now_ms()) == ErrorCode::Timeout);
}

// ---------------------------------------------------------------------------
// Happy path and denial
// ---------------------------------------------------------------------------

FACEAUTH_TEST(valid_request_response_flow) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    const VerifyRequest request = make_request(6);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);
    CHECK(client.state() == ClientState::AwaitingResult);

    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, to_client) == ErrorCode::None);
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
    ScriptedVerificationBackend backend({VerificationDecision{
        Outcome::Deny, static_cast<std::uint16_t>(ErrorCode::VerificationFailed)}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    const VerifyRequest request = make_request(7);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);
    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, to_client) == ErrorCode::None);
    CHECK(client.on_message(to_client, kT0) == ErrorCode::None);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0, outcome) == ErrorCode::None);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(exhausted_backend_script_denies) {
    ScriptedVerificationBackend backend;
    const VerifyRequest request = make_request(8);
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

    const VerifyRequest first = make_request(9);
    std::vector<std::uint8_t> reply;
    ManualMonotonicClock server_a_clock(kT0);
    ServerSession server_a(backend, cache, server_a_clock);
    CHECK(server_a.on_message(encode(first), reply) == ErrorCode::None);

    VerifyRequest second = first;
    second.nonce = make_nonce_value(0xEEu);
    ManualMonotonicClock server_b_clock(kT0);
    ServerSession server_b(backend, cache, server_b_clock);
    CHECK(server_b.on_message(encode(second), reply) == ErrorCode::DuplicateRequestId);
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

    const VerifyRequest first = make_request(10);
    std::vector<std::uint8_t> reply;
    ManualMonotonicClock server_a_clock(kT0);
    ServerSession server_a(backend, cache, server_a_clock);
    CHECK(server_a.on_message(encode(first), reply) == ErrorCode::None);

    VerifyRequest second = first;
    second.request_id = make_id(0xABu);
    ManualMonotonicClock server_b_clock(kT0);
    ServerSession server_b(backend, cache, server_b_clock);
    CHECK(server_b.on_message(encode(second), reply) == ErrorCode::ReplayedNonce);
    CHECK(server_b.state() == ServerState::Failed);
}

FACEAUTH_TEST(replay_cache_evicts_on_the_servers_monotonic_clock) {
    ReplayCache cache(4);
    CHECK(cache.observe(make_id(1), make_nonce_value(1), kT0 + 1000, kT0) == ErrorCode::None);
    CHECK(cache.size() == 1u);

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

FACEAUTH_TEST(replay_cache_is_safe_under_concurrent_observers) {
    // Every thread offers the SAME (request_id, nonce). Exactly one must win.
    // Without internal locking, two threads could both pass the lookup before
    // either inserted, and both would be told the request was fresh.
    ReplayCache cache(64);
    constexpr int kThreads = 8;

    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    std::atomic<int> accepted{0};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&]() {
            ready.fetch_add(1);
            while (!go.load()) {
            }
            if (cache.observe(make_id(200), make_nonce_value(201), kT0 + 10000, kT0) ==
                ErrorCode::None) {
                accepted.fetch_add(1);
            }
        });
    }
    while (ready.load() < kThreads) {
    }
    go.store(true);
    for (std::thread& t : threads) {
        t.join();
    }

    CHECK(accepted.load() == 1);
    CHECK(cache.size() == 1u);
}

// ---------------------------------------------------------------------------
// Deadlines and timeouts (session level)
// ---------------------------------------------------------------------------

FACEAUTH_TEST(zero_lifetime_request_is_rejected_before_the_backend_runs) {
    // Renamed from `expired_request_is_rejected_by_server`, which overstated
    // what it covered: a zero lifetime is a malformed request, not an expired
    // one. Genuine expiry is covered by the `..._after_the_deadline_...` tests
    // below.
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    VerifyRequest request = make_request(11);
    request.requested_lifetime_ms = 0u;
    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(request), reply) == ErrorCode::MalformedMessage);
    CHECK(server.state() == ServerState::Failed);
    CHECK(backend.calls() == 0u);
}

FACEAUTH_TEST(server_clamps_the_requested_lifetime_to_the_protocol_maximum) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    // The maximum is accepted and produces exactly the maximum window.
    VerifyRequest request = make_request(12, kMaxRequestLifetimeMs);
    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(request), reply) == ErrorCode::None);
    CHECK(server.request_deadline_steady_ms() == kT0 + kMaxRequestLifetimeMs);

    // Anything beyond it never even parses, so a client cannot buy itself an
    // unbounded window by asking for one.
    VerifyRequest excessive = make_request(13, kMaxRequestLifetimeMs);
    excessive.requested_lifetime_ms = kMaxRequestLifetimeMs + 1u;
    CHECK(decode_message(encode(excessive)).error == ErrorCode::MalformedMessage);
}

FACEAUTH_TEST(result_ttl_never_exceeds_the_protocol_maximum) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(make_request(14, kMaxRequestLifetimeMs)), reply) ==
          ErrorCode::None);

    const DecodeResult decoded = decode_message(reply);
    CHECK(decoded.ok());
    CHECK(decoded.message.result.result_ttl_ms == kMaxResultValidityMs);
}

FACEAUTH_TEST(result_ttl_never_outlives_a_short_request_window) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(make_request(15, 1000u)), reply) == ErrorCode::None);

    const DecodeResult decoded = decode_message(reply);
    CHECK(decoded.ok());
    CHECK(decoded.message.result.result_ttl_ms == 1000u);
}

FACEAUTH_TEST(expired_result_cannot_be_consumed) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    const VerifyRequest request = make_request(16, 2000u);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);
    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, to_client) == ErrorCode::None);
    CHECK(client.on_message(to_client, kT0) == ErrorCode::None);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0 + 5000, outcome) == ErrorCode::RequestExpired);
    CHECK(outcome == Outcome::Deny);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(result_arriving_after_the_deadline_is_rejected) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    const VerifyRequest request = make_request(17, 2000u);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);
    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, to_client) == ErrorCode::None);

    CHECK(client.on_message(to_client, kT0 + 9999) == ErrorCode::RequestExpired);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(client_timeout_denies) {
    const VerifyRequest request = make_request(18);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);
    CHECK(client.on_timeout(kT0 + 4000) == ErrorCode::Timeout);
    CHECK(client.state() == ClientState::Failed);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0 + 4000, outcome) == ErrorCode::InvalidStateTransition);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(server_timeout_while_idle_is_an_invalid_transition) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);
    std::vector<std::uint8_t> reply;
    CHECK(server.on_timeout(reply) == ErrorCode::InvalidStateTransition);
}

FACEAUTH_TEST(client_can_abandon_locally_without_sending_anything) {
    // This is NOT cancellation. Abandonment is local and sends nothing, so the
    // server remains unaware; a synchronous in-flight backend keeps its worker
    // and the concurrency gate until it returns. See
    // `abandoning_a_client_leaves_the_server_untouched` and
    // `a_synchronous_backend_holds_its_worker_until_it_returns`.
    const VerifyRequest request = make_request(19);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);

    CHECK(client.abandon() == ErrorCode::Abandoned);
    CHECK(client.state() == ClientState::Abandoned);

    // An abandoned client can no longer consume anything.
    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0, outcome) == ErrorCode::InvalidStateTransition);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(abandoning_a_client_leaves_the_server_untouched) {
    // Proving the honest limitation: because nothing is sent, a server that
    // already accepted the request still runs its verification to completion.
    // In-flight cancellation would require an asynchronous server and is a
    // Phase 3 requirement.
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    const VerifyRequest request = make_request(20);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);

    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, to_client) == ErrorCode::None);
    CHECK(backend.calls() == 1u);

    CHECK(client.abandon() == ErrorCode::Abandoned);
    CHECK(server.state() == ServerState::Responded);
}

// ---------------------------------------------------------------------------
// State machine integrity
// ---------------------------------------------------------------------------

FACEAUTH_TEST(client_invalid_state_transition) {
    const VerifyRequest request = make_request(21);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);
    CHECK(client.start(kT0, to_server) == ErrorCode::InvalidStateTransition);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(client_rejects_a_request_message_from_the_server) {
    const VerifyRequest request = make_request(22);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);

    CHECK(client.on_message(encode(request), kT0) == ErrorCode::InvalidStateTransition);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(server_invalid_state_transition) {
    ScriptedVerificationBackend backend(
        {VerificationDecision{Outcome::Allow, 0}, VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(make_request(23)), reply) == ErrorCode::None);
    CHECK(server.state() == ServerState::Responded);

    CHECK(server.on_message(encode(make_request(24)), reply) ==
          ErrorCode::InvalidStateTransition);
    CHECK(server.state() == ServerState::Failed);
    CHECK(backend.calls() == 1u);
}

FACEAUTH_TEST(server_rejects_a_result_message_from_the_client) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    VerifyResult forged{};
    forged.request_id = make_id(25);
    forged.nonce = make_nonce_value(25);
    forged.account_binding = to_binding("opaque-test-identity-a");
    forged.outcome = Outcome::Allow;
    forged.result_ttl_ms = 1000;

    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(forged), reply) == ErrorCode::InvalidStateTransition);
    CHECK(server.state() == ServerState::Failed);
}

// ---------------------------------------------------------------------------
// Identity binding
// ---------------------------------------------------------------------------

FACEAUTH_TEST(result_with_wrong_identity_binding_is_rejected) {
    const VerifyRequest request = make_request(26);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);

    VerifyResult other{};
    other.request_id = request.request_id;
    other.nonce = request.nonce;
    other.account_binding = to_binding("opaque-test-identity-b");
    other.outcome = Outcome::Allow;
    other.result_ttl_ms = 1000;

    CHECK(client.on_message(encode(other), kT0) == ErrorCode::IdentityMismatch);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(result_with_wrong_request_id_is_rejected) {
    const VerifyRequest request = make_request(27);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);

    VerifyResult other{};
    other.request_id = make_id(0x77u);
    other.nonce = request.nonce;
    other.account_binding = request.account_binding;
    other.outcome = Outcome::Allow;
    other.result_ttl_ms = 1000;

    CHECK(client.on_message(encode(other), kT0) == ErrorCode::IdentityMismatch);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(result_with_wrong_nonce_is_rejected) {
    const VerifyRequest request = make_request(28);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);

    VerifyResult other{};
    other.request_id = request.request_id;
    other.nonce = make_nonce_value(0x99u);
    other.account_binding = request.account_binding;
    other.outcome = Outcome::Allow;
    other.result_ttl_ms = 1000;

    CHECK(client.on_message(encode(other), kT0) == ErrorCode::IdentityMismatch);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(successful_result_cannot_be_reused) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock);

    const VerifyRequest request = make_request(29);
    ClientSession client = make_client(request);

    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);
    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, to_client) == ErrorCode::None);
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
    ClientSession replay_victim = make_client(make_request(30));
    std::vector<std::uint8_t> ignored;
    CHECK(replay_victim.start(kT0, ignored) == ErrorCode::None);
    CHECK(replay_victim.on_message(to_client, kT0) == ErrorCode::IdentityMismatch);
}

// ---------------------------------------------------------------------------
// Disconnects, restarts, concurrency
// ---------------------------------------------------------------------------

FACEAUTH_TEST(client_handles_server_disconnect) {
    auto pair = make_in_memory_pair();
    SteadyClock mono_clock;
    CollectingSink diagnostics;

    pair.second->close();

    FakeClientOptions options;
    options.receive_timeout_ms = 500;
    const FakeClientResult result = run_fake_client(*pair.first, options, mono_clock, diagnostics);

    CHECK(!result.completed);
    CHECK(result.outcome == Outcome::Deny);
    CHECK(result.error == ErrorCode::PeerDisconnected);
    CHECK(result.final_state == ClientState::Failed);
}

FACEAUTH_TEST(server_handles_client_disconnect) {
    auto pair = make_in_memory_pair();
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    SteadyClock mono_clock;
    CollectingSink diagnostics;

    pair.first->close();
    const ErrorCode error = run_fake_server(*pair.second, backend, cache, mono_clock, diagnostics, 500);
    CHECK(error == ErrorCode::PeerDisconnected);
    CHECK(backend.calls() == 0u);
}

FACEAUTH_TEST(mid_request_disconnect_denies) {
    const VerifyRequest request = make_request(31);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);

    CHECK(client.on_peer_disconnect() == ErrorCode::PeerDisconnected);
    CHECK(client.state() == ClientState::Failed);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0, outcome) == ErrorCode::InvalidStateTransition);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(service_restart_voids_an_in_flight_request) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;

    const VerifyRequest request = make_request(32);

    ManualMonotonicClock before_restart_clock(kT0);
    ServerSession before_restart(backend, cache, before_restart_clock);
    CHECK(before_restart.on_peer_disconnect() == ErrorCode::PeerDisconnected);
    CHECK(before_restart.state() == ServerState::Failed);

    ManualMonotonicClock after_restart_clock(kT0);
    ServerSession after_restart(backend, cache, after_restart_clock);
    std::vector<std::uint8_t> reply;
    CHECK(after_restart.on_message(encode(request), reply) == ErrorCode::None);

    ManualMonotonicClock third_clock(kT0);
    ServerSession third(backend, cache, third_clock);
    CHECK(third.on_message(encode(request), reply) == ErrorCode::DuplicateRequestId);
}

FACEAUTH_TEST(concurrency_gate_admits_only_the_configured_number_simultaneously) {
    // Real threads, released together, all attempting to acquire at once.
    // A non-thread-safe counter would let several past the check.
    ConcurrencyGate gate(1);
    constexpr int kThreads = 8;

    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    std::atomic<int> attempted{0};
    std::atomic<int> admitted{0};
    std::atomic<int> busy{0};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&]() {
            ready.fetch_add(1);
            while (!go.load()) {
            }
            const bool acquired = (gate.acquire() == ErrorCode::None);
            attempted.fetch_add(1);
            if (acquired) {
                admitted.fetch_add(1);
                // Hold until EVERY thread has attempted, so the contention is
                // guaranteed rather than dependent on a sleep winning a race.
                while (attempted.load() < kThreads) {
                }
                gate.release();
            } else {
                busy.fetch_add(1);
            }
        });
    }
    while (ready.load() < kThreads) {
    }
    go.store(true);
    for (std::thread& t : threads) {
        t.join();
    }

    CHECK(admitted.load() == 1);
    CHECK(busy.load() == kThreads - 1);
    CHECK(gate.in_flight() == 0u);
}

FACEAUTH_TEST(server_sessions_sharing_a_gate_cannot_verify_concurrently) {
    // End-to-end: two ServerSessions share one gate and one blocking backend.
    // The first genuinely sits inside verify(); the second must be refused
    // with Busy rather than running a second verification.
    BlockingVerificationBackend backend(VerificationDecision{Outcome::Allow, 0});
    ReplayCache cache;
    ConcurrencyGate gate(1);

    std::vector<std::uint8_t> first_reply;
    ErrorCode first_error = ErrorCode::InternalError;

    std::thread first([&]() {
        ManualMonotonicClock session_clock(kT0);
        ServerSession session(backend, cache, session_clock, &gate);
        first_error = session.on_message(encode(make_request(60)), first_reply);
    });

    // Wait until the first verification is genuinely in flight.
    backend.wait_until_entered(1);
    CHECK(gate.in_flight() == 1u);

    ManualMonotonicClock second_clock(kT0);
    ServerSession second(backend, cache, second_clock, &gate);
    std::vector<std::uint8_t> second_reply;
    const ErrorCode second_error = second.on_message(encode(make_request(61)), second_reply);

    CHECK(second_error == ErrorCode::Busy);
    CHECK(second.state() == ServerState::Failed);
    // The blocked-out session never reached the backend.
    CHECK(backend.entered() == 1u);

    const DecodeResult decoded = decode_message(second_reply);
    CHECK(decoded.ok());
    CHECK(decoded.message.error.error_code == ErrorCode::Busy);

    backend.release_all();
    first.join();

    CHECK(first_error == ErrorCode::None);
    CHECK(gate.in_flight() == 0u);
}

FACEAUTH_TEST(distinct_requests_do_not_collide_in_a_shared_replay_cache) {
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0},
                                         VerificationDecision{Outcome::Allow, 0},
                                         VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;

    for (std::uint8_t seed = 33; seed < 36; ++seed) {
        ManualMonotonicClock server_clock(kT0);
        ServerSession server(backend, cache, server_clock);
        std::vector<std::uint8_t> reply;
        CHECK(server.on_message(encode(make_request(seed)), reply) == ErrorCode::None);
    }
    CHECK(cache.size() == 3u);
}

FACEAUTH_TEST(end_to_end_exchange_over_in_memory_transport) {
    auto pair = make_in_memory_pair();
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    SteadyClock mono_clock;
    CollectingSink client_diagnostics;
    CollectingSink server_diagnostics;

    std::thread server_thread([&]() {
        run_fake_server(*pair.second, backend, cache, mono_clock, server_diagnostics, 3000);
    });

    FakeClientOptions options;
    const FakeClientResult result = run_fake_client(*pair.first, options, mono_clock, client_diagnostics);
    server_thread.join();

    CHECK(result.completed);
    CHECK(result.outcome == Outcome::Allow);
    CHECK(result.final_state == ClientState::Consumed);
    CHECK(!client_diagnostics.empty());
}

// ---------------------------------------------------------------------------
// CollectingSink concurrency (issue #7)
//
// A sink is routinely shared: two peers on two threads emit into the sink they
// were handed. CollectingSink::write() used to be an unsynchronised
// vector::push_back, and lines() handed out a reference into storage a writer
// could still be growing. Both are undefined behaviour, and both are now
// removed by construction rather than made less likely.
//
// These tests pin that behaviour. They do not, and cannot, prove the absence of
// a race - the mutex does that. Threads are released together by an explicit
// gate, never by sleeping.
// ---------------------------------------------------------------------------

FACEAUTH_TEST(concurrent_writers_to_one_collecting_sink_lose_nothing) {
    constexpr int kWriters = 8;
    constexpr int kLinesPerWriter = 250;

    CollectingSink sink;
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};

    std::vector<std::thread> writers;
    writers.reserve(kWriters);
    for (int writer = 0; writer < kWriters; ++writer) {
        writers.emplace_back([&sink, &ready, &go, writer]() {
            // Arrive, then wait for every other writer. This is the contention
            // the old code could not survive; a sleep would only make it
            // likely, and unreliably so.
            ready.fetch_add(1);
            while (!go.load()) {
            }
            for (int line = 0; line < kLinesPerWriter; ++line) {
                sink.write("w" + std::to_string(writer) + "-l" + std::to_string(line));
            }
        });
    }

    while (ready.load() < kWriters) {
    }
    go.store(true);
    for (std::thread& writer : writers) {
        writer.join();
    }

    // Every writer has joined, so this is the complete, final state.
    const std::vector<std::string> lines = sink.snapshot();
    CHECK_EQ(lines.size(), static_cast<std::size_t>(kWriters * kLinesPerWriter));

    // Every expected record present exactly once, and nothing corrupted: a
    // torn or lost push_back would show up as a missing or duplicated key.
    std::map<std::string, int> counts;
    for (const std::string& line : lines) {
        counts[line] += 1;
    }
    CHECK_EQ(counts.size(), static_cast<std::size_t>(kWriters * kLinesPerWriter));
    for (int writer = 0; writer < kWriters; ++writer) {
        for (int line = 0; line < kLinesPerWriter; ++line) {
            const std::string expected =
                "w" + std::to_string(writer) + "-l" + std::to_string(line);
            CHECK_EQ(counts[expected], 1);
        }
    }
}

FACEAUTH_TEST(a_snapshot_taken_while_writers_run_is_internally_consistent) {
    constexpr int kWriters = 4;
    constexpr int kLinesPerWriter = 200;

    CollectingSink sink;
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    std::atomic<bool> writing{true};

    std::vector<std::thread> writers;
    writers.reserve(kWriters);
    for (int writer = 0; writer < kWriters; ++writer) {
        writers.emplace_back([&sink, &ready, &go, writer]() {
            ready.fetch_add(1);
            while (!go.load()) {
            }
            for (int line = 0; line < kLinesPerWriter; ++line) {
                sink.write("w" + std::to_string(writer) + "-l" + std::to_string(line));
            }
        });
    }

    // Reading concurrently with writing is part of the contract, so it is
    // tested as such rather than only after the writers have finished.
    std::size_t observed_snapshots = 0;
    std::size_t previous_size = 0;
    bool sizes_never_shrank = true;
    bool every_record_well_formed = true;

    std::thread reader([&]() {
        while (writing.load()) {
            const std::vector<std::string> shot = sink.snapshot();
            observed_snapshots += 1;
            if (shot.size() < previous_size) {
                sizes_never_shrank = false;
            }
            previous_size = shot.size();
            for (const std::string& line : shot) {
                // A snapshot must never contain a partially written string.
                if (line.empty() || line[0] != 'w' || line.find("-l") == std::string::npos) {
                    every_record_well_formed = false;
                }
            }
        }
    });

    while (ready.load() < kWriters) {
    }
    go.store(true);
    for (std::thread& writer : writers) {
        writer.join();
    }
    writing.store(false);
    reader.join();

    CHECK(observed_snapshots > 0);
    CHECK(sizes_never_shrank);
    CHECK(every_record_well_formed);
    CHECK_EQ(sink.size(), static_cast<std::size_t>(kWriters * kLinesPerWriter));
}

FACEAUTH_TEST(both_fake_peers_can_share_one_collecting_sink) {
    // The exact shape that made the named-pipe exchange test unsafe, reduced to
    // the in-memory transport so it runs on every platform.
    auto pair = make_in_memory_pair();
    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    SteadyClock mono_clock;
    CollectingSink shared_diagnostics;

    std::thread server_thread([&]() {
        run_fake_server(*pair.second, backend, cache, mono_clock, shared_diagnostics, 3000);
    });

    FakeClientOptions options;
    const FakeClientResult result =
        run_fake_client(*pair.first, options, mono_clock, shared_diagnostics);
    server_thread.join();

    CHECK(result.completed);
    CHECK(result.outcome == Outcome::Allow);

    // Both peers emitted into the same sink and every line survived intact.
    const std::vector<std::string> lines = shared_diagnostics.snapshot();
    CHECK(lines.size() >= 2);
    for (const std::string& line : lines) {
        CHECK(!line.empty());
    }
}

FACEAUTH_TEST(collecting_sink_clear_and_size_are_consistent) {
    CollectingSink sink;
    CHECK(sink.empty());
    CHECK_EQ(sink.size(), static_cast<std::size_t>(0));

    sink.write("one");
    sink.write("two");
    CHECK(!sink.empty());
    CHECK_EQ(sink.size(), static_cast<std::size_t>(2));
    CHECK_EQ(sink.snapshot().size(), static_cast<std::size_t>(2));

    sink.clear();
    CHECK(sink.empty());
    CHECK_EQ(sink.size(), static_cast<std::size_t>(0));
    CHECK(sink.snapshot().empty());
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
    CHECK(sink.empty());
}

FACEAUTH_TEST(diagnostics_allow_opaque_identifier_fields) {
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
    CHECK(prefix.size() == 8u);
    CHECK(prefix == "00010203");
}

FACEAUTH_TEST(protocol_test_results_are_labelled_as_such) {
    const std::string label(kProtocolTestResultLabel);
    CHECK(label.find("NOT A WINDOWS AUTHENTICATION DECISION") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Server deadline is enforced AFTER the backend returns
// ---------------------------------------------------------------------------

FACEAUTH_TEST(allow_completing_after_the_server_deadline_is_rejected) {
    // The heart of the fix. The deadline used to be checked only on arrival, so
    // a backend that overran its window still produced an Allow. It is now
    // re-checked against a FRESH clock reading after verify() returns.
    ManualMonotonicClock server_clock(kT0);
    // Window is 1000 ms; the backend burns 1500 ms.
    SlowVerificationBackend backend(server_clock, 1500u, VerificationDecision{Outcome::Allow, 0});
    ReplayCache cache;
    ServerSession server(backend, cache, server_clock);

    std::vector<std::uint8_t> reply;
    const ErrorCode error = server.on_message(encode(make_request(70, 1000u)), reply);

    CHECK(error == ErrorCode::RequestExpired);
    CHECK(server.state() == ServerState::Failed);
    CHECK(backend.calls() == 1u);

    // And the reply must be a ProtocolError - never a late VerifyResult that a
    // client could mistake for a live decision.
    const DecodeResult decoded = decode_message(reply);
    CHECK(decoded.ok());
    CHECK(decoded.message.type == MessageType::ProtocolError);
    CHECK(decoded.message.error.error_code == ErrorCode::RequestExpired);
}

FACEAUTH_TEST(no_late_allow_is_ever_emitted_to_the_client) {
    // End-to-end: even with an Allow-scripted backend, a client driven by the
    // overrun exchange must finish denied.
    ManualMonotonicClock server_clock(kT0);
    SlowVerificationBackend backend(server_clock, 1500u, VerificationDecision{Outcome::Allow, 0});
    ReplayCache cache;
    ServerSession server(backend, cache, server_clock);

    const VerifyRequest request = make_request(71, 1000u);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> to_server;
    CHECK(client.start(kT0, to_server) == ErrorCode::None);

    std::vector<std::uint8_t> to_client;
    CHECK(server.on_message(to_server, to_client) == ErrorCode::RequestExpired);

    // The client sees a ProtocolError, not a result, and can never consume.
    CHECK(client.on_message(to_client, kT0) == ErrorCode::RequestExpired);
    CHECK(client.state() == ClientState::Failed);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0, outcome) == ErrorCode::InvalidStateTransition);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(completing_exactly_at_the_server_deadline_is_rejected) {
    // Half-open: now >= deadline is expired, so landing exactly on it fails.
    ManualMonotonicClock server_clock(kT0);
    SlowVerificationBackend backend(server_clock, 1000u, VerificationDecision{Outcome::Allow, 0});
    ReplayCache cache;
    ServerSession server(backend, cache, server_clock);

    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(make_request(72, 1000u)), reply) == ErrorCode::RequestExpired);
    CHECK(server.state() == ServerState::Failed);
}

FACEAUTH_TEST(completing_one_ms_before_the_server_deadline_still_succeeds) {
    // The boundary from the other side, so the half-open rule is pinned rather
    // than merely asserted in one direction.
    ManualMonotonicClock server_clock(kT0);
    SlowVerificationBackend backend(server_clock, 999u, VerificationDecision{Outcome::Allow, 0});
    ReplayCache cache;
    ServerSession server(backend, cache, server_clock);

    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(make_request(73, 1000u)), reply) == ErrorCode::None);
    CHECK(server.state() == ServerState::Responded);

    const DecodeResult decoded = decode_message(reply);
    CHECK(decoded.ok());
    CHECK(decoded.message.type == MessageType::VerifyResult);
    // 1 ms of the window is left, so that is the TTL - not the original 1000.
    CHECK(decoded.message.result.result_ttl_ms == 1u);
}

FACEAUTH_TEST(result_ttl_is_measured_from_completion_not_from_the_original_lifetime) {
    // A 30 s window with 28 s consumed leaves 2 s. The old code would have sent
    // the full kMaxResultValidityMs (5 s) - a window the server no longer had.
    ManualMonotonicClock server_clock(kT0);
    SlowVerificationBackend backend(server_clock, 28000u, VerificationDecision{Outcome::Allow, 0});
    ReplayCache cache;
    ServerSession server(backend, cache, server_clock);

    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(make_request(74, kMaxRequestLifetimeMs)), reply) ==
          ErrorCode::None);

    const DecodeResult decoded = decode_message(reply);
    CHECK(decoded.ok());
    CHECK(decoded.message.result.result_ttl_ms == 2000u);
    CHECK(decoded.message.result.result_ttl_ms < kMaxResultValidityMs);
}

FACEAUTH_TEST(a_fast_backend_still_gets_the_capped_result_ttl) {
    ManualMonotonicClock server_clock(kT0);
    SlowVerificationBackend backend(server_clock, 1u, VerificationDecision{Outcome::Allow, 0});
    ReplayCache cache;
    ServerSession server(backend, cache, server_clock);

    std::vector<std::uint8_t> reply;
    CHECK(server.on_message(encode(make_request(75, kMaxRequestLifetimeMs)), reply) ==
          ErrorCode::None);

    const DecodeResult decoded = decode_message(reply);
    CHECK(decoded.ok());
    CHECK(decoded.message.result.result_ttl_ms == kMaxResultValidityMs);
}

// ---------------------------------------------------------------------------
// Exact expiry boundaries (half-open: valid when now < deadline)
// ---------------------------------------------------------------------------

FACEAUTH_TEST(result_arriving_exactly_at_the_request_deadline_is_rejected) {
    const VerifyRequest request = make_request(76, 1000u);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> out;
    CHECK(client.start(kT0, out) == ErrorCode::None);
    CHECK(client.request_deadline_steady_ms() == kT0 + 1000u);

    VerifyResult result{};
    result.request_id = request.request_id;
    result.nonce = request.nonce;
    result.account_binding = request.account_binding;
    result.outcome = Outcome::Allow;
    result.result_ttl_ms = 500u;

    // Exactly on the deadline is already too late.
    CHECK(client.on_message(encode(result), kT0 + 1000u) == ErrorCode::RequestExpired);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(result_arriving_one_ms_before_the_request_deadline_is_accepted) {
    const VerifyRequest request = make_request(77, 1000u);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> out;
    CHECK(client.start(kT0, out) == ErrorCode::None);

    VerifyResult result{};
    result.request_id = request.request_id;
    result.nonce = request.nonce;
    result.account_binding = request.account_binding;
    result.outcome = Outcome::Allow;
    result.result_ttl_ms = 500u;

    CHECK(client.on_message(encode(result), kT0 + 999u) == ErrorCode::None);
    CHECK(client.state() == ClientState::ResultAvailable);
}

FACEAUTH_TEST(result_consumed_exactly_at_its_deadline_is_rejected) {
    const VerifyRequest request = make_request(78, kMaxRequestLifetimeMs);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> out;
    CHECK(client.start(kT0, out) == ErrorCode::None);

    VerifyResult result{};
    result.request_id = request.request_id;
    result.nonce = request.nonce;
    result.account_binding = request.account_binding;
    result.outcome = Outcome::Allow;
    result.result_ttl_ms = 400u;

    CHECK(client.on_message(encode(result), kT0) == ErrorCode::None);
    CHECK(client.result_deadline_steady_ms() == kT0 + 400u);

    // One millisecond earlier is fine...
    ClientSession twin = make_client(make_request(79, kMaxRequestLifetimeMs));
    std::vector<std::uint8_t> twin_out;
    CHECK(twin.start(kT0, twin_out) == ErrorCode::None);
    VerifyResult twin_result = result;
    twin_result.request_id = twin.request().request_id;
    twin_result.nonce = twin.request().nonce;
    CHECK(twin.on_message(encode(twin_result), kT0) == ErrorCode::None);
    Outcome early = Outcome::Deny;
    CHECK(twin.consume(kT0 + 399u, early) == ErrorCode::None);
    CHECK(early == Outcome::Allow);

    // ...but exactly on the deadline is not.
    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0 + 400u, outcome) == ErrorCode::RequestExpired);
    CHECK(outcome == Outcome::Deny);
    CHECK(client.state() == ClientState::Failed);
}

FACEAUTH_TEST(zero_ttl_result_can_never_be_consumed) {
    // A zero-length window is unusable by construction under the half-open
    // rule: result_deadline == now, and now >= now is expired.
    const VerifyRequest request = make_request(80, kMaxRequestLifetimeMs);
    ClientSession client = make_client(request);
    std::vector<std::uint8_t> out;
    CHECK(client.start(kT0, out) == ErrorCode::None);

    VerifyResult result{};
    result.request_id = request.request_id;
    result.nonce = request.nonce;
    result.account_binding = request.account_binding;
    result.outcome = Outcome::Allow;
    result.result_ttl_ms = 0u;

    CHECK(client.on_message(encode(result), kT0) == ErrorCode::None);
    CHECK(client.result_deadline_steady_ms() == kT0);

    Outcome outcome = Outcome::Allow;
    CHECK(client.consume(kT0, outcome) == ErrorCode::RequestExpired);
    CHECK(outcome == Outcome::Deny);
}

FACEAUTH_TEST(replay_cache_expiry_agrees_with_session_expiry_at_the_boundary) {
    // The cache and the sessions must stop considering the same instant live at
    // the same moment. A mismatch would leave a one-millisecond seam in which a
    // request was expired but its replay protection had not yet lapsed, or the
    // reverse - which is the more dangerous direction.
    ReplayCache cache(8);
    const std::uint64_t expires_at = kT0 + 1000u;

    CHECK(cache.observe(make_id(90), make_nonce_value(90), expires_at, kT0) == ErrorCode::None);

    // One millisecond before: still live, so a duplicate is still rejected.
    CHECK(cache.observe(make_id(90), make_nonce_value(91), expires_at, expires_at - 1u) ==
          ErrorCode::DuplicateRequestId);

    // Exactly at the deadline: gone, matching `now >= deadline` everywhere else.
    CHECK(cache.observe(make_id(90), make_nonce_value(92), kT0 + 2000u, expires_at) ==
          ErrorCode::None);
}

// ---------------------------------------------------------------------------
// Backend exceptions
// ---------------------------------------------------------------------------

FACEAUTH_TEST(throwing_backend_fails_closed_and_releases_the_gate) {
    ThrowingVerificationBackend backend;
    ReplayCache cache;
    ConcurrencyGate gate(1);
    ManualMonotonicClock server_clock(kT0);
    ServerSession server(backend, cache, server_clock, &gate);

    std::vector<std::uint8_t> reply;
    const ErrorCode error = server.on_message(encode(make_request(81)), reply);

    // Fail closed with InternalError...
    CHECK(error == ErrorCode::InternalError);
    CHECK(server.state() == ServerState::Failed);
    CHECK(backend.calls() == 1u);

    // ...a valid ProtocolError reply, never an Allow...
    const DecodeResult decoded = decode_message(reply);
    CHECK(decoded.ok());
    CHECK(decoded.message.type == MessageType::ProtocolError);
    CHECK(decoded.message.error.error_code == ErrorCode::InternalError);

    // ...and the gate is released as the exception unwinds. Without RAII this
    // would stay at 1 forever and wedge admission control for the machine.
    CHECK(gate.in_flight() == 0u);

    // Proof it is genuinely reusable afterwards.
    CHECK(gate.acquire() == ErrorCode::None);
    gate.release();
}

FACEAUTH_TEST(a_throwing_backend_does_not_block_a_later_verification) {
    ReplayCache cache;
    ConcurrencyGate gate(1);

    {
        ThrowingVerificationBackend throwing;
        ManualMonotonicClock first_clock(kT0);
        ServerSession first(throwing, cache, first_clock, &gate);
        std::vector<std::uint8_t> reply;
        CHECK(first.on_message(encode(make_request(82)), reply) == ErrorCode::InternalError);
    }

    ScriptedVerificationBackend healthy({VerificationDecision{Outcome::Allow, 0}});
    ManualMonotonicClock second_clock(kT0);
    ServerSession second(healthy, cache, second_clock, &gate);
    std::vector<std::uint8_t> reply;
    CHECK(second.on_message(encode(make_request(83)), reply) == ErrorCode::None);
    CHECK(second.state() == ServerState::Responded);
    CHECK(gate.in_flight() == 0u);
}

FACEAUTH_TEST(a_synchronous_backend_holds_its_worker_until_it_returns) {
    // Stated as a test so the limitation cannot quietly drift out of the docs.
    //
    // Protocol version 1 calls the backend synchronously. The post-verification
    // deadline check bounds the DECISION - a late Allow is refused - but it
    // cannot bound the CALL. While the backend runs, this thread and the
    // concurrency gate are held, and nothing can preempt it. Making the call
    // itself interruptible is Phase 3 work (entry criterion B16).
    ManualMonotonicClock server_clock(kT0);
    SlowVerificationBackend backend(server_clock, 5000u, VerificationDecision{Outcome::Allow, 0});
    ReplayCache cache;
    ConcurrencyGate gate(1);
    ServerSession server(backend, cache, server_clock, &gate);

    std::vector<std::uint8_t> reply;
    // The window is 30 s, so 5 s of backend time is survivable and the result
    // is honoured - the point is that on_message did not return until the
    // backend did.
    CHECK(server.on_message(encode(make_request(84, kMaxRequestLifetimeMs)), reply) ==
          ErrorCode::None);
    CHECK(backend.calls() == 1u);
    // The clock only advanced because the backend advanced it; nothing else
    // could run in the meantime.
    CHECK(server_clock.steady_now_ms() == kT0 + 5000u);
    CHECK(gate.in_flight() == 0u);
}
