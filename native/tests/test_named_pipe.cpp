// Windows named-pipe transport tests.
//
// These exist because an earlier version of the transport ignored the caller's
// timeout entirely and used blocking ConnectNamedPipe/ReadFile/WriteFile. Its
// tests still passed, because nothing ever exercised an unresponsive peer.
// Every test below deliberately creates a peer that does nothing, and asserts
// both that the call returns Timeout AND that it returned within a sane bound.
//
// A regression that reintroduced blocking I/O would hang here rather than fail
// quietly, so every one of these is also registered with a CTest TIMEOUT.
//
// Scope reminder: this is a user-owned, normal-desktop pipe used for protocol
// testing. It is not a service, and it does not use the Phase 3 privileged
// endpoint (ADR-0003 section 5.2).

#include "test_harness.hpp"

#if defined(_WIN32)

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "faceauth/ipc/boundaries.hpp"
#include "faceauth/ipc/clock.hpp"
#include "faceauth/ipc/diagnostics.hpp"
#include "faceauth/ipc/fake_peer.hpp"
#include "faceauth/ipc/protocol.hpp"
#include "faceauth/ipc/replay_cache.hpp"
#include "faceauth/ipc/transport.hpp"
#include "faceauth/ipc/wire.hpp"

using namespace faceauth::ipc;

namespace {

// Generous but finite. Every bounded call must come back well inside this;
// exceeding it means the bound is not being honoured.
constexpr std::uint32_t kTimeoutMs = 400u;
constexpr std::int64_t kMaxAcceptableElapsedMs = 8000;

// Lower bound with slack for timer granularity and a loaded CI runner. The
// point is to prove the call actually waited rather than failing instantly for
// an unrelated reason.
constexpr std::int64_t kMinAcceptableElapsedMs = 100;

std::string unique_pipe_name(const char* tag) {
    static std::atomic<unsigned long> counter{0};
    return std::string("faceauth-phase2-PROTOCOL-TEST-") + tag + "-" +
           std::to_string(static_cast<unsigned long>(GetCurrentProcessId())) + "-" +
           std::to_string(counter.fetch_add(1));
}

class Stopwatch {
public:
    Stopwatch() : start_(std::chrono::steady_clock::now()) {}

    std::int64_t elapsed_ms() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - start_)
            .count();
    }

private:
    std::chrono::steady_clock::time_point start_;
};

}  // namespace

FACEAUTH_TEST(named_pipe_server_connect_times_out_with_no_client) {
    const std::string name = unique_pipe_name("connect");
    TransportStatus status = TransportStatus::Error;

    const Stopwatch watch;
    std::shared_ptr<Transport> server = make_named_pipe_server(name, kTimeoutMs, &status);
    const std::int64_t elapsed = watch.elapsed_ms();

    // Nobody ever connects, so this must come back as a bounded timeout.
    CHECK(server == nullptr);
    CHECK(status == TransportStatus::Timeout);
    CHECK(elapsed >= kMinAcceptableElapsedMs);
    CHECK(elapsed < kMaxAcceptableElapsedMs);
}

FACEAUTH_TEST(named_pipe_client_read_times_out_with_a_silent_server) {
    const std::string name = unique_pipe_name("clientread");

    std::shared_ptr<Transport> server;
    std::thread server_thread([&]() {
        // Accepts the connection and then deliberately says nothing at all.
        server = make_named_pipe_server(name, 5000u, nullptr);
    });

    std::shared_ptr<Transport> client = make_named_pipe_client(name, 5000u, nullptr);
    CHECK(client != nullptr);

    std::vector<std::uint8_t> received;
    const Stopwatch watch;
    const TransportStatus status = client->receive(received, kTimeoutMs);
    const std::int64_t elapsed = watch.elapsed_ms();

    CHECK(status == TransportStatus::Timeout);
    CHECK(received.empty());
    CHECK(elapsed >= kMinAcceptableElapsedMs);
    CHECK(elapsed < kMaxAcceptableElapsedMs);

    client->close();
    server_thread.join();
    if (server) {
        server->close();
    }
}

FACEAUTH_TEST(named_pipe_server_read_times_out_with_a_silent_client) {
    const std::string name = unique_pipe_name("serverread");

    std::shared_ptr<Transport> client;
    std::thread client_thread([&]() {
        client = make_named_pipe_client(name, 5000u, nullptr);
        // Connects and then says nothing.
    });

    std::shared_ptr<Transport> server = make_named_pipe_server(name, 5000u, nullptr);
    CHECK(server != nullptr);
    client_thread.join();
    CHECK(client != nullptr);

    std::vector<std::uint8_t> received;
    const Stopwatch watch;
    const TransportStatus status = server->receive(received, kTimeoutMs);
    const std::int64_t elapsed = watch.elapsed_ms();

    CHECK(status == TransportStatus::Timeout);
    CHECK(elapsed >= kMinAcceptableElapsedMs);
    CHECK(elapsed < kMaxAcceptableElapsedMs);

    server->close();
    if (client) {
        client->close();
    }
}

FACEAUTH_TEST(named_pipe_transport_is_reusable_after_a_timeout) {
    // A timed-out read must leave the handle in a usable state: the pending
    // operation is cancelled and drained, not abandoned mid-flight. If the
    // OVERLAPPED were left dangling, this second exchange would misbehave.
    const std::string name = unique_pipe_name("reuse");

    std::shared_ptr<Transport> client;
    std::thread client_thread([&]() { client = make_named_pipe_client(name, 5000u, nullptr); });

    std::shared_ptr<Transport> server = make_named_pipe_server(name, 5000u, nullptr);
    CHECK(server != nullptr);
    client_thread.join();
    CHECK(client != nullptr);

    std::vector<std::uint8_t> received;
    CHECK(server->receive(received, kTimeoutMs) == TransportStatus::Timeout);

    // Now actually send something on the same handles.
    const std::vector<std::uint8_t> payload = {0xDEu, 0xADu, 0xBEu, 0xEFu};
    CHECK(client->send_with_timeout(payload, 2000u) == TransportStatus::Ok);
    CHECK(server->receive(received, 2000u) == TransportStatus::Ok);
    CHECK(received == payload);

    server->close();
    client->close();
}

FACEAUTH_TEST(named_pipe_peer_disconnect_is_reported_not_hung) {
    const std::string name = unique_pipe_name("disconnect");

    std::shared_ptr<Transport> client;
    std::thread client_thread([&]() { client = make_named_pipe_client(name, 5000u, nullptr); });

    std::shared_ptr<Transport> server = make_named_pipe_server(name, 5000u, nullptr);
    CHECK(server != nullptr);
    client_thread.join();
    CHECK(client != nullptr);

    // Close the client while the server is about to read.
    std::thread closer([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(60));
        client->close();
    });

    std::vector<std::uint8_t> received;
    const Stopwatch watch;
    const TransportStatus status = server->receive(received, 5000u);
    const std::int64_t elapsed = watch.elapsed_ms();
    closer.join();

    // A vanished peer must surface as Disconnected (fail closed), promptly.
    CHECK(status == TransportStatus::Disconnected);
    CHECK(elapsed < kMaxAcceptableElapsedMs);

    server->close();
}

FACEAUTH_TEST(named_pipe_send_to_a_closed_peer_returns_promptly) {
    // Saturating a pipe's buffer to force a genuinely blocked write is not
    // reliably reproducible on a CI runner, so this proves the adjacent and
    // testable property: a write to a vanished peer returns a bounded failure
    // rather than waiting. The write path uses the same bounded overlapped
    // wait as the read path.
    const std::string name = unique_pipe_name("sendclosed");

    std::shared_ptr<Transport> client;
    std::thread client_thread([&]() { client = make_named_pipe_client(name, 5000u, nullptr); });

    std::shared_ptr<Transport> server = make_named_pipe_server(name, 5000u, nullptr);
    CHECK(server != nullptr);
    client_thread.join();
    CHECK(client != nullptr);

    client->close();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    const std::vector<std::uint8_t> payload(256u, 0x5Au);
    const Stopwatch watch;
    const TransportStatus status = server->send_with_timeout(payload, kTimeoutMs);
    const std::int64_t elapsed = watch.elapsed_ms();

    // The status legitimately varies - Windows may buffer the write and report
    // Ok, or fail it as Disconnected. The property under test is that it
    // returns within a bound instead of blocking, so that is what is asserted.
    (void)status;
    CHECK(elapsed < kMaxAcceptableElapsedMs);

    server->close();
}

FACEAUTH_TEST(named_pipe_close_does_not_wait_for_an_unresponsive_peer) {
    // close() must never call FlushFileBuffers on a named pipe: it waits for
    // the peer to drain, which is unbounded. Here the peer never reads
    // anything, so a flushing close would stall.
    const std::string name = unique_pipe_name("close");

    std::shared_ptr<Transport> client;
    std::thread client_thread([&]() { client = make_named_pipe_client(name, 5000u, nullptr); });

    std::shared_ptr<Transport> server = make_named_pipe_server(name, 5000u, nullptr);
    CHECK(server != nullptr);
    client_thread.join();
    CHECK(client != nullptr);

    const std::vector<std::uint8_t> payload(512u, 0x42u);
    CHECK(server->send_with_timeout(payload, 2000u) == TransportStatus::Ok);

    const Stopwatch watch;
    server->close();
    client->close();
    const std::int64_t elapsed = watch.elapsed_ms();

    CHECK(elapsed < kMaxAcceptableElapsedMs);
}

FACEAUTH_TEST(named_pipe_full_exchange_succeeds_after_the_bounded_io_rewrite) {
    // The bounded-I/O rewrite must not have broken the happy path.
    const std::string name = unique_pipe_name("exchange");

    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache cache;
    SteadyClock mono_clock;
    CollectingSink diagnostics;

    FakeClientResult result{};
    std::shared_ptr<Transport> client;

    std::thread client_thread([&]() {
        client = make_named_pipe_client(name, 5000u, nullptr);
        if (!client) {
            return;
        }
        FakeClientOptions options;
        options.receive_timeout_ms = 5000;
        options.send_timeout_ms = 5000;
        result = run_fake_client(*client, options, mono_clock, diagnostics);
    });

    std::shared_ptr<Transport> server = make_named_pipe_server(name, 5000u, nullptr);
    CHECK(server != nullptr);
    const ErrorCode server_error =
        run_fake_server(*server, backend, cache, mono_clock, diagnostics, 5000);
    client_thread.join();

    CHECK(server_error == ErrorCode::None);
    CHECK(result.completed);
    CHECK(result.outcome == Outcome::Allow);
    CHECK(result.final_state == ClientState::Consumed);

    server->close();
    if (client) {
        client->close();
    }
}

#endif  // _WIN32
