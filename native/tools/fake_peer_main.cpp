// faceauth_ipc_fake - a normal-desktop protocol exerciser.
//
// This program is NOT a credential provider, NOT a service, and NOT an
// authentication tool. It runs a fake client and a fake server against each
// other to demonstrate that the ADR-0003 contract behaves as specified.
// Identities are opaque test strings; outcomes come from a fixed script; no
// camera, no biometric code, and no Windows authentication API is involved.
//
// Modes:
//   --memory        one exchange over the in-process transport, scripted ALLOW
//   --memory-deny   one exchange over the in-process transport, scripted DENY
//   --pipe          one exchange over a user-owned loopback named pipe
//                   (Windows only; see src/transport_pipe_win.cpp)

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "faceauth/ipc/boundaries.hpp"
#include "faceauth/ipc/clock.hpp"
#include "faceauth/ipc/diagnostics.hpp"
#include "faceauth/ipc/fake_peer.hpp"
#include "faceauth/ipc/replay_cache.hpp"
#include "faceauth/ipc/transport.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

using namespace faceauth::ipc;

namespace {

void print_banner() {
    std::puts("faceauth_ipc_fake - IPC protocol exerciser (Phase 2 scaffold)");
    std::puts("  This tool performs NO Windows authentication of any kind.");
    std::puts("  Identities are opaque test strings. Outcomes are simulated.");
    std::puts("");
}

void report(const char* mode, const FakeClientResult& result) {
    std::printf("[%s] %s\n", mode, kProtocolTestResultLabel);
    std::printf("[%s]   completed   : %s\n", mode, result.completed ? "yes" : "no");
    std::printf("[%s]   outcome     : %s (simulated)\n", mode, to_string(result.outcome));
    std::printf("[%s]   error        : %s\n", mode, to_string(result.error));
    std::printf("[%s]   client state : %s\n", mode, to_string(result.final_state));
}

int run_memory_exchange(Outcome scripted, const char* mode) {
    auto pair = make_in_memory_pair();
    std::shared_ptr<Transport> client_side = pair.first;
    std::shared_ptr<Transport> server_side = pair.second;

    ScriptedVerificationBackend backend({VerificationDecision{scripted, 0}});
    ReplayCache replay_cache;
    SystemClock wall_clock;
    StdoutSink diagnostics;

    std::thread server_thread([&]() {
        run_fake_server(*server_side, backend, replay_cache, wall_clock, diagnostics, 3000);
    });

    FakeClientOptions options;
    const FakeClientResult result = run_fake_client(*client_side, options, wall_clock, diagnostics);

    server_thread.join();
    client_side->close();
    server_side->close();

    report(mode, result);
    // The exchange must complete, and the delivered outcome must be exactly
    // the scripted one - a deny that "succeeds" by failing early would hide a
    // protocol bug.
    return (result.completed && result.outcome == scripted) ? 0 : 1;
}

#if defined(_WIN32)
int run_pipe_exchange() {
    const std::string pipe_name =
        "faceauth-phase2-PROTOCOL-TEST-" + std::to_string(static_cast<unsigned long>(GetCurrentProcessId()));

    ScriptedVerificationBackend backend({VerificationDecision{Outcome::Allow, 0}});
    ReplayCache replay_cache;
    SystemClock wall_clock;
    StdoutSink diagnostics;

    FakeClientResult result{};
    std::shared_ptr<Transport> client_side;

    // The client retries until the pipe exists, so it can start first.
    std::thread client_thread([&]() {
        client_side = make_named_pipe_client(pipe_name, 5000);
        if (!client_side) {
            result.error = ErrorCode::PeerDisconnected;
            return;
        }
        FakeClientOptions options;
        result = run_fake_client(*client_side, options, wall_clock, diagnostics);
    });

    std::shared_ptr<Transport> server_side = make_named_pipe_server(pipe_name, 5000);
    if (!server_side) {
        client_thread.join();
        std::puts("[pipe] failed to create the loopback pipe");
        return 1;
    }
    run_fake_server(*server_side, backend, replay_cache, wall_clock, diagnostics, 5000);

    client_thread.join();
    if (client_side) {
        client_side->close();
    }
    server_side->close();

    report("pipe", result);
    return (result.completed && result.outcome == Outcome::Allow) ? 0 : 1;
}
#endif

}  // namespace

int main(int argc, char** argv) {
    print_banner();

    const char* mode = (argc > 1) ? argv[1] : "--memory";

    if (std::strcmp(mode, "--memory") == 0) {
        return run_memory_exchange(Outcome::Allow, "memory");
    }
    if (std::strcmp(mode, "--memory-deny") == 0) {
        return run_memory_exchange(Outcome::Deny, "memory-deny");
    }
    if (std::strcmp(mode, "--pipe") == 0) {
#if defined(_WIN32)
        return run_pipe_exchange();
#else
        std::puts("--pipe is only available on Windows");
        return 0;
#endif
    }

    std::puts("usage: faceauth_ipc_fake [--memory|--memory-deny|--pipe]");
    return 2;
}
