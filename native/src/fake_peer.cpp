#include "faceauth/ipc/fake_peer.hpp"

#include "faceauth/ipc/random.hpp"
#include "faceauth/ipc/wire.hpp"

namespace faceauth::ipc {

OpaqueBinding to_binding(const std::string& text) {
    OpaqueBinding binding;
    const std::size_t length =
        (text.size() < kMaxAccountBindingBytes) ? text.size() : kMaxAccountBindingBytes;
    binding.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        binding.push_back(static_cast<std::uint8_t>(text[i]));
    }
    return binding;
}

FakeClientResult run_fake_client(Transport& transport, const FakeClientOptions& options,
                                 MonotonicClock& mono_clock, DiagnosticSink& diagnostics) {
    FakeClientResult result{};

    bool id_ok = false;
    bool nonce_ok = false;
    const RequestId request_id = make_request_id(id_ok);
    const Nonce nonce = make_nonce(nonce_ok);
    if (!id_ok || !nonce_ok) {
        // A weak identifier would defeat replay rejection, so this is fatal.
        result.error = ErrorCode::InternalError;
        DiagnosticEvent event("ipc_client_random_failure");
        emit(diagnostics, event);
        return result;
    }

    OpaqueBinding desktop = to_binding(options.test_desktop);
    if (desktop.size() > kMaxDesktopBindingBytes) {
        desktop.resize(kMaxDesktopBindingBytes);
    }

    ClientSession session(request_id, nonce, to_binding(options.test_identity), options.session_id,
                          desktop, options.requested_lifetime_ms);

    // The client's own monotonic deadline starts inside start().
    std::vector<std::uint8_t> outbound;
    ErrorCode error = session.start(mono_clock.steady_now_ms(), outbound);
    if (error != ErrorCode::None) {
        result.error = error;
        result.final_state = session.state();
        return result;
    }

    {
        DiagnosticEvent event("ipc_client_request_sent");
        event.add("request_ref", hex_prefix(request_id));
        event.add("session_id", static_cast<std::int64_t>(options.session_id));
        emit(diagnostics, event);
    }

    if (transport.send_with_timeout(outbound, options.send_timeout_ms) != TransportStatus::Ok) {
        result.error = session.on_peer_disconnect();
        result.final_state = session.state();
        return result;
    }

    if (options.abandon_after_send) {
        // Purely local. Nothing is sent - there is no cancellation message in
        // protocol version 1, and pretending otherwise is exactly the claim
        // this scaffold must not make.
        result.error = session.abandon();
        result.final_state = session.state();
        DiagnosticEvent event("ipc_client_abandoned_locally");
        event.add("request_ref", hex_prefix(request_id));
        emit(diagnostics, event);
        return result;
    }

    std::vector<std::uint8_t> inbound;
    const TransportStatus status = transport.receive(inbound, options.receive_timeout_ms);
    if (status == TransportStatus::Timeout) {
        result.error = session.on_timeout(mono_clock.steady_now_ms());
        result.final_state = session.state();
        return result;
    }
    if (status != TransportStatus::Ok) {
        result.error = session.on_peer_disconnect();
        result.final_state = session.state();
        return result;
    }

    error = session.on_message(inbound, mono_clock.steady_now_ms());
    if (error != ErrorCode::None) {
        result.error = error;
        result.final_state = session.state();
        return result;
    }

    Outcome outcome = Outcome::Deny;
    error = session.consume(mono_clock.steady_now_ms(), outcome);
    result.final_state = session.state();
    if (error != ErrorCode::None) {
        result.error = error;
        return result;
    }

    result.completed = true;
    result.outcome = outcome;

    DiagnosticEvent event("ipc_client_protocol_test_outcome");
    event.add("request_ref", hex_prefix(request_id));
    event.add("outcome", to_string(outcome));
    event.add("label", kProtocolTestResultLabel);
    emit(diagnostics, event);
    return result;
}

ErrorCode run_fake_server(Transport& transport, IVerificationBackend& backend,
                          ReplayCache& replay_cache, MonotonicClock& mono_clock,
                          DiagnosticSink& diagnostics, std::uint32_t receive_timeout_ms,
                          ConcurrencyGate* gate) {
    ServerSession session(backend, replay_cache, gate);

    std::vector<std::uint8_t> inbound;
    const TransportStatus status = transport.receive(inbound, receive_timeout_ms);
    if (status == TransportStatus::Timeout) {
        std::vector<std::uint8_t> reply;
        return session.on_timeout(mono_clock.steady_now_ms(), reply);
    }
    if (status != TransportStatus::Ok) {
        return session.on_peer_disconnect();
    }

    std::vector<std::uint8_t> reply;
    const ErrorCode error = session.on_message(inbound, mono_clock.steady_now_ms(), reply);
    if (!reply.empty()) {
        transport.send_with_timeout(reply, receive_timeout_ms);
    }

    DiagnosticEvent event("ipc_server_exchange_complete");
    event.add("state", to_string(session.state()));
    event.add("result_code", to_string(error));
    event.add("label", kProtocolTestResultLabel);
    emit(diagnostics, event);
    return error;
}

}  // namespace faceauth::ipc
