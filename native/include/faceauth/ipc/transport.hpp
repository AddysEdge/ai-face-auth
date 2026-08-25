// Message transports for the fake client/server pair.
//
// SCOPE: both implementations below run on the NORMAL DESKTOP as the invoking
// user. Neither is a service, neither runs in Session 0, and neither uses the
// privileged endpoint described in ADR-0003 section 5.2. The named-pipe
// implementation exists to exercise real message framing, real bounded I/O,
// and real disconnect behaviour; its security descriptor grants the current
// user only, and its pipe name is explicitly marked as a protocol test.
//
// The SDDL, service SID, and client/server token checks specified in ADR-0003
// section 5.2 are a Phase 3 requirement and are deliberately NOT implemented
// here, because implementing them would mean creating the very endpoint this
// phase is not allowed to create.
//
// TIMEOUTS ARE PART OF THE CONTRACT. Every operation that can wait takes a
// millisecond bound and is required to honour it. An implementation that
// ignored the bound would make the fail-closed timeout rules in ADR-0003
// section 5.7 unenforceable, and would let an unresponsive peer hang a test
// run - see src/transport_pipe_win.cpp for how that is guaranteed on Windows.

#ifndef FACEAUTH_IPC_TRANSPORT_HPP
#define FACEAUTH_IPC_TRANSPORT_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace faceauth::ipc {

enum class TransportStatus {
    Ok,
    Timeout,
    Disconnected,
    Error,
};

const char* to_string(TransportStatus status);

class Transport {
public:
    virtual ~Transport() = default;

    // Sends with the implementation's default bound.
    virtual TransportStatus send(const std::vector<std::uint8_t>& message) = 0;

    // Sends with an explicit bound. Must return Timeout rather than blocking
    // past `timeout_ms`, even if the peer never drains the channel.
    virtual TransportStatus send_with_timeout(const std::vector<std::uint8_t>& message,
                                              std::uint32_t timeout_ms) = 0;

    // Must return Timeout rather than blocking past `timeout_ms`.
    virtual TransportStatus receive(std::vector<std::uint8_t>& out, std::uint32_t timeout_ms) = 0;

    // Must not wait on the peer.
    virtual void close() = 0;

    virtual bool connected() const = 0;
};

// Deterministic in-process transport used by the test suite. Preserves message
// boundaries, supports timeouts, and models an explicit peer disconnect.
std::pair<std::shared_ptr<Transport>, std::shared_ptr<Transport>> make_in_memory_pair();

#if defined(_WIN32)

// Creates the server end of a user-owned named pipe and waits, with a real
// bound, for a client. `pipe_name` must be a bare name; the caller does not
// supply the \\.\pipe\ prefix.
//
// Returns nullptr if no client connected within `connect_timeout_ms`, and when
// `out_status` is supplied reports Timeout in that case so a caller can tell a
// bounded timeout apart from a creation failure.
//
// Uses FILE_FLAG_FIRST_PIPE_INSTANCE (anti-squatting),
// PIPE_REJECT_REMOTE_CLIENTS, FILE_FLAG_OVERLAPPED, and an explicit security
// descriptor granting the current user only - never the NULL descriptor, which
// per Microsoft's own documentation would "grant read access to members of the
// Everyone group and the anonymous account".
std::shared_ptr<Transport> make_named_pipe_server(const std::string& pipe_name,
                                                  std::uint32_t connect_timeout_ms,
                                                  TransportStatus* out_status = nullptr);

std::shared_ptr<Transport> make_named_pipe_client(const std::string& pipe_name,
                                                  std::uint32_t connect_timeout_ms,
                                                  TransportStatus* out_status = nullptr);

#endif  // _WIN32

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_TRANSPORT_HPP
