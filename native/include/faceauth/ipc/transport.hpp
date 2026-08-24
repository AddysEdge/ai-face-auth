// Message transports for the fake client/server pair.
//
// SCOPE: both implementations below run on the NORMAL DESKTOP as the invoking
// user. Neither is a service, neither runs in Session 0, and neither uses the
// privileged endpoint described in ADR-0003 section 5.2. The named-pipe
// implementation exists to exercise real message framing and real disconnect
// behaviour; its security descriptor grants the current user only, and its
// pipe name is explicitly marked as a protocol test.
//
// The SDDL, service SID, and client/server token checks specified in ADR-0003
// section 5.2 are a Phase 3 requirement and are deliberately NOT implemented
// here, because implementing them would mean creating the very endpoint this
// phase is not allowed to create.

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

    virtual TransportStatus send(const std::vector<std::uint8_t>& message) = 0;
    virtual TransportStatus receive(std::vector<std::uint8_t>& out, std::uint32_t timeout_ms) = 0;
    virtual void close() = 0;
    virtual bool connected() const = 0;
};

// Deterministic in-process transport used by the test suite. Preserves message
// boundaries, supports timeouts, and models an explicit peer disconnect.
std::pair<std::shared_ptr<Transport>, std::shared_ptr<Transport>> make_in_memory_pair();

#if defined(_WIN32)

// Creates the server end of a user-owned named pipe. `pipe_name` must be a
// bare name; the caller does not supply the \\.\pipe\ prefix.
//
// Uses FILE_FLAG_FIRST_PIPE_INSTANCE (anti-squatting) and
// PIPE_REJECT_REMOTE_CLIENTS, and an explicit security descriptor granting the
// current user only - never the NULL descriptor, which per Microsoft's own
// documentation would "grant read access to members of the Everyone group and
// the anonymous account".
std::shared_ptr<Transport> make_named_pipe_server(const std::string& pipe_name,
                                                  std::uint32_t connect_timeout_ms);

std::shared_ptr<Transport> make_named_pipe_client(const std::string& pipe_name,
                                                  std::uint32_t connect_timeout_ms);

#endif  // _WIN32

}  // namespace faceauth::ipc

#endif  // FACEAUTH_IPC_TRANSPORT_HPP
