// Windows named-pipe transport for the fake client/server pair.
//
// READ THIS BEFORE ASSUMING THIS IS THE PHASE 3 ENDPOINT. It is not.
//
// This creates a pipe owned by, and accessible only to, the user running the
// test tool. It is not created by a service, it has no service SID in its
// DACL, it performs no client-token check, and its name is explicitly marked
// as a protocol test. The privileged endpoint specified in ADR-0003 section
// 5.2 - service-created, SYSTEM + NT SERVICE\FaceAuthVerifier only, with a
// System-integrity mandatory label and an ImpersonateNamedPipeClient check -
// is a Phase 3 deliverable and is deliberately not built here.
//
// What this file does demonstrate, because both are cheap and both are
// security-relevant:
//   * an EXPLICIT security descriptor, never the NULL default. Microsoft's own
//     documentation for CreateNamedPipe says the default descriptor's ACLs
//     "grant read access to members of the Everyone group and the anonymous
//     account" - which would be unacceptable for any version of this channel.
//   * FILE_FLAG_FIRST_PIPE_INSTANCE, so a squatter that got there first causes
//     a loud failure instead of a silent hijack.
//   * PIPE_REJECT_REMOTE_CLIENTS.
//   * message-mode framing, so a partial message is a transport error rather
//     than a parser problem.

#include "faceauth/ipc/transport.hpp"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// <sddl.h> must follow <windows.h>.
#include <sddl.h>

#include <chrono>
#include <thread>

#include "faceauth/ipc/protocol.hpp"

namespace faceauth::ipc {
namespace {

std::wstring full_pipe_path(const std::string& pipe_name) {
    std::wstring path = L"\\\\.\\pipe\\";
    for (const char ch : pipe_name) {
        path.push_back(static_cast<wchar_t>(static_cast<unsigned char>(ch)));
    }
    return path;
}

// Returns the SDDL string SID of the current process user, or an empty string
// on failure. Failure must abort pipe creation - never fall back to a default
// or permissive descriptor.
std::wstring current_user_sid_string() {
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == 0) {
        return std::wstring{};
    }

    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        CloseHandle(token);
        return std::wstring{};
    }

    std::vector<unsigned char> buffer(needed);
    if (GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed) == 0) {
        CloseHandle(token);
        return std::wstring{};
    }
    CloseHandle(token);

    const TOKEN_USER* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR sid_text = nullptr;
    if (ConvertSidToStringSidW(user->User.Sid, &sid_text) == 0) {
        return std::wstring{};
    }
    std::wstring result(sid_text);
    LocalFree(sid_text);
    return result;
}

class NamedPipeTransport : public Transport {
public:
    explicit NamedPipeTransport(HANDLE handle, bool is_server)
        : handle_(handle), is_server_(is_server) {}

    ~NamedPipeTransport() override { close(); }

    NamedPipeTransport(const NamedPipeTransport&) = delete;
    NamedPipeTransport& operator=(const NamedPipeTransport&) = delete;

    TransportStatus send(const std::vector<std::uint8_t>& message) override {
        if (handle_ == INVALID_HANDLE_VALUE) {
            return TransportStatus::Disconnected;
        }
        if (message.empty() || message.size() > kMaxMessageBytes) {
            return TransportStatus::Error;
        }
        DWORD written = 0;
        const BOOL ok = WriteFile(handle_, message.data(), static_cast<DWORD>(message.size()),
                                  &written, nullptr);
        if (ok == 0) {
            const DWORD error = GetLastError();
            return (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA)
                       ? TransportStatus::Disconnected
                       : TransportStatus::Error;
        }
        return (written == message.size()) ? TransportStatus::Ok : TransportStatus::Error;
    }

    // The timeout argument is intentionally unused: this transport is blocking
    // by design, and the deadline/timeout security controls are enforced by the
    // state machines against an injectable clock, not by the transport. The
    // in-memory transport is the one that models timeouts for tests.
    TransportStatus receive(std::vector<std::uint8_t>& out, std::uint32_t timeout_ms) override {
        (void)timeout_ms;
        if (handle_ == INVALID_HANDLE_VALUE) {
            return TransportStatus::Disconnected;
        }
        std::vector<std::uint8_t> buffer(kMaxMessageBytes);
        DWORD read = 0;
        const BOOL ok = ReadFile(handle_, buffer.data(), static_cast<DWORD>(buffer.size()), &read,
                                 nullptr);
        if (ok == 0) {
            const DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) {
                return TransportStatus::Disconnected;
            }
            // ERROR_MORE_DATA means the peer sent a message larger than our
            // ceiling. Refuse it; do not try to reassemble.
            return TransportStatus::Error;
        }
        if (read == 0) {
            return TransportStatus::Disconnected;
        }
        buffer.resize(read);
        out = buffer;
        return TransportStatus::Ok;
    }

    void close() override {
        if (handle_ != INVALID_HANDLE_VALUE) {
            if (is_server_) {
                FlushFileBuffers(handle_);
                DisconnectNamedPipe(handle_);
            }
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    bool connected() const override { return handle_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    bool is_server_ = false;
};

}  // namespace

std::shared_ptr<Transport> make_named_pipe_server(const std::string& pipe_name,
                                                  std::uint32_t connect_timeout_ms) {
    const std::wstring user_sid = current_user_sid_string();
    if (user_sid.empty()) {
        return nullptr;
    }

    // Protected DACL (P), granting GENERIC_ALL to this user and nobody else.
    // No Everyone, no Anonymous, no Authenticated Users.
    const std::wstring sddl = L"D:P(A;;GA;;;" + user_sid + L")";

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                             &descriptor, nullptr) == 0) {
        return nullptr;
    }

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    attributes.bInheritHandle = FALSE;

    const std::wstring path = full_pipe_path(pipe_name);
    const HANDLE handle = CreateNamedPipeW(
        path.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, static_cast<DWORD>(kMaxMessageBytes), static_cast<DWORD>(kMaxMessageBytes),
        connect_timeout_ms, &attributes);

    LocalFree(descriptor);

    if (handle == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    // Blocking connect. ERROR_PIPE_CONNECTED means the client won the race
    // between CreateNamedPipe and ConnectNamedPipe, which is a success.
    if (ConnectNamedPipe(handle, nullptr) == 0 && GetLastError() != ERROR_PIPE_CONNECTED) {
        CloseHandle(handle);
        return nullptr;
    }

    return std::make_shared<NamedPipeTransport>(handle, true);
}

std::shared_ptr<Transport> make_named_pipe_client(const std::string& pipe_name,
                                                  std::uint32_t connect_timeout_ms) {
    const std::wstring path = full_pipe_path(pipe_name);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(connect_timeout_ms);

    for (;;) {
        const HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                          OPEN_EXISTING, 0, nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_MESSAGE;
            if (SetNamedPipeHandleState(handle, &mode, nullptr, nullptr) == 0) {
                CloseHandle(handle);
                return nullptr;
            }
            return std::make_shared<NamedPipeTransport>(handle, false);
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            return nullptr;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

}  // namespace faceauth::ipc

#endif  // _WIN32
